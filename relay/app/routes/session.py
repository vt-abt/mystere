import hashlib
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..auth import hex_bytes, validate_ack, validate_request, verify_signature
from ..db import get_db
from ..envelope import delivery_frame
from ..models.prekeys import IdentityKey
from ..models.sessions import MessageQueue, SessionCommitment
from .ws import notify_online

router = APIRouter()


class SessionRequestData(BaseModel):
    initiator_id: uuid.UUID
    responder_id: uuid.UUID
    payload: str
    signature: str


@router.post("/request")
def session_request(data: SessionRequestData, background_tasks: BackgroundTasks,
                    db: Session = Depends(get_db)):
    payload = hex_bytes(data.payload, 56, "payload")
    signature = hex_bytes(data.signature, 64, "signature")
    validate_request(payload, data.responder_id)
    initiator = db.get(IdentityKey, data.initiator_id)
    responder = db.get(IdentityKey, data.responder_id)
    if (initiator is None or responder is None or initiator.user_id == responder.user_id
            or initiator.signing_pubkey is None or responder.signing_pubkey is None):
        raise HTTPException(status_code=404, detail="Identity not found")
    verify_signature(initiator.signing_pubkey, payload, signature)

    temp_id = hashlib.sha256(payload).digest()
    if db.get(SessionCommitment, temp_id) is not None:
        raise HTTPException(status_code=409, detail="Request already exists")
    db.add(SessionCommitment(
        session_id=temp_id, initiator_id=data.initiator_id,
        responder_id=data.responder_id, session_request=payload, status="pending",
    ))
    queue_id = uuid.uuid4()
    frame = delivery_frame(data.initiator_id, 0x07, payload + signature, queue_id)
    db.add(MessageQueue(
        id=queue_id, session_id=temp_id, recipient_id=data.responder_id, message_type=0x07,
        payload=frame, sequence_num=0,
    ))
    db.commit()
    background_tasks.add_task(notify_online, data.responder_id, frame)
    return {"temp_id": temp_id.hex()}


class SessionAckData(BaseModel):
    temp_id: str
    payload: str
    signature: str


@router.post("/ack")
def session_ack(data: SessionAckData, background_tasks: BackgroundTasks,
                db: Session = Depends(get_db)):
    temp_id = hex_bytes(data.temp_id, 32, "temp_id")
    payload = hex_bytes(data.payload, 104, "payload")
    signature = hex_bytes(data.signature, 64, "signature")
    commitment = (db.query(SessionCommitment).filter(
        SessionCommitment.session_id == temp_id,
        SessionCommitment.status == "pending",
    ).with_for_update().first())
    if commitment is None:
        raise HTTPException(status_code=404, detail="Session request not found")
    validate_ack(commitment.session_request, payload)
    responder = db.get(IdentityKey, commitment.responder_id)
    verify_signature(responder.signing_pubkey, payload, signature)

    final_id = hashlib.sha512(commitment.session_request + payload).digest()
    initiator_id = commitment.initiator_id
    responder_id = commitment.responder_id
    db.add(SessionCommitment(
        session_id=final_id, initiator_id=initiator_id,
        responder_id=responder_id, session_request=commitment.session_request,
        session_ack=payload, status="committed",
    ))
    db.flush()
    db.query(MessageQueue).filter(MessageQueue.session_id == temp_id).update(
        {MessageQueue.session_id: final_id}, synchronize_session=False,
    )
    db.delete(commitment)
    queue_id = uuid.uuid4()
    frame = delivery_frame(responder_id, 0x08, payload + signature, queue_id)
    db.add(MessageQueue(
        id=queue_id, session_id=final_id, recipient_id=initiator_id, message_type=0x08,
        payload=frame, sequence_num=0,
    ))
    db.commit()
    background_tasks.add_task(notify_online, initiator_id, frame)
    return {"session_id": final_id.hex()}
