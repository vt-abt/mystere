import asyncio
import datetime
import os
import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from ..auth import verify_signature
from ..db import get_db
from ..envelope import delivery_frame, parse_outbound
from ..models.prekeys import IdentityKey
from ..models.sessions import MessageQueue

router = APIRouter()
connections: dict[uuid.UUID, WebSocket] = {}
ACK_TYPE = 0x0B


async def notify_online(recipient_id: uuid.UUID, payload: bytes) -> None:
    target = connections.get(recipient_id)
    if target is not None:
        try:
            await target.send_bytes(payload)
        except (RuntimeError, WebSocketDisconnect):
            pass


def queue_for_delivery(sender_id: uuid.UUID, recipient_id: uuid.UUID,
                       message_type: int, payload: bytes, db: Session) -> bytes:
    queue_id = uuid.uuid4()
    hours = int(os.getenv("RELAY_MESSAGE_QUEUE_TTL_HOURS", "72"))
    frame = delivery_frame(sender_id, message_type, payload, queue_id)
    db.add(MessageQueue(
        id=queue_id, session_id=None, recipient_id=recipient_id,
        message_type=message_type,
        payload=frame,
        sequence_num=0,
        expires_at=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=hours),
    ))
    db.commit()
    return frame


@router.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: uuid.UUID,
                             db: Session = Depends(get_db)):
    identity = db.get(IdentityKey, user_id)
    if identity is None or identity.signing_pubkey is None:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    challenge = secrets.token_bytes(32)
    await websocket.send_bytes(b"\x00" + challenge)
    try:
        signature = await asyncio.wait_for(websocket.receive_bytes(), timeout=10)
        verify_signature(identity.signing_pubkey,
                         b"MYSTERE_WS_V1" + user_id.bytes + challenge, signature)
    except (asyncio.TimeoutError, WebSocketDisconnect, HTTPException, ValueError):
        await websocket.close(code=1008)
        return

    old_socket = connections.get(user_id)
    if old_socket is not None:
        try:
            await old_socket.close(code=1000)
        except RuntimeError:
            pass
    connections[user_id] = websocket
    await websocket.send_bytes(b"\x00\x01")
    try:
        offline = db.query(MessageQueue).filter(
            MessageQueue.recipient_id == user_id,
            MessageQueue.delivered.is_(False),
            (MessageQueue.expires_at.is_(None) |
             (MessageQueue.expires_at > datetime.datetime.now(datetime.timezone.utc))),
        ).order_by(MessageQueue.created_at).all()
        for message in offline:
            await websocket.send_bytes(message.payload)

        while True:
            data = await websocket.receive_bytes()
            try:
                recipient_id, message_type, payload = parse_outbound(data)
            except HTTPException:
                await websocket.close(code=1003)
                break
            if message_type == ACK_TYPE:
                if len(payload) != 16:
                    await websocket.close(code=1003)
                    break
                queued = db.get(MessageQueue, uuid.UUID(bytes=payload))
                if queued is not None and queued.recipient_id == user_id:
                    queued.delivered = True
                    db.commit()
                continue
            if message_type in (0x07, 0x08) or recipient_id.int == 0 or len(payload) > 1024 * 1024:
                await websocket.close(code=1008)
                break
            if db.get(IdentityKey, recipient_id) is None:
                continue
            frame = queue_for_delivery(user_id, recipient_id, message_type, payload, db)
            target = connections.get(recipient_id)
            if target is not None:
                try:
                    await target.send_bytes(frame)
                except (RuntimeError, WebSocketDisconnect):
                    pass
    except WebSocketDisconnect:
        pass
    finally:
        if connections.get(user_id) is websocket:
            del connections[user_id]
