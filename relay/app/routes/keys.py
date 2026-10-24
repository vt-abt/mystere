import datetime
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..auth import hex_bytes, registration_payload, verify_signature
from ..db import get_db
from ..models.prekeys import IdentityKey, OneTimePrekey, PrekeyFetch, SignedPrekey
from ..models.sessions import SessionCommitment

router = APIRouter()


class PublicPrekey(BaseModel):
    key_id: int = Field(ge=1, le=2**31 - 1)
    pubkey: str


class IdentityCreate(BaseModel):
    identity_pubkey: str
    signing_pubkey: str
    registration_id: int = Field(ge=0, le=16383)
    signed_prekey_id: int = Field(ge=1, le=2**31 - 1)
    signed_prekey: str
    signed_prekey_sig: str
    one_time_prekeys: list[PublicPrekey] = Field(min_length=1, max_length=100)
    registration_signature: str


@router.post("/identity")
def create_identity(data: IdentityCreate, db: Session = Depends(get_db)):
    identity_key = hex_bytes(data.identity_pubkey, 33, "identity_pubkey")
    signing_key = hex_bytes(data.signing_pubkey, 32, "signing_pubkey")
    signed_key = hex_bytes(data.signed_prekey, 33, "signed_prekey")
    signed_signature = hex_bytes(data.signed_prekey_sig, 64, "signed_prekey_sig")
    one_time = [(item.key_id, hex_bytes(item.pubkey, 33, "prekey")) for item in data.one_time_prekeys]
    if len({key_id for key_id, _ in one_time}) != len(one_time):
        raise HTTPException(status_code=400, detail="Duplicate prekey IDs")
    proof = hex_bytes(data.registration_signature, 64, "registration_signature")
    verify_signature(signing_key, registration_payload(
        identity_key, data.registration_id, data.signed_prekey_id,
        signed_key, signed_signature, one_time,
    ), proof)

    identity = IdentityKey(
        identity_pubkey=identity_key,
        signing_pubkey=signing_key,
        registration_id=data.registration_id,
        webauthn_pubkey=b"",
    )
    db.add(identity)
    db.flush()
    db.add(SignedPrekey(
        user_id=identity.user_id, key_id=data.signed_prekey_id,
        pubkey=signed_key, signature=signed_signature,
    ))
    for key_id, public_key in one_time:
        db.add(OneTimePrekey(user_id=identity.user_id, key_id=key_id, pubkey=public_key))
    db.commit()
    return {"user_id": str(identity.user_id)}


@router.get("/identity/{user_id}")
def get_identity(user_id: uuid.UUID, db: Session = Depends(get_db)):
    identity = db.get(IdentityKey, user_id)
    if identity is None or identity.signing_pubkey is None or identity.registration_id is None:
        raise HTTPException(status_code=404, detail="User not found")
    signed = (db.query(SignedPrekey).filter(SignedPrekey.user_id == user_id)
              .filter(SignedPrekey.key_id.isnot(None))
              .order_by(SignedPrekey.created_at.desc()).first())
    if signed is None:
        raise HTTPException(status_code=404, detail="Signed prekey missing")
    return {
        "identity_pubkey": identity.identity_pubkey.hex(),
        "signing_pubkey": identity.signing_pubkey.hex(),
        "registration_id": identity.registration_id,
        "signed_prekey_id": signed.key_id,
        "signed_prekey": signed.pubkey.hex(),
        "signed_prekey_sig": signed.signature.hex(),
    }


class PrekeyFetchRequest(BaseModel):
    session_id: str
    proof: str


@router.post("/prekeys/{user_id}/fetch")
def get_prekeys(user_id: uuid.UUID, request: PrekeyFetchRequest, db: Session = Depends(get_db)):
    session_bytes = hex_bytes(request.session_id, 64, "session_id")
    commitment = (db.query(SessionCommitment).filter(
        SessionCommitment.session_id == session_bytes,
        SessionCommitment.responder_id == user_id,
        SessionCommitment.status == "committed",
        SessionCommitment.created_at >= datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=24),
    ).with_for_update().first())
    if commitment is None:
        raise HTTPException(status_code=403, detail="Committed session required")
    initiator = db.get(IdentityKey, commitment.initiator_id)
    if initiator is None or initiator.signing_pubkey is None:
        raise HTTPException(status_code=403, detail="Registered initiator required")
    verify_signature(initiator.signing_pubkey, b"MYSTERE_PREKEY_FETCH_V1" + session_bytes + user_id.bytes,
                     hex_bytes(request.proof, 64, "proof"))
    identity = db.get(IdentityKey, user_id)
    if identity is None or identity.registration_id is None:
        raise HTTPException(status_code=404, detail="Registered identity required")
    signed = (db.query(SignedPrekey).filter(SignedPrekey.user_id == user_id)
              .filter(SignedPrekey.key_id.isnot(None))
              .order_by(SignedPrekey.created_at.desc()).first())
    previous = db.get(PrekeyFetch, session_bytes)
    if previous is not None:
        one_time = db.get(OneTimePrekey, previous.prekey_id)
    else:
        one_time = (db.query(OneTimePrekey).filter(
            OneTimePrekey.user_id == user_id, OneTimePrekey.consumed.is_(False),
            OneTimePrekey.key_id.isnot(None),
        ).with_for_update(skip_locked=True).first())
        if one_time is None:
            raise HTTPException(status_code=409, detail="No one-time prekeys available")
        one_time.consumed = True
        one_time.consumed_at = datetime.datetime.now(datetime.timezone.utc)
        db.add(PrekeyFetch(session_id=session_bytes, prekey_id=one_time.id))
        db.commit()
    remaining = db.query(OneTimePrekey).filter(
        OneTimePrekey.user_id == user_id, OneTimePrekey.consumed.is_(False),
    ).count()
    return {
        "identity_pubkey": identity.identity_pubkey.hex(),
        "registration_id": identity.registration_id,
        "signed_prekey_id": signed.key_id,
        "signed_prekey": signed.pubkey.hex(),
        "signed_prekey_sig": signed.signature.hex(),
        "one_time_prekey_id": one_time.key_id,
        "one_time_prekey": one_time.pubkey.hex(),
        "needs_replenishment": remaining < 20,
    }


class ReplenishPrekeys(BaseModel):
    user_id: uuid.UUID
    one_time_prekeys: list[PublicPrekey] = Field(min_length=1, max_length=100)
    signature: str


@router.post("/prekeys/replenish")
def replenish_prekeys(data: ReplenishPrekeys, db: Session = Depends(get_db)):
    identity = db.get(IdentityKey, data.user_id)
    if identity is None or identity.signing_pubkey is None:
        raise HTTPException(status_code=404, detail="User not found")
    keys = [(item.key_id, hex_bytes(item.pubkey, 33, "prekey")) for item in data.one_time_prekeys]
    if len({key_id for key_id, _ in keys}) != len(keys):
        raise HTTPException(status_code=400, detail="Duplicate prekey IDs")
    payload = b"MYSTERE_REPLENISH_V1" + data.user_id.bytes
    for key_id, public_key in keys:
        payload += key_id.to_bytes(4, "big") + public_key
    verify_signature(identity.signing_pubkey, payload, hex_bytes(data.signature, 64, "signature"))
    for key_id, public_key in keys:
        existing = db.query(OneTimePrekey).filter(
            OneTimePrekey.user_id == data.user_id,
            OneTimePrekey.key_id == key_id,
        ).first()
        if existing is not None:
            if existing.pubkey != public_key:
                raise HTTPException(status_code=409, detail="Prekey ID already used")
            continue
        db.add(OneTimePrekey(user_id=data.user_id, key_id=key_id, pubkey=public_key))
    db.commit()
    return {"status": "ok"}
