import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session
from webauthn import verify_authentication_response

from ..db import get_db
from ..models.blobs import Blob, Credential
from ..security import (
    RP_ID, WEB_ORIGIN, b64url, from_b64url, hex_bytes, new_challenge,
    receipt_public_key, require_challenge, sign_receipt,
)

router = APIRouter()


class StorageKeyRequest(BaseModel):
    key: str


@router.get("/receipt-key")
def get_receipt_key():
    return {"public_key": receipt_public_key().hex()}


@router.post("/retrieve/challenge")
def retrieve_challenge(request: StorageKeyRequest, db: Session = Depends(get_db)):
    key = hex_bytes(request.key, 32, "storage key")
    blob = db.query(Blob).filter(
        Blob.storage_key == key, Blob.expires_at > func.now(),
        Blob.credential_id.isnot(None),
    ).first()
    if blob is None:
        raise HTTPException(status_code=404, detail="Blob unavailable")
    challenge = new_challenge(db, "retrieve", key)
    return {"challenge": b64url(challenge), "rp_id": RP_ID}


class RetrieveRequest(BaseModel):
    key: str
    challenge: str
    assertion: dict


@router.post("/retrieve")
def retrieve(request: RetrieveRequest, db: Session = Depends(get_db)):
    key = hex_bytes(request.key, 32, "storage key")
    challenge = hex_bytes(request.challenge, 32, "challenge")
    record = require_challenge(db, challenge, "retrieve", key)
    blob = db.query(Blob).filter(
        Blob.storage_key == key, Blob.expires_at > func.now(),
        Blob.credential_id.isnot(None),
    ).with_for_update().first()
    if blob is None:
        raise HTTPException(status_code=404, detail="Blob unavailable")
    credential_id = from_b64url(request.assertion.get("rawId", ""), "credential ID")
    if credential_id != blob.credential_id:
        raise HTTPException(status_code=403, detail="Credential does not own this blob")
    credential = db.get(Credential, credential_id)
    if credential is None:
        raise HTTPException(status_code=403, detail="Credential unavailable")
    try:
        verified = verify_authentication_response(
            credential=request.assertion,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=WEB_ORIGIN,
            credential_public_key=credential.public_key,
            credential_current_sign_count=credential.sign_count,
            require_user_verification=True,
        )
    except Exception:
        raise HTTPException(status_code=403, detail="WebAuthn verification failed") from None
    record.used_at = datetime.datetime.now(datetime.timezone.utc)
    credential.sign_count = verified.new_sign_count
    receipt = sign_receipt(key, challenge)
    value = blob.value.hex()
    db.commit()
    return {"value": value, "receipt": receipt}
