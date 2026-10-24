import datetime
import os
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..models.blobs import Blob, Credential
from ..security import from_b64url, hex_bytes

router = APIRouter()
MAX_BLOB_SIZE = int(os.getenv("CUSTODIAN_MAX_BLOB_SIZE_BYTES", "256"))
MAX_TTL = int(os.getenv("CUSTODIAN_MAX_TTL_SECONDS", "7200"))


class DepositRequest(BaseModel):
    key: str
    value: str
    ttl: int
    credential_id: str


@router.post("/deposit")
def deposit(request: DepositRequest, db: Session = Depends(get_db)):
    key = hex_bytes(request.key, 32, "storage key")
    if len(request.value) > MAX_BLOB_SIZE * 2:
        raise HTTPException(status_code=400, detail="Invalid blob size")
    try:
        value = bytes.fromhex(request.value)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid blob") from None
    if not value or len(value) > MAX_BLOB_SIZE:
        raise HTTPException(status_code=400, detail="Invalid blob size")
    credential_id = from_b64url(request.credential_id, "credential ID")
    if db.get(Credential, credential_id) is None:
        raise HTTPException(status_code=404, detail="Credential not enrolled")
    now = time.time()
    if request.ttl <= now or request.ttl > now + MAX_TTL:
        raise HTTPException(status_code=400, detail="Invalid TTL")
    if db.get(Blob, key) is not None:
        raise HTTPException(status_code=409, detail="Storage key already used")
    db.add(Blob(
        storage_key=key, value=value, credential_id=credential_id,
        expires_at=datetime.datetime.fromtimestamp(request.ttl, datetime.timezone.utc),
    ))
    db.commit()
    return {"status": "ok"}
