import datetime
import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from webauthn import verify_registration_response

from ..db import get_db
from ..models.blobs import Credential
from ..security import RP_ID, WEB_ORIGIN, b64url, hex_bytes, new_challenge, require_challenge

router = APIRouter(prefix="/credentials")


@router.post("/options")
def registration_options(db: Session = Depends(get_db)):
    challenge = new_challenge(db, "register")
    return {
        "challenge": b64url(challenge),
        "rp_id": RP_ID,
        "user_id": b64url(secrets.token_bytes(16)),
    }


class Enrollment(BaseModel):
    challenge: str
    credential: dict


@router.post("/enroll")
def enroll(request: Enrollment, db: Session = Depends(get_db)):
    challenge = hex_bytes(request.challenge, 32, "challenge")
    record = require_challenge(db, challenge, "register")
    try:
        verified = verify_registration_response(
            credential=request.credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=WEB_ORIGIN,
            require_user_presence=True,
            require_user_verification=True,
        )
    except Exception:
        raise HTTPException(status_code=403, detail="Credential registration failed") from None
    if db.get(Credential, verified.credential_id) is not None:
        raise HTTPException(status_code=409, detail="Credential already enrolled")
    db.add(Credential(
        id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
    ))
    record.used_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    return {"credential_id": b64url(verified.credential_id)}
