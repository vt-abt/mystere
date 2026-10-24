import base64
import datetime
import os
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import HTTPException

from .models.blobs import Challenge


RP_ID = os.getenv("CUSTODIAN_WEBAUTHN_RP_ID", "localhost")
WEB_ORIGIN = os.getenv("CUSTODIAN_WEB_ORIGIN", "http://localhost:5173")
CHALLENGE_LIFETIME = datetime.timedelta(minutes=5)
RECEIPT_PREFIX = b"MYSTERE_RELEASE_V1"

seed_hex = os.getenv("CUSTODIAN_RECEIPT_PRIVATE_KEY")
if seed_hex:
    try:
        seed = bytes.fromhex(seed_hex)
        if len(seed) != 32:
            raise ValueError()
        receipt_signer = Ed25519PrivateKey.from_private_bytes(seed)
    except ValueError:
        raise RuntimeError("CUSTODIAN_RECEIPT_PRIVATE_KEY must be 32 hex-encoded bytes") from None
elif os.getenv("MYSTERE_ENV") == "production":
    raise RuntimeError("CUSTODIAN_RECEIPT_PRIVATE_KEY is required in production")
else:
    receipt_signer = Ed25519PrivateKey.generate()


def hex_bytes(value: str, length: int, field: str) -> bytes:
    try:
        result = bytes.fromhex(value)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid {field}") from None
    if len(result) != length:
        raise HTTPException(status_code=400, detail=f"Invalid {field} length")
    return result


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def from_b64url(value: str, field: str) -> bytes:
    try:
        if (not value or len(value) > 2048
                or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for char in value)):
            raise ValueError()
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error):
        raise HTTPException(status_code=400, detail=f"Invalid {field}") from None


def new_challenge(db, purpose: str, storage_key: bytes | None = None) -> bytes:
    value = secrets.token_bytes(32)
    db.add(Challenge(
        value=value, purpose=purpose, storage_key=storage_key,
        expires_at=datetime.datetime.now(datetime.timezone.utc) + CHALLENGE_LIFETIME,
    ))
    db.commit()
    return value


def require_challenge(db, value: bytes, purpose: str, storage_key: bytes | None = None):
    record = db.query(Challenge).filter(Challenge.value == value).with_for_update().first()
    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = record.expires_at if record is not None else now
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
    if (record is None or record.purpose != purpose or record.storage_key != storage_key
            or record.used_at is not None or expires_at <= now):
        raise HTTPException(status_code=403, detail="Invalid or expired challenge")
    return record


def receipt_public_key() -> bytes:
    return receipt_signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def sign_receipt(storage_key: bytes, challenge: bytes) -> dict[str, str]:
    timestamp = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000).to_bytes(8, "big")
    payload = RECEIPT_PREFIX + storage_key + challenge + timestamp
    return {"payload": payload.hex(), "signature": receipt_signer.sign(payload).hex()}
