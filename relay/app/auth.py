import datetime
import hashlib
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import HTTPException


MAX_COMMITMENT_AGE = datetime.timedelta(minutes=5)


def hex_bytes(value: str, length: int, field: str) -> bytes:
    try:
        result = bytes.fromhex(value)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid {field}") from None
    if len(result) != length:
        raise HTTPException(status_code=400, detail=f"Invalid {field} length")
    return result


def verify_signature(public_key: bytes, payload: bytes, signature: bytes) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except (InvalidSignature, ValueError):
        raise HTTPException(status_code=403, detail="Invalid signature") from None


def fresh_timestamp(payload: bytes, offset: int) -> bool:
    timestamp = int.from_bytes(payload[offset:offset + 8], "big")
    try:
        moment = datetime.datetime.fromtimestamp(timestamp / 1000, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return False
    now = datetime.datetime.now(datetime.timezone.utc)
    return abs(now - moment) <= MAX_COMMITMENT_AGE


def validate_request(payload: bytes, target: uuid.UUID) -> None:
    if len(payload) != 56 or payload[:16] != target.bytes or not fresh_timestamp(payload, 48):
        raise HTTPException(status_code=400, detail="Invalid or stale session request")


def validate_ack(request: bytes, acknowledgment: bytes) -> None:
    if (len(acknowledgment) != 104 or
            acknowledgment[:64] != hashlib.sha512(request).digest() or
            not fresh_timestamp(acknowledgment, 96)):
        raise HTTPException(status_code=400, detail="Invalid or stale session acknowledgment")


def registration_payload(identity_key: bytes, registration_id: int, signed_key_id: int,
                         signed_key: bytes, signed_signature: bytes,
                         one_time_keys: list[tuple[int, bytes]]) -> bytes:
    result = (b"MYSTERE_IDENTITY_V1" + identity_key + registration_id.to_bytes(2, "big") +
              signed_key_id.to_bytes(4, "big") + signed_key + signed_signature)
    for key_id, public_key in one_time_keys:
        result += key_id.to_bytes(4, "big") + public_key
    return result
