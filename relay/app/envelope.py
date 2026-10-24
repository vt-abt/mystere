import uuid

from fastapi import HTTPException


def parse_outbound(data: bytes) -> tuple[uuid.UUID, int, bytes]:
    if len(data) < 17:
        raise HTTPException(status_code=400, detail="Invalid envelope")
    return uuid.UUID(bytes=data[:16]), data[16], data[17:]


def delivery_frame(sender_id: uuid.UUID, message_type: int, payload: bytes,
                   queue_id: uuid.UUID | None = None) -> bytes:
    return (queue_id or uuid.UUID(int=0)).bytes + sender_id.bytes + bytes([message_type]) + payload
