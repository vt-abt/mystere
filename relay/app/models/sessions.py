import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, LargeBinary, SmallInteger, BigInteger, func
from sqlalchemy.dialects.postgresql import UUID
from ..db import Base

class SessionCommitment(Base):
    __tablename__ = "session_commitments"
    session_id = Column(LargeBinary, primary_key=True)
    initiator_id = Column(UUID(as_uuid=True), ForeignKey("identity_keys.user_id"))
    responder_id = Column(UUID(as_uuid=True), ForeignKey("identity_keys.user_id"))
    session_request = Column(LargeBinary, nullable=False)
    session_ack = Column(LargeBinary)
    status = Column(String, default="pending")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class MessageQueue(Base):
    __tablename__ = "message_queue"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(LargeBinary, ForeignKey("session_commitments.session_id"))
    recipient_id = Column(UUID(as_uuid=True), ForeignKey("identity_keys.user_id"))
    message_type = Column(SmallInteger, nullable=False)
    payload = Column(LargeBinary, nullable=False)
    sequence_num = Column(BigInteger, nullable=False)
    delivered = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True))
