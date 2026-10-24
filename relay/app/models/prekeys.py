import uuid
from sqlalchemy import Column, Boolean, DateTime, ForeignKey, LargeBinary, Integer, SmallInteger, func
from sqlalchemy.dialects.postgresql import UUID
from ..db import Base

class IdentityKey(Base):
    __tablename__ = "identity_keys"
    user_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    identity_pubkey = Column(LargeBinary, nullable=False)
    signing_pubkey = Column(LargeBinary)
    registration_id = Column(SmallInteger)
    webauthn_pubkey = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class SignedPrekey(Base):
    __tablename__ = "signed_prekeys"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("identity_keys.user_id"))
    key_id = Column(Integer)
    pubkey = Column(LargeBinary, nullable=False)
    signature = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class OneTimePrekey(Base):
    __tablename__ = "one_time_prekeys"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("identity_keys.user_id"))
    key_id = Column(Integer)
    pubkey = Column(LargeBinary, nullable=False)
    consumed = Column(Boolean, default=False)
    consumed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class PrekeyFetch(Base):
    __tablename__ = "prekey_fetches"
    session_id = Column(LargeBinary, ForeignKey("session_commitments.session_id"), primary_key=True)
    prekey_id = Column(UUID(as_uuid=True), ForeignKey("one_time_prekeys.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
