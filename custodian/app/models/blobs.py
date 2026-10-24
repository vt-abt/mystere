from sqlalchemy import Column, DateTime, ForeignKey, Integer, LargeBinary, String, func
from ..db import Base

class Blob(Base):
    __tablename__ = "blobs"
    storage_key = Column(LargeBinary, primary_key=True) # SHA-256(capability_token || message_id)
    value = Column(LargeBinary, nullable=False)        # encrypted custodian_blob, opaque
    credential_id = Column(LargeBinary, ForeignKey("credentials.id"))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Credential(Base):
    __tablename__ = "credentials"
    id = Column(LargeBinary, primary_key=True)
    public_key = Column(LargeBinary, nullable=False)
    sign_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Challenge(Base):
    __tablename__ = "challenges"
    value = Column(LargeBinary, primary_key=True)
    purpose = Column(String(16), nullable=False)
    storage_key = Column(LargeBinary)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True))
