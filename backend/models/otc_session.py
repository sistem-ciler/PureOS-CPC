import uuid
import enum
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Boolean, DateTime, Enum, ForeignKey,
    JSON, Integer, LargeBinary,
)
from sqlalchemy.orm import relationship
from backend.database import Base


class SessionStatus(str, enum.Enum):
    pending = "pending"     # OTC issued, not yet redeemed
    active = "active"       # OTC redeemed; both parties have key material
    expired = "expired"     # Past TTL without redemption
    revoked = "revoked"     # Manually invalidated


class OTCSession(Base):
    __tablename__ = "otc_sessions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    creator_id = Column(String, ForeignKey("users.id"), nullable=False)

    # SHA-256(raw_otc) — raw OTC is returned once and never persisted
    otc_hash = Column(String, nullable=False)

    # Public salt fed into HKDF on both sides for key derivation
    kdf_salt = Column(String, nullable=False)  # base64url

    status = Column(Enum(SessionStatus), default=SessionStatus.pending, nullable=False)
    label = Column(String, nullable=True)
    metadata_ = Column("metadata", JSON, default=dict, nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    redeemed_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    tenant = relationship("Tenant", back_populates="sessions", lazy="raise")
    creator = relationship("User", back_populates="sessions", lazy="raise")
    messages = relationship(
        "EncryptedMessage", back_populates="session",
        order_by="EncryptedMessage.sequence", lazy="raise",
    )


class EncryptedMessage(Base):
    """
    Zero-knowledge relay storage.
    The server stores ciphertext only and cannot decrypt anything.
    """
    __tablename__ = "encrypted_messages"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("otc_sessions.id"), nullable=False, index=True)
    # "creator" = party A who created the session; "redeemer" = party B
    sender_role = Column(String, nullable=False)
    # Raw bytes stored as blob; clients base64-encode before sending
    ciphertext = Column(LargeBinary, nullable=False)
    sequence = Column(Integer, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    session = relationship("OTCSession", back_populates="messages", lazy="raise")
