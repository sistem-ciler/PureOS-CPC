import uuid
import enum
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Enum, ForeignKey
from sqlalchemy.orm import relationship
from backend.database import Base


class UserRole(str, enum.Enum):
    platform_admin = "platform_admin"
    tenant_admin = "tenant_admin"
    user = "user"


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False, index=True)
    email = Column(String, nullable=False, unique=True, index=True)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.user, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_login = Column(DateTime(timezone=True), nullable=True)

    tenant = relationship("Tenant", back_populates="users", lazy="raise")
    sessions = relationship("OTCSession", back_populates="creator", lazy="raise")
    audit_logs = relationship("AuditLog", back_populates="user", lazy="raise")
