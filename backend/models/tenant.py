import uuid
import enum
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Enum, JSON, Integer
from sqlalchemy.orm import relationship
from backend.database import Base


class TenantPlan(str, enum.Enum):
    free = "free"
    pro = "pro"
    enterprise = "enterprise"


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False, unique=True, index=True)
    plan = Column(Enum(TenantPlan), default=TenantPlan.free, nullable=False)
    api_key_hash = Column(String, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    # Per-tenant limits
    max_sessions_per_day = Column(Integer, default=100, nullable=False)
    session_ttl_seconds = Column(Integer, default=1800, nullable=False)
    settings = Column(JSON, default=dict, nullable=False)

    users = relationship("User", back_populates="tenant", lazy="raise")
    sessions = relationship("OTCSession", back_populates="tenant", lazy="raise")
    audit_logs = relationship("AuditLog", back_populates="tenant", lazy="raise")
