from __future__ import annotations
from pydantic import BaseModel, EmailStr
from datetime import datetime


class PlatformStats(BaseModel):
    total_tenants: int
    active_tenants: int
    total_users: int
    total_sessions: int
    active_sessions: int
    total_messages: int


class AuditLogResponse(BaseModel):
    id: str
    tenant_id: str
    user_id: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    ip_address: str | None
    details: dict
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditLogListResponse(BaseModel):
    logs: list[AuditLogResponse]
    total: int


class AdminUpdateTenantRequest(BaseModel):
    plan: str | None = None
    is_active: bool | None = None
    max_sessions_per_day: int | None = None
    session_ttl_seconds: int | None = None


class AdminCreateUserRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_id: str
    role: str = "user"


class AdminUserResponse(BaseModel):
    id: str
    tenant_id: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: datetime | None

    model_config = {"from_attributes": True}


class AdminUserListResponse(BaseModel):
    users: list[AdminUserResponse]
    total: int
