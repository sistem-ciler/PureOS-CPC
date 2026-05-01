from __future__ import annotations
from pydantic import BaseModel
from datetime import datetime


class TenantResponse(BaseModel):
    id: str
    name: str
    plan: str
    is_active: bool
    max_sessions_per_day: int
    session_ttl_seconds: int
    created_at: datetime
    settings: dict

    model_config = {"from_attributes": True}


class UpdateTenantRequest(BaseModel):
    session_ttl_seconds: int | None = None
    settings: dict | None = None


class APIKeyResponse(BaseModel):
    api_key: str     # shown ONCE on creation
    message: str = "Store this key securely — it will not be shown again."


class TenantListResponse(BaseModel):
    tenants: list[TenantResponse]
    total: int
