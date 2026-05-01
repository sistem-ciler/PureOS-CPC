from __future__ import annotations
from pydantic import BaseModel, field_validator
from datetime import datetime


class CreateSessionRequest(BaseModel):
    label: str | None = None
    ttl_seconds: int | None = None   # override tenant default
    metadata: dict = {}


class SessionCreatedResponse(BaseModel):
    session_id: str
    otc: str                  # raw one-time code — shown ONCE, never again
    kdf_salt: str             # public HKDF salt for key derivation
    expires_at: datetime
    label: str | None
    key_derivation_info: str  # canonical info string for HKDF

    model_config = {"from_attributes": True}


class RedeemOTCRequest(BaseModel):
    otc: str

    @field_validator("otc")
    @classmethod
    def otc_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("OTC cannot be empty")
        return v.strip()


class RedeemOTCResponse(BaseModel):
    session_id: str
    kdf_salt: str
    expires_at: datetime
    label: str | None
    key_derivation_info: str


class SessionResponse(BaseModel):
    id: str
    tenant_id: str
    creator_id: str
    status: str
    label: str | None
    created_at: datetime
    expires_at: datetime
    redeemed_at: datetime | None
    revoked_at: datetime | None
    message_count: int = 0

    model_config = {"from_attributes": True}


class PostMessageRequest(BaseModel):
    ciphertext_b64: str       # AES-256-GCM encrypted, base64-encoded by client

    @field_validator("ciphertext_b64")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("ciphertext cannot be empty")
        return v.strip()


class MessageResponse(BaseModel):
    id: str
    session_id: str
    sender_role: str
    ciphertext_b64: str
    sequence: int
    created_at: datetime

    model_config = {"from_attributes": True}


class SessionListResponse(BaseModel):
    sessions: list[SessionResponse]
    total: int
