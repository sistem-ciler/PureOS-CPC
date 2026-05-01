import base64
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.user import User
from backend.models.tenant import Tenant
from backend.models.otc_session import OTCSession, SessionStatus, EncryptedMessage
from backend.schemas.sessions import (
    CreateSessionRequest, SessionCreatedResponse,
    RedeemOTCRequest, RedeemOTCResponse,
    SessionResponse, SessionListResponse,
    PostMessageRequest, MessageResponse,
)
from backend.services import otc_service, audit_service
from backend.services.crypto import KDF_INFO

router = APIRouter(prefix="/sessions", tags=["sessions"])


async def _fetch_tenant(db: AsyncSession, tenant_id: str) -> Tenant:
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None or not tenant.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Tenant not found or inactive")
    return tenant


async def _msg_count(db: AsyncSession, session_id: str) -> int:
    from sqlalchemy import func
    r = await db.execute(
        select(func.count(EncryptedMessage.id)).where(EncryptedMessage.session_id == session_id)
    )
    return r.scalar_one()


def _session_response(s: OTCSession, msg_count: int = 0) -> SessionResponse:
    return SessionResponse(
        id=s.id,
        tenant_id=s.tenant_id,
        creator_id=s.creator_id,
        status=s.status.value,
        label=s.label,
        created_at=s.created_at,
        expires_at=s.expires_at,
        redeemed_at=s.redeemed_at,
        revoked_at=s.revoked_at,
        message_count=msg_count,
    )


@router.post("", response_model=SessionCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_session(
    body: CreateSessionRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    tenant = await _fetch_tenant(db, user.tenant_id)
    session, raw_otc = await otc_service.create_session(
        db,
        tenant=tenant,
        creator_id=user.id,
        label=body.label,
        ttl_seconds=body.ttl_seconds,
        metadata=body.metadata,
    )
    await audit_service.log(
        db,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="session.create",
        resource_type="otc_session",
        resource_id=session.id,
        ip_address=request.client.host if request.client else None,
        details={"label": body.label},
    )
    return SessionCreatedResponse(
        session_id=session.id,
        otc=raw_otc,
        kdf_salt=session.kdf_salt,
        expires_at=session.expires_at,
        label=session.label,
        key_derivation_info=KDF_INFO.decode(),
    )


@router.get("", response_model=SessionListResponse)
async def list_sessions(
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    sessions, total = await otc_service.list_sessions(
        db,
        tenant_id=user.tenant_id,
        creator_id=user.id,
        status=status_filter,
        limit=limit,
        offset=offset,
    )
    items = [_session_response(s) for s in sessions]
    return SessionListResponse(sessions=items, total=total)


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    session = await otc_service.get_session(db, session_id, user.tenant_id)
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    count = await _msg_count(db, session_id)
    return _session_response(session, count)


@router.post("/{session_id}/redeem", response_model=RedeemOTCResponse)
async def redeem_otc(
    session_id: str,
    body: RedeemOTCRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        session = await otc_service.redeem_session(
            db, session_id, user.tenant_id, body.otc
        )
    except (ValueError, PermissionError) as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    await audit_service.log(
        db,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="session.redeem",
        resource_type="otc_session",
        resource_id=session_id,
        ip_address=request.client.host if request.client else None,
    )
    return RedeemOTCResponse(
        session_id=session.id,
        kdf_salt=session.kdf_salt,
        expires_at=session.expires_at,
        label=session.label,
        key_derivation_info=KDF_INFO.decode(),
    )


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        await otc_service.revoke_session(db, session_id, user.tenant_id, user.id)
    except PermissionError as e:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(e))
    except ValueError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))

    await audit_service.log(
        db,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="session.revoke",
        resource_type="otc_session",
        resource_id=session_id,
        ip_address=request.client.host if request.client else None,
    )


@router.post("/{session_id}/messages", response_model=MessageResponse, status_code=201)
async def post_message(
    session_id: str,
    body: PostMessageRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    session = await otc_service.get_session(db, session_id, user.tenant_id)
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    if session.status != SessionStatus.active:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Session is {session.status.value}; cannot post messages",
        )

    sender_role = "creator" if session.creator_id == user.id else "redeemer"

    try:
        msg = await otc_service.post_message(db, session, sender_role, body.ciphertext_b64)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    await audit_service.log(
        db,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="message.post",
        resource_type="otc_session",
        resource_id=session_id,
        ip_address=request.client.host if request.client else None,
        details={"sequence": msg.sequence},
    )
    return MessageResponse(
        id=msg.id,
        session_id=msg.session_id,
        sender_role=msg.sender_role,
        ciphertext_b64=base64.b64encode(msg.ciphertext).decode(),
        sequence=msg.sequence,
        created_at=msg.created_at,
    )


@router.get("/{session_id}/messages", response_model=list[MessageResponse])
async def get_messages(
    session_id: str,
    after: int = Query(0, ge=0, description="Return messages with sequence > after"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    session = await otc_service.get_session(db, session_id, user.tenant_id)
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    if session.status not in (SessionStatus.active,):
        raise HTTPException(status.HTTP_409_CONFLICT, "Session is not active")

    msgs = await otc_service.get_messages(db, session_id, after_sequence=after)
    return [
        MessageResponse(
            id=m.id,
            session_id=m.session_id,
            sender_role=m.sender_role,
            ciphertext_b64=base64.b64encode(m.ciphertext).decode(),
            sequence=m.sequence,
            created_at=m.created_at,
        )
        for m in msgs
    ]
