from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from backend.database import get_db
from backend.dependencies import require_platform_admin
from backend.models.user import User, UserRole
from backend.models.tenant import Tenant, TenantPlan
from backend.models.otc_session import OTCSession, SessionStatus, EncryptedMessage
from backend.models.audit_log import AuditLog
from backend.schemas.admin import (
    PlatformStats, AuditLogListResponse, AuditLogResponse,
    AdminUpdateTenantRequest, AdminCreateUserRequest,
    AdminUserResponse, AdminUserListResponse,
)
from backend.schemas.tenants import TenantResponse, TenantListResponse
from backend.services import audit_service
from backend.services.auth_service import hash_password

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/stats", response_model=PlatformStats)
async def platform_stats(
    _: User = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    total_tenants = (await db.execute(select(func.count(Tenant.id)))).scalar_one()
    active_tenants = (
        await db.execute(select(func.count(Tenant.id)).where(Tenant.is_active == True))
    ).scalar_one()
    total_users = (await db.execute(select(func.count(User.id)))).scalar_one()
    total_sessions = (await db.execute(select(func.count(OTCSession.id)))).scalar_one()
    active_sessions = (
        await db.execute(
            select(func.count(OTCSession.id)).where(OTCSession.status == SessionStatus.active)
        )
    ).scalar_one()
    total_messages = (await db.execute(select(func.count(EncryptedMessage.id)))).scalar_one()

    return PlatformStats(
        total_tenants=total_tenants,
        active_tenants=active_tenants,
        total_users=total_users,
        total_sessions=total_sessions,
        active_sessions=active_sessions,
        total_messages=total_messages,
    )


@router.get("/tenants", response_model=TenantListResponse)
async def list_tenants(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _: User = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    total = (await db.execute(select(func.count(Tenant.id)))).scalar_one()
    rows = await db.execute(select(Tenant).limit(limit).offset(offset))
    tenants = list(rows.scalars().all())
    return TenantListResponse(tenants=tenants, total=total)


@router.get("/tenants/{tenant_id}", response_model=TenantResponse)
async def get_tenant(
    tenant_id: str,
    _: User = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant not found")
    return tenant


@router.patch("/tenants/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: str,
    body: AdminUpdateTenantRequest,
    admin: User = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant not found")

    if body.plan is not None:
        tenant.plan = TenantPlan(body.plan)
    if body.is_active is not None:
        tenant.is_active = body.is_active
    if body.max_sessions_per_day is not None:
        tenant.max_sessions_per_day = body.max_sessions_per_day
    if body.session_ttl_seconds is not None:
        tenant.session_ttl_seconds = body.session_ttl_seconds

    await audit_service.log(
        db,
        tenant_id=admin.tenant_id,
        user_id=admin.id,
        action="admin.tenant.update",
        resource_type="tenant",
        resource_id=tenant_id,
    )
    return tenant


@router.get("/users", response_model=AdminUserListResponse)
async def list_users(
    tenant_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _: User = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    q = select(User)
    if tenant_id:
        q = q.where(User.tenant_id == tenant_id)
    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows = await db.execute(q.limit(limit).offset(offset))
    return AdminUserListResponse(users=list(rows.scalars().all()), total=total)


@router.post("/users", response_model=AdminUserResponse, status_code=201)
async def create_user(
    body: AdminCreateUserRequest,
    admin: User = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    existing = (
        await db.execute(select(User).where(User.email == body.email))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    tenant = (
        await db.execute(select(Tenant).where(Tenant.id == body.tenant_id))
    ).scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant not found")

    user = User(
        tenant_id=body.tenant_id,
        email=body.email,
        hashed_password=hash_password(body.password),
        role=UserRole(body.role),
    )
    db.add(user)
    await db.flush()

    await audit_service.log(
        db,
        tenant_id=admin.tenant_id,
        user_id=admin.id,
        action="admin.user.create",
        resource_type="user",
        resource_id=user.id,
    )
    return user


@router.get("/audit-logs", response_model=AuditLogListResponse)
async def get_audit_logs(
    tenant_id: str | None = Query(None),
    action: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    admin: User = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    target_tenant = tenant_id or admin.tenant_id
    logs, total = await audit_service.list_logs(
        db, tenant_id=target_tenant, action=action, limit=limit, offset=offset
    )
    return AuditLogListResponse(
        logs=[AuditLogResponse.model_validate(l) for l in logs],
        total=total,
    )
