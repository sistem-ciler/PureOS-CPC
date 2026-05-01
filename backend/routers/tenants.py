from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.database import get_db
from backend.dependencies import get_current_user, require_tenant_admin
from backend.models.user import User
from backend.models.tenant import Tenant
from backend.schemas.tenants import TenantResponse, UpdateTenantRequest, APIKeyResponse
from backend.services import audit_service
from backend.services.crypto import CryptoEngine

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.get("/me", response_model=TenantResponse)
async def get_my_tenant(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant not found")
    return tenant


@router.put("/me", response_model=TenantResponse)
async def update_my_tenant(
    body: UpdateTenantRequest,
    request: Request,
    user: User = Depends(require_tenant_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant not found")

    if body.session_ttl_seconds is not None:
        tenant.session_ttl_seconds = body.session_ttl_seconds
    if body.settings is not None:
        tenant.settings = {**tenant.settings, **body.settings}

    await audit_service.log(
        db,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="tenant.update",
        resource_type="tenant",
        resource_id=tenant.id,
        ip_address=request.client.host if request.client else None,
    )
    return tenant


@router.post("/me/rotate-api-key", response_model=APIKeyResponse)
async def rotate_api_key(
    request: Request,
    user: User = Depends(require_tenant_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant not found")

    raw_key, key_hash = CryptoEngine.generate_api_key()
    tenant.api_key_hash = key_hash

    await audit_service.log(
        db,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="tenant.rotate_api_key",
        resource_type="tenant",
        resource_id=tenant.id,
        ip_address=request.client.host if request.client else None,
    )
    return APIKeyResponse(api_key=raw_key)
