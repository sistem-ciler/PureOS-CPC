from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.user import User
from backend.schemas.auth import (
    RegisterRequest, LoginRequest, TokenResponse,
    RefreshRequest, ChangePasswordRequest, UserResponse,
)
from backend.services import auth_service, audit_service
from backend.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=dict, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, request: Request, db: AsyncSession = Depends(get_db)):
    try:
        user, raw_api_key = await auth_service.register_user(
            db, body.email, body.password, body.tenant_name
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))

    await audit_service.log(
        db,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="auth.register",
        ip_address=request.client.host if request.client else None,
    )

    access = auth_service.create_access_token(user.id, user.tenant_id, user.role.value)
    refresh = auth_service.create_refresh_token(user.id)

    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in": settings.JWT_ACCESS_TTL,
        "api_key": raw_api_key,
        "api_key_note": "Store this API key securely — it will not be shown again.",
    }


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    try:
        user = await auth_service.authenticate_user(db, body.email, body.password)
    except ValueError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e))

    await audit_service.log(
        db,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="auth.login",
        ip_address=request.client.host if request.client else None,
    )

    return TokenResponse(
        access_token=auth_service.create_access_token(user.id, user.tenant_id, user.role.value),
        refresh_token=auth_service.create_refresh_token(user.id),
        expires_in=settings.JWT_ACCESS_TTL,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    from jwt import ExpiredSignatureError, DecodeError
    try:
        payload = auth_service.decode_token(body.refresh_token)
    except (ExpiredSignatureError, DecodeError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong token type")

    user = await auth_service.get_user_by_id(db, payload["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")

    return TokenResponse(
        access_token=auth_service.create_access_token(user.id, user.tenant_id, user.role.value),
        refresh_token=auth_service.create_refresh_token(user.id),
        expires_in=settings.JWT_ACCESS_TTL,
    )


@router.get("/me", response_model=UserResponse)
async def me(user: User = Depends(get_current_user)):
    return user


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not auth_service.verify_password(body.current_password, user.hashed_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")

    user.hashed_password = auth_service.hash_password(body.new_password)
    await audit_service.log(
        db,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="auth.change_password",
        ip_address=request.client.host if request.client else None,
    )
