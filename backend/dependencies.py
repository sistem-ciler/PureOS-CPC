from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from jwt import ExpiredSignatureError, DecodeError

from backend.database import get_db
from backend.models.user import User, UserRole
from backend.services import auth_service

bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    try:
        payload = auth_service.decode_token(credentials.credentials)
    except ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    except DecodeError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")

    if payload.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong token type")

    user = await auth_service.get_user_by_id(db, payload["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")
    return user


async def require_tenant_admin(user: User = Depends(get_current_user)) -> User:
    if user.role not in (UserRole.tenant_admin, UserRole.platform_admin):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Tenant admin required")
    return user


async def require_platform_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != UserRole.platform_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Platform admin required")
    return user
