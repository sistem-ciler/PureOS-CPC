from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.config import get_settings
from backend.models.user import User, UserRole
from backend.models.tenant import Tenant, TenantPlan
from backend.services.crypto import CryptoEngine

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(user_id: str, tenant_id: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "role": role,
        "type": "access",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=settings.JWT_ACCESS_TTL),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "type": "refresh",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=settings.JWT_REFRESH_TTL),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])


async def register_user(
    db: AsyncSession,
    email: str,
    password: str,
    tenant_name: str,
) -> tuple[User, str]:
    """Create tenant + first admin user. Returns (user, raw_api_key)."""
    # Prevent duplicate tenants/emails
    existing = await db.execute(select(User).where(User.email == email))
    if existing.scalar_one_or_none():
        raise ValueError("Email already registered")

    raw_api_key, api_key_hash = CryptoEngine.generate_api_key()

    tenant = Tenant(
        name=tenant_name,
        plan=TenantPlan.free,
        api_key_hash=api_key_hash,
    )
    db.add(tenant)
    await db.flush()  # get tenant.id

    user = User(
        tenant_id=tenant.id,
        email=email,
        hashed_password=hash_password(password),
        role=UserRole.tenant_admin,
    )
    db.add(user)
    await db.flush()

    return user, raw_api_key


async def authenticate_user(db: AsyncSession, email: str, password: str) -> User:
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(password, user.hashed_password):
        raise ValueError("Invalid credentials")
    if not user.is_active:
        raise ValueError("Account is disabled")

    user.last_login = datetime.now(timezone.utc)
    return user


async def get_user_by_id(db: AsyncSession, user_id: str) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def get_tenant_by_api_key(db: AsyncSession, raw_key: str) -> Tenant | None:
    key_hash = CryptoEngine.hash_secret(raw_key.encode())
    result = await db.execute(
        select(Tenant).where(Tenant.api_key_hash == key_hash, Tenant.is_active == True)
    )
    return result.scalar_one_or_none()
