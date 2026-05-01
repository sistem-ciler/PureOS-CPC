"""
OTC Secure Communication Platform — FastAPI application entry point.

Architecture overview:
  - /auth/*      → registration, login, token refresh, password management
  - /sessions/*  → OTC session lifecycle + zero-knowledge message relay
  - /tenants/*   → tenant self-management and API key rotation
  - /admin/*     → platform-wide management (platform_admin role only)

Security design:
  - AES-256-GCM authenticated encryption (client-side; server stores ciphertext only)
  - HKDF-SHA256 key derivation from one-time codes
  - OTC stored as SHA-256 hash only; burned on first redemption
  - JWT Bearer tokens (access + refresh); bcrypt password hashing
  - Full audit log on every mutating action
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from backend.config import get_settings
from backend.database import init_db, AsyncSessionLocal
from backend.models.user import User, UserRole
from backend.models.tenant import Tenant, TenantPlan
from backend.services.auth_service import hash_password
from backend.services.crypto import CryptoEngine
from backend.routers import auth, sessions, tenants, admin

settings = get_settings()
logging.basicConfig(level=logging.DEBUG if settings.DEBUG else logging.INFO)
logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address, default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE}/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await _seed_platform_admin()
    logger.info("OTC Secure Comm started")
    yield
    logger.info("OTC Secure Comm shutting down")


async def _seed_platform_admin():
    """Create the platform admin account on first run if it doesn't exist."""
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.email == settings.ADMIN_EMAIL))
        if result.scalar_one_or_none():
            return

        _, api_key_hash = CryptoEngine.generate_api_key()
        tenant = Tenant(
            name="__platform__",
            plan=TenantPlan.enterprise,
            api_key_hash=api_key_hash,
            max_sessions_per_day=10000,
        )
        db.add(tenant)
        await db.flush()

        user = User(
            tenant_id=tenant.id,
            email=settings.ADMIN_EMAIL,
            hashed_password=hash_password(settings.ADMIN_PASSWORD),
            role=UserRole.platform_admin,
        )
        db.add(user)
        await db.commit()
        logger.info("Platform admin account created: %s", settings.ADMIN_EMAIL)


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Enterprise-grade OTC (One-Time Code) secure communication platform. "
        "End-to-end AES-256-GCM encryption; the server is a zero-knowledge relay."
    ),
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(sessions.router)
app.include_router(tenants.router)
app.include_router(admin.router)


@app.get("/health", tags=["health"])
async def health():
    return {"status": "ok", "version": settings.APP_VERSION}
