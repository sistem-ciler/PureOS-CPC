from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from backend.config import get_settings
from backend.models.otc_session import OTCSession, SessionStatus, EncryptedMessage
from backend.models.tenant import Tenant
from backend.services.crypto import CryptoEngine, KDF_INFO

settings = get_settings()


async def create_session(
    db: AsyncSession,
    tenant: Tenant,
    creator_id: str,
    label: str | None,
    ttl_seconds: int | None,
    metadata: dict,
) -> tuple[OTCSession, str]:
    """
    Create an OTC session.
    Returns (session, raw_otc). raw_otc is returned ONCE and never stored.
    """
    ttl = min(
        ttl_seconds or tenant.session_ttl_seconds,
        settings.OTC_MAX_TTL,
    )

    raw_otc = CryptoEngine.generate_otc()
    otc_hash = CryptoEngine.hash_secret(raw_otc)
    salt = CryptoEngine.generate_salt()
    kdf_salt_b64 = CryptoEngine.encode_b64url(salt)

    session = OTCSession(
        tenant_id=tenant.id,
        creator_id=creator_id,
        otc_hash=otc_hash,
        kdf_salt=kdf_salt_b64,
        status=SessionStatus.pending,
        label=label,
        metadata_=metadata,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl),
    )
    db.add(session)
    await db.flush()

    return session, CryptoEngine.encode_b64url(raw_otc)


async def redeem_session(
    db: AsyncSession,
    session_id: str,
    tenant_id: str,
    raw_otc: str,
) -> OTCSession:
    """
    Party B redeems the OTC. Verifies, marks active, burns the code.
    After this call the OTC hash is overwritten — it can never be redeemed again.
    """
    result = await db.execute(
        select(OTCSession).where(
            OTCSession.id == session_id,
            OTCSession.tenant_id == tenant_id,
        )
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise ValueError("Session not found")

    now = datetime.now(timezone.utc)

    if session.status == SessionStatus.revoked:
        raise ValueError("Session has been revoked")
    if session.status == SessionStatus.expired or now > session.expires_at:
        session.status = SessionStatus.expired
        raise ValueError("Session has expired")
    if session.status == SessionStatus.active:
        raise ValueError("OTC already redeemed")

    otc_bytes = CryptoEngine.decode_b64url(raw_otc)
    if not CryptoEngine.verify_secret(otc_bytes, session.otc_hash):
        raise ValueError("Invalid OTC")

    # Burn the OTC: replace stored hash with a random sentinel
    session.otc_hash = CryptoEngine.hash_secret(CryptoEngine.generate_otc())
    session.status = SessionStatus.active
    session.redeemed_at = now
    return session


async def get_session(
    db: AsyncSession,
    session_id: str,
    tenant_id: str,
) -> OTCSession | None:
    result = await db.execute(
        select(OTCSession).where(
            OTCSession.id == session_id,
            OTCSession.tenant_id == tenant_id,
        )
    )
    return result.scalar_one_or_none()


async def revoke_session(
    db: AsyncSession,
    session_id: str,
    tenant_id: str,
    requestor_id: str,
) -> OTCSession:
    session = await get_session(db, session_id, tenant_id)
    if session is None:
        raise ValueError("Session not found")
    if session.status == SessionStatus.revoked:
        raise ValueError("Session already revoked")
    if session.creator_id != requestor_id:
        raise PermissionError("Only the session creator can revoke it")

    session.status = SessionStatus.revoked
    session.revoked_at = datetime.now(timezone.utc)
    return session


async def post_message(
    db: AsyncSession,
    session: OTCSession,
    sender_role: str,
    ciphertext_b64: str,
) -> EncryptedMessage:
    """
    Store an encrypted message blob. Server never decrypts anything here.
    """
    import base64

    # Validate it is valid base64 before storing
    try:
        ciphertext_bytes = base64.urlsafe_b64decode(
            ciphertext_b64 + "==" if len(ciphertext_b64) % 4 else ciphertext_b64
        )
    except Exception:
        try:
            ciphertext_bytes = base64.b64decode(ciphertext_b64)
        except Exception:
            raise ValueError("ciphertext_b64 is not valid base64")

    # next sequence number
    result = await db.execute(
        select(func.count(EncryptedMessage.id)).where(
            EncryptedMessage.session_id == session.id
        )
    )
    count = result.scalar_one()

    msg = EncryptedMessage(
        session_id=session.id,
        sender_role=sender_role,
        ciphertext=ciphertext_bytes,
        sequence=count + 1,
    )
    db.add(msg)
    await db.flush()
    return msg


async def get_messages(
    db: AsyncSession,
    session_id: str,
    after_sequence: int = 0,
) -> list[EncryptedMessage]:
    result = await db.execute(
        select(EncryptedMessage)
        .where(
            EncryptedMessage.session_id == session_id,
            EncryptedMessage.sequence > after_sequence,
        )
        .order_by(EncryptedMessage.sequence)
    )
    return list(result.scalars().all())


async def expire_stale_sessions(db: AsyncSession) -> int:
    """Mark sessions past their expiry as expired. Returns count updated."""
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(OTCSession).where(
            OTCSession.status == SessionStatus.pending,
            OTCSession.expires_at < now,
        )
    )
    sessions = result.scalars().all()
    for s in sessions:
        s.status = SessionStatus.expired
    return len(sessions)


async def list_sessions(
    db: AsyncSession,
    tenant_id: str,
    creator_id: str | None = None,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[OTCSession], int]:
    q = select(OTCSession).where(OTCSession.tenant_id == tenant_id)
    if creator_id:
        q = q.where(OTCSession.creator_id == creator_id)
    if status:
        q = q.where(OTCSession.status == status)

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    q = q.order_by(OTCSession.created_at.desc()).limit(limit).offset(offset)
    rows = await db.execute(q)
    return list(rows.scalars().all()), total
