from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from backend.models.audit_log import AuditLog


async def log(
    db: AsyncSession,
    *,
    tenant_id: str,
    action: str,
    user_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    ip_address: str | None = None,
    details: dict | None = None,
) -> None:
    entry = AuditLog(
        tenant_id=tenant_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        details=details or {},
    )
    db.add(entry)
    # no flush needed — commits with the parent transaction


async def list_logs(
    db: AsyncSession,
    tenant_id: str,
    action: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[AuditLog], int]:
    q = select(AuditLog).where(AuditLog.tenant_id == tenant_id)
    if action:
        q = q.where(AuditLog.action == action)

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar_one()

    q = q.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
    rows = await db.execute(q)
    return list(rows.scalars().all()), total
