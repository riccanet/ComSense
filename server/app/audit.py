from __future__ import annotations

from sqlalchemy.orm import Session

from .models import AuditLog


def audit(
    db: Session, actor: str, action: str, target: str = "", detail: str = "", ip: str = ""
) -> None:
    """Record an audit event. The caller commits."""
    db.add(AuditLog(actor=actor, action=action, target=target, detail=detail[:4000], ip=ip))
