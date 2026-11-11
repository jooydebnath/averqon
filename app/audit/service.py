"""Audit trail writer."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.database.models import AuditLogEntry


def record_audit(
    session: Session,
    *,
    actor: str,
    action: str,
    target: str = "",
    outcome: str = "success",
    source_ip: str = "",
    details: dict[str, Any] | None = None,
) -> AuditLogEntry:
    """Add an audit entry to ``session`` (caller commits)."""
    entry = AuditLogEntry(
        actor=actor, action=action, target=target, outcome=outcome,
        source_ip=source_ip, details=details or {},
    )
    session.add(entry)
    return entry
