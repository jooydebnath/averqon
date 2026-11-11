"""Phase 1 models. Further tables arrive with their phases, each with a migration."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, TimestampMixin


class AuditLogEntry(TimestampMixin, Base):
    """Append-only record of privileged / administrative actions."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(256), default="")
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    source_ip: Mapped[str] = mapped_column(String(45), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class FirewallRuleRow(TimestampMixin, Base):
    """Persisted firewall rule (validated through FirewallRule before storing)."""

    __tablename__ = "firewall_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=1000, index=True)
    direction: Mapped[str] = mapped_column(String(3))
    action: Mapped[str] = mapped_column(String(6))
    protocol: Mapped[str] = mapped_column(String(8))
    source: Mapped[str | None] = mapped_column(String(49), nullable=True)
    destination: Mapped[str | None] = mapped_column(String(49), nullable=True)
    sport: Mapped[list] = mapped_column(JSON, default=list)
    dport: Mapped[list] = mapped_column(JSON, default=list)
    interface: Mapped[str | None] = mapped_column(String(15), nullable=True)
    states: Mapped[list] = mapped_column(JSON, default=list)
    rate_limit: Mapped[str | None] = mapped_column(String(16), nullable=True)
    log: Mapped[bool] = mapped_column(Boolean, default=False)
    group: Mapped[str | None] = mapped_column("rule_group", String(64), nullable=True)
    comment: Mapped[str] = mapped_column(String(100), default="")


class WhitelistRow(TimestampMixin, Base):
    __tablename__ = "whitelist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    network: Mapped[str] = mapped_column(String(49), unique=True)
    comment: Mapped[str] = mapped_column(String(100), default="")


class BanRow(TimestampMixin, Base):
    """Ban history. ``active`` rows are enforced; others are history."""

    __tablename__ = "bans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    network: Mapped[str] = mapped_column(String(49), index=True)
    reason: Mapped[str] = mapped_column(String(200), default="")
    source: Mapped[str] = mapped_column(String(32), default="manual")  # manual|ids|jail:<name>
    actor: Mapped[str] = mapped_column(String(128), default="")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_by: Mapped[str] = mapped_column(String(128), default="")


class IdsEventRow(Base):
    """Detection audit trail: every stored security event and the action taken."""

    __tablename__ = "ids_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(8), index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    jail: Mapped[str | None] = mapped_column(String(32), nullable=True)
    message: Mapped[str] = mapped_column(String(300), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    action: Mapped[str] = mapped_column(String(24), default="none")


class UserRow(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    token_version: Mapped[int] = mapped_column(Integer, default=0)  # bump to revoke all sessions


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
