"""IDS: stores events (audit trail), classifies, applies false-positive controls, hands bans to IPS."""

from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import IdsSettings
from app.database.base import session_scope
from app.database.models import IdsEventRow
from app.detection.events import SEVERITY_ORDER, SecurityEvent
from app.ips.service import IPSService

log = logging.getLogger(__name__)
Listener = Callable[[SecurityEvent, str], None]


class IDSEngine:
    def __init__(self, sessions: sessionmaker[Session], ips: IPSService, settings: IdsSettings, *,
                 listeners: list[Listener] | None = None, clock: Callable[[], float] = time.time,
                 low_event_interval: float = 5.0) -> None:
        self.sessions, self.ips, self.cfg = sessions, ips, settings
        self.listeners = listeners or []
        self.clock, self.low_interval = clock, low_event_interval
        self._ignore = [ipaddress.ip_network(n) for n in settings.ignore_networks]
        self._last_low: dict[tuple[str, str], float] = {}

    def ignored(self, ip: str) -> bool:
        a = ipaddress.ip_address(ip)
        return any(a.version == n.version and a in n for n in self._ignore)

    @staticmethod
    def classify(event: SecurityEvent) -> str:
        """Escalate severity for scans / repeated offenders; never downgrade."""
        sev = event.severity
        if event.kind == "port_scan" and SEVERITY_ORDER[sev] < SEVERITY_ORDER["high"]:
            sev = "high"
        return sev

    def handle(self, event: SecurityEvent) -> str:
        """Process one event; returns the action taken."""
        if self.ignored(event.source_ip):
            return "ignored"
        event.severity = self.classify(event)  # type: ignore[assignment]
        action = "none"
        if event.ban_recommended:
            if SEVERITY_ORDER[event.severity] < SEVERITY_ORDER[self.cfg.autoban_min_severity]:
                action = "below_threshold"
            else:
                action = self.ips.handle(event)
        elif event.severity == "low":
            key = (event.source_ip, event.kind)
            now = self.clock()
            if now - self._last_low.get(key, 0) < self.low_interval:
                return "sampled_out"  # DB flood protection: one low event per ip/kind per interval
            self._last_low[key] = now
            if len(self._last_low) > 50_000:
                self._last_low.clear()
        with session_scope(self.sessions) as s:
            s.add(IdsEventRow(ts=event.ts, kind=event.kind, severity=event.severity, source_ip=event.source_ip,
                              jail=event.jail, message=event.message[:300], details=event.details, action=action))
        for fn in self.listeners:
            try:
                fn(event, action)
            except Exception:
                log.exception("event listener failed")
        return action

    # ---- queries (used by API / CLI)
    def query(self, *, limit: int = 50, offset: int = 0, severity: str | None = None, kind: str | None = None,
              source_ip: str | None = None, since: datetime | None = None) -> tuple[list[IdsEventRow], int]:
        with session_scope(self.sessions) as s:
            q = select(IdsEventRow)
            for col, val in ((IdsEventRow.severity, severity), (IdsEventRow.kind, kind), (IdsEventRow.source_ip, source_ip)):
                if val:
                    q = q.where(col == val)
            if since:
                q = q.where(IdsEventRow.ts >= since)
            total = s.scalar(select(func.count()).select_from(q.subquery())) or 0
            rows = list(s.scalars(q.order_by(IdsEventRow.id.desc()).limit(limit).offset(offset)))
            return rows, total

    def stats(self, hours: int = 24) -> dict:
        since = datetime.now(UTC) - timedelta(hours=hours)
        with session_scope(self.sessions) as s:
            by_sev = dict(s.execute(select(IdsEventRow.severity, func.count()).where(IdsEventRow.ts >= since)
                                    .group_by(IdsEventRow.severity)).all())
            by_kind = dict(s.execute(select(IdsEventRow.kind, func.count()).where(IdsEventRow.ts >= since)
                                     .group_by(IdsEventRow.kind)).all())
            top = s.execute(select(IdsEventRow.source_ip, func.count().label("n")).where(IdsEventRow.ts >= since)
                            .group_by(IdsEventRow.source_ip).order_by(func.count().desc()).limit(10)).all()
        return {"hours": hours, "by_severity": by_sev, "by_kind": by_kind, "top_sources": [{"ip": i, "count": n} for i, n in top]}

    def prune(self, keep_days: int = 90) -> int:
        from sqlalchemy import delete
        with session_scope(self.sessions) as s:
            return s.execute(delete(IdsEventRow).where(IdsEventRow.ts < datetime.now(UTC) - timedelta(days=keep_days))).rowcount or 0
