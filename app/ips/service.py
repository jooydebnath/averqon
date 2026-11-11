"""IPS: turns ban recommendations into bans, with escalation and safety rules."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from app.core.config import IdsSettings
from app.core.errors import BackendError, ValidationFailed
from app.detection.events import SecurityEvent
from app.utils.validation import is_unbannable

log = logging.getLogger(__name__)


class IPSService:
    """Decides and applies automatic bans. Returns the action taken as a short string."""

    def __init__(self, firewall, settings: IdsSettings, own_ips: set[str] | None = None) -> None:
        """``firewall`` is a LocalFacade or ExecutorClient (keyword-only calls)."""
        self.fw, self.cfg, self.own_ips = firewall, settings, own_ips or set()

    def compute_bantime(self, ip: str, base: int) -> int | None:
        """Escalating ban: base * multiplier**prior_offences, capped; None = permanent."""
        if base == -1:
            return None
        since = datetime.now(UTC) - timedelta(seconds=self.cfg.escalation_window)
        prior = self.fw.offence_count(ip=ip, since=since.isoformat())
        if self.cfg.permanent_after and prior + 1 >= self.cfg.permanent_after:
            return None
        return min(base * (self.cfg.escalation_multiplier ** prior), self.cfg.max_bantime)

    def handle(self, event: SecurityEvent) -> str:
        if not event.ban_recommended:
            return "none"
        ip = event.source_ip
        if not self.cfg.autoban:
            return "autoban_disabled"
        if is_unbannable(ip) or ip in self.own_ips:
            return "protected_address"
        if self.fw.is_whitelisted(ip=ip):
            return "whitelisted"
        if self.fw.active_ban_exists(ip=ip):
            return "already_banned"
        base = int(event.details.get("bantime", self.cfg.portscan_bantime))
        try:
            ttl = self.compute_bantime(ip, base)
            self.fw.ban(network=ip, actor="ips", ttl_seconds=ttl, reason=event.message, source=event.jail or event.kind)
        except ValidationFailed:
            return "whitelisted"
        except BackendError:
            log.exception("auto-ban of %s failed", ip)
            return "ban_failed"
        return "banned"
