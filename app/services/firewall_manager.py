"""Orchestrates rules, whitelist and bans: DB is the source of truth, firewall is derived.

Every mutation runs in one DB transaction that commits only if the firewall change
succeeded, so DB and kernel state cannot diverge.
PRIVILEGED: calls into the backend via safe_apply / live ban operations.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.audit.service import record_audit
from app.core.config import FirewallSettings
from app.core.errors import AverqonError, ValidationFailed
from app.database.base import session_scope
from app.database.models import BanRow, FirewallRuleRow, WhitelistRow
from app.firewall.backends.base import FirewallBackend
from app.firewall.policies.policy import Ban, FirewallState, Policy, Protection
from app.firewall.rules.models import FirewallRule
from app.services.blocklists import BlocklistStore
from app.services.safe_apply import ApplyResult, BackupStore, safe_apply
from app.utils import validation as v

log = logging.getLogger(__name__)
_RULE_FIELDS = tuple(FirewallRule.model_fields)


class NotFound(AverqonError):
    code = "not_found"
    public_message = "Not found"


def _utc(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=UTC)


class FirewallManager:
    def __init__(self, backend: FirewallBackend, sessions: sessionmaker[Session], store: BackupStore,
                 settings: FirewallSettings, connectivity_check: Callable[[], bool] | None = None) -> None:
        self.backend, self.sessions, self.store = backend, sessions, store
        self.settings, self.connectivity_check = settings, connectivity_check
        self.blocklists = BlocklistStore(settings.blocklist_dir)

    # ------------------------------------------------------------------ state
    def _policy(self) -> Policy:
        s = self.settings
        return Policy(input=s.default_input, output=s.default_output, forward=s.default_forward,
                      management_ports=s.management_ports)

    def build_state(self, session: Session) -> FirewallState:
        rows = session.scalars(select(FirewallRuleRow).order_by(FirewallRuleRow.priority, FirewallRuleRow.id))
        rules = [FirewallRule(**{k: getattr(r, k) for k in _RULE_FIELDS}) for r in rows]
        wl = sorted({*self.settings.admin_ips, *session.scalars(select(WhitelistRow.network))})
        now = datetime.now(UTC)
        bans = [Ban(network=b.network, expires_at=_utc(b.expires_at)) for b in session.scalars(
            select(BanRow).where(BanRow.active.is_(True)))
            if b.expires_at is None or _utc(b.expires_at) > now]
        cfg = self.settings
        prot = Protection(syn_rate=cfg.syn_rate, syn_burst=cfg.syn_burst, conn_limit_per_ip=cfg.conn_limit_per_ip,
                          new_conn_rate_per_ip=cfg.new_conn_rate_per_ip, log_drops=cfg.log_drops,
                          blocklists=self._load_blocklists(wl))
        return FirewallState(policy=self._policy(), rules=rules, whitelist=wl, bans=bans, protection=prot)

    def _load_blocklists(self, whitelist: list[str]) -> dict[str, list[str]]:
        """Blocklist entries overlapping the whitelist are dropped so a feed can never lock out an admin."""
        wl = [ipaddress.ip_network(w) for w in whitelist]
        out = {}
        for name, nets in self.blocklists.load_all().items():
            out[name] = [n for n in nets if not any(
                w.version == (b := ipaddress.ip_network(n)).version and w.overlaps(b) for w in wl)]
        return out

    def refresh_blocklists(self, *, actor: str = "system") -> dict[str, int]:
        """Fetch threat feeds + country lists, then re-apply. Failed feeds keep their previous list."""
        counts: dict[str, int] = {}
        for name, url in self.settings.threat_feeds.items():
            try:
                counts[name] = self.blocklists.update_feed(name, url)
            except (AverqonError, OSError, ValueError) as exc:
                log.warning("feed %s failed: %s", name, exc)
        if self.settings.geo_block_countries:
            counts["geo"] = self.blocklists.load_countries(self.settings.geo_zone_dir, self.settings.geo_block_countries)
        self.apply(actor=actor)
        return counts

    def _apply(self, session: Session, *, dry_run: bool = False, allow_conflicts: bool = False) -> ApplyResult:
        session.flush()
        return safe_apply(self.backend, self.build_state(session), self.store, dry_run=dry_run,
                          allow_conflicts=allow_conflicts, connectivity_check=self.connectivity_check)

    def apply(self, *, dry_run: bool = False, actor: str = "system", allow_conflicts: bool = False) -> ApplyResult:
        with session_scope(self.sessions) as s:
            res = self._apply(s, dry_run=dry_run, allow_conflicts=allow_conflicts)
            if not dry_run:
                record_audit(s, actor=actor, action="firewall.apply")
            return res

    # ------------------------------------------------------------------ rules
    def list_rules(self) -> list[FirewallRule]:
        with session_scope(self.sessions) as s:
            return self.build_state(s).rules

    def add_rule(self, rule: FirewallRule, *, actor: str, dry_run: bool = False,
                 allow_conflicts: bool = False) -> FirewallRule:
        with session_scope(self.sessions) as s:
            row = FirewallRuleRow(**rule.model_dump(exclude={"id"}))
            s.add(row)
            self._apply(s, dry_run=dry_run, allow_conflicts=allow_conflicts)
            if dry_run:
                s.rollback()
                return rule
            record_audit(s, actor=actor, action="rule.add", target=rule.name)
            s.flush()
            return rule.model_copy(update={"id": row.id})

    def update_rule(self, rule_id: int, rule: FirewallRule, *, actor: str, allow_conflicts: bool = False) -> FirewallRule:
        with session_scope(self.sessions) as s:
            row = s.get(FirewallRuleRow, rule_id)
            if row is None:
                raise NotFound(f"rule {rule_id}")
            for k, val in rule.model_dump(exclude={"id"}).items():
                setattr(row, k, val)
            self._apply(s, allow_conflicts=allow_conflicts)
            record_audit(s, actor=actor, action="rule.update", target=str(rule_id))
            return rule.model_copy(update={"id": rule_id})

    def delete_rule(self, rule_id: int, *, actor: str) -> None:
        with session_scope(self.sessions) as s:
            row = s.get(FirewallRuleRow, rule_id)
            if row is None:
                raise NotFound(f"rule {rule_id}")
            s.delete(row)
            self._apply(s, allow_conflicts=True)  # removing a rule must never be blocked
            record_audit(s, actor=actor, action="rule.delete", target=str(rule_id))

    # -------------------------------------------------------------- whitelist
    def whitelist_add(self, network: str, *, actor: str, comment: str = "") -> None:
        net = str(v.parse_network(network))
        with session_scope(self.sessions) as s:
            if s.scalar(select(WhitelistRow).where(WhitelistRow.network == net)) is None:
                s.add(WhitelistRow(network=net, comment=comment[:100]))
                # Whitelisting wins: end overlapping active bans so state stays consistent.
                for b in s.scalars(select(BanRow).where(BanRow.active.is_(True))):
                    bn = ipaddress.ip_network(b.network)
                    wn = ipaddress.ip_network(net)
                    if bn.version == wn.version and bn.overlaps(wn):
                        b.active, b.ended_at, b.ended_by = False, datetime.now(UTC), f"whitelist:{actor}"
                self._apply(s)
                record_audit(s, actor=actor, action="whitelist.add", target=net)

    def whitelist_remove(self, network: str, *, actor: str) -> None:
        net = str(v.parse_network(network))
        with session_scope(self.sessions) as s:
            row = s.scalar(select(WhitelistRow).where(WhitelistRow.network == net))
            if row is None:
                raise NotFound(net)
            s.delete(row)
            self._apply(s)
            record_audit(s, actor=actor, action="whitelist.remove", target=net)

    def is_whitelisted(self, ip: str) -> bool:
        addr = ipaddress.ip_address(v.normalize_ip(ip))
        with session_scope(self.sessions) as s:
            nets = {*self.settings.admin_ips, *s.scalars(select(WhitelistRow.network))}
        return any(addr.version == (n := ipaddress.ip_network(x)).version and addr in n for x in nets)

    def active_ban_exists(self, ip: str) -> bool:
        addr = ipaddress.ip_address(v.normalize_ip(ip))
        now = datetime.now(UTC)
        for b in self.list_bans():
            n = ipaddress.ip_network(b.network)
            if n.version == addr.version and addr in n and (b.expires_at is None or _utc(b.expires_at) > now):
                return True
        return False

    def offence_count(self, ip: str, since: datetime) -> int:
        net = str(v.parse_network(ip))
        with session_scope(self.sessions) as s:
            return len(list(s.scalars(select(BanRow.id).where(BanRow.network == net, BanRow.created_at >= since))))

    # -------------------------------------------------------------------- bans
    def ban(self, network: str, *, actor: str, ttl_seconds: int | None = None, reason: str = "",
            source: str = "manual") -> BanRow:
        net = v.parse_network(network)
        if ttl_seconds is not None and not 1 <= ttl_seconds <= 10 * 365 * 86400:
            raise ValidationFailed("ttl out of range")
        with session_scope(self.sessions) as s:
            expires = datetime.now(UTC) + timedelta(seconds=ttl_seconds) if ttl_seconds else None
            # Validates: no whole-space ban, no whitelist overlap (incl. admin_ips).
            state = self.build_state(s)
            state.bans.append(Ban(network=str(net), expires_at=expires))
            state.validate_consistency()
            row = BanRow(network=str(net), reason=reason[:200], source=source[:32], actor=actor, expires_at=expires)
            s.add(row)
            self.backend.ban(str(net), ttl_seconds)
            record_audit(s, actor=actor, action="ip.ban", target=str(net), details={"ttl": ttl_seconds, "reason": reason[:200]})
            s.flush()
            return row

    def unban(self, network: str, *, actor: str) -> int:
        net = str(v.parse_network(network))
        with session_scope(self.sessions) as s:
            rows = list(s.scalars(select(BanRow).where(BanRow.network == net, BanRow.active.is_(True))))
            if not rows:
                raise NotFound(net)
            for b in rows:
                b.active, b.ended_at, b.ended_by = False, datetime.now(UTC), actor
            self.backend.unban(net)
            record_audit(s, actor=actor, action="ip.unban", target=net)
            return len(rows)

    def expire_bans(self) -> int:
        """Mark elapsed bans inactive (kernel timeouts already removed them from nft)."""
        now, n = datetime.now(UTC), 0
        with session_scope(self.sessions) as s:
            for b in s.scalars(select(BanRow).where(BanRow.active.is_(True), BanRow.expires_at.is_not(None))):
                if _utc(b.expires_at) <= now:  # type: ignore[operator]
                    b.active, b.ended_at, b.ended_by = False, now, "expired"
                    self.backend.unban(b.network)  # no-op for nft (already timed out), needed for iptables
                    n += 1
        return n

    def list_bans(self, *, active_only: bool = True) -> list[BanRow]:
        with session_scope(self.sessions) as s:
            q = select(BanRow).order_by(BanRow.id.desc())
            if active_only:
                q = q.where(BanRow.active.is_(True))
            return list(s.scalars(q))

    # ------------------------------------------------------------------ health
    def status(self) -> dict:
        snap = self.backend.export()
        return {"backend": self.backend.name, "installed": snap is not None,
                "counters": self.backend.counters() if snap else {}, "dry_run_default": self.settings.dry_run}

    def list_whitelist(self) -> list[dict]:
        with session_scope(self.sessions) as s:
            rows = [{"network": r.network, "comment": r.comment, "source": "database", "created_at": r.created_at}
                    for r in s.scalars(select(WhitelistRow).order_by(WhitelistRow.id))]
        return [{"network": n, "comment": "from config (admin_ips)", "source": "config", "created_at": None}
                for n in self.settings.admin_ips] + rows
