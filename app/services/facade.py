"""JSON-friendly facade over FirewallManager.

This is the single interface the API calls. It runs in-process (``LocalFacade``) or inside the
privileged executor (served over a unix socket) so the unprivileged API never touches the kernel.
Every public method here is exported to the executor, so keep arguments/results JSON-serialisable.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.firewall import sysctl
from app.firewall.rules.models import FirewallRule
from app.services.firewall_manager import FirewallManager


def _iso(v: Any) -> Any:
    return v.isoformat() if isinstance(v, datetime) else v


def ban_dict(b: Any) -> dict:
    return {"id": b.id, "network": b.network, "reason": b.reason, "source": b.source, "actor": b.actor,
            "created_at": _iso(b.created_at), "expires_at": _iso(b.expires_at), "active": b.active,
            "ended_at": _iso(b.ended_at), "ended_by": b.ended_by}


class LocalFacade:
    EXPORTED = ("list_rules", "add_rule", "update_rule", "delete_rule", "list_bans", "ban", "unban",
                "whitelist_list", "whitelist_add", "whitelist_remove", "apply", "status", "refresh_blocklists",
                "hardening_plan", "apply_hardening", "expire_bans", "is_whitelisted", "active_ban_exists",
                "offence_count")

    def __init__(self, manager: FirewallManager) -> None:
        self.m = manager

    def list_rules(self) -> list[dict]:
        return [r.model_dump() for r in self.m.list_rules()]

    def add_rule(self, rule: dict, actor: str, dry_run: bool = False, force: bool = False) -> dict:
        return self.m.add_rule(FirewallRule(**rule), actor=actor, dry_run=dry_run, allow_conflicts=force).model_dump()

    def update_rule(self, rule_id: int, rule: dict, actor: str, force: bool = False) -> dict:
        return self.m.update_rule(rule_id, FirewallRule(**rule), actor=actor, allow_conflicts=force).model_dump()

    def delete_rule(self, rule_id: int, actor: str) -> None:
        self.m.delete_rule(rule_id, actor=actor)

    def list_bans(self, active_only: bool = True) -> list[dict]:
        return [ban_dict(b) for b in self.m.list_bans(active_only=active_only)]

    def ban(self, network: str, actor: str, ttl_seconds: int | None = None, reason: str = "",
            source: str = "manual") -> dict:
        return ban_dict(self.m.ban(network, actor=actor, ttl_seconds=ttl_seconds, reason=reason, source=source))

    def unban(self, network: str, actor: str) -> int:
        return self.m.unban(network, actor=actor)

    def whitelist_list(self) -> list[dict]:
        return [{**w, "created_at": _iso(w["created_at"])} for w in self.m.list_whitelist()]

    def whitelist_add(self, network: str, actor: str, comment: str = "") -> None:
        self.m.whitelist_add(network, actor=actor, comment=comment)

    def whitelist_remove(self, network: str, actor: str) -> None:
        self.m.whitelist_remove(network, actor=actor)

    def apply(self, actor: str, dry_run: bool = False) -> dict:
        r = self.m.apply(dry_run=dry_run, actor=actor)
        return {"applied": r.applied, "dry_run": r.dry_run, "ruleset": r.ruleset if r.dry_run else None,
                "conflicts": [c.message for c in r.conflicts]}

    def status(self) -> dict:
        return self.m.status()

    def refresh_blocklists(self, actor: str) -> dict:
        return self.m.refresh_blocklists(actor=actor)

    def hardening_plan(self) -> list[dict]:
        return [{"key": c.key, "current": c.current, "desired": c.desired, "needs_change": c.needs_change}
                for c in sysctl.plan()]

    def apply_hardening(self) -> list[str]:
        return [c.key for c in sysctl.apply_hardening()]

    def expire_bans(self) -> int:
        return self.m.expire_bans()

    def is_whitelisted(self, ip: str) -> bool:
        return self.m.is_whitelisted(ip)

    def active_ban_exists(self, ip: str) -> bool:
        return self.m.active_ban_exists(ip)

    def offence_count(self, ip: str, since: str) -> int:
        return self.m.offence_count(ip, datetime.fromisoformat(since))
