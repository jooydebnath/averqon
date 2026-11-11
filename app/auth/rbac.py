"""Role-based access control: explicit role -> permission map; unknown roles get nothing."""

from __future__ import annotations

ROLES = ("viewer", "auditor", "operator", "admin")

_VIEW = {"status:read", "rules:read", "events:read", "bans:read", "health:read", "network:read",
         "analytics:read", "whitelist:read", "metrics:read"}
PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset(_VIEW),
    "auditor": frozenset(_VIEW | {"audit:read"}),
    "operator": frozenset(_VIEW | {"rules:write", "bans:write", "whitelist:write", "firewall:apply"}),
    "admin": frozenset(_VIEW | {"audit:read", "rules:write", "bans:write", "whitelist:write", "firewall:apply",
                                "users:manage", "settings:read", "settings:write"}),
}


def has_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, frozenset())
