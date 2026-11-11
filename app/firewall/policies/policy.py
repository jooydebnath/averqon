"""Policy and desired-state objects handed to backends."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.errors import ValidationFailed
from app.firewall.rules.models import FirewallRule
from app.utils import validation as v


class Policy(BaseModel):
    """Default policies plus protected management access."""

    model_config = ConfigDict(extra="forbid")
    input: Literal["accept", "drop"] = "drop"
    output: Literal["accept", "drop"] = "accept"
    forward: Literal["accept", "drop"] = "drop"
    management_ports: list[int] = [22]
    icmp_rate_limit: str | None = "10/second"
    allow_ping: bool = True

    @field_validator("management_ports")
    @classmethod
    def _mp(cls, ports: list[int]) -> list[int]:
        return [v.parse_port(p) for p in ports]


_RATE = re.compile(r"^[1-9]\d{0,5}/(second|minute)$")
_LISTNAME = re.compile(r"^[a-z][a-z0-9_]{0,15}$")


class Protection(BaseModel):
    """Kernel-level, per-source-IP protections. These reduce, not eliminate, flood impact."""

    model_config = ConfigDict(extra="forbid")
    syn_rate: str | None = None  # e.g. "200/second": per-source new-SYN rate above which SYNs drop
    syn_burst: int = Field(default=400, ge=1, le=1_000_000)
    conn_limit_per_ip: int | None = Field(default=None, ge=1, le=1_000_000)  # concurrent tracked conns
    new_conn_rate_per_ip: str | None = None  # e.g. "50/second"
    log_drops: bool = False  # rate-limited log of policy-dropped packets (feeds port-scan detection)
    blocklists: dict[str, list[str]] = Field(default_factory=dict)  # geo / threat-intel feeds

    @field_validator("syn_rate", "new_conn_rate_per_ip")
    @classmethod
    def _r(cls, val: str | None) -> str | None:
        if val is not None and not _RATE.fullmatch(val):
            raise ValueError("rate must look like 100/second")
        return val

    @field_validator("blocklists")
    @classmethod
    def _bl(cls, lists: dict[str, list[str]]) -> dict[str, list[str]]:
        out = {}
        for name, nets in lists.items():
            if not _LISTNAME.fullmatch(name):
                raise ValueError("invalid blocklist name")
            out[name] = [str(v.parse_network(n)) for n in nets]
        return out


class Ban(BaseModel):
    """A banned network; ``expires_at`` of None means permanent."""

    network: str
    expires_at: datetime | None = None

    @field_validator("network")
    @classmethod
    def _n(cls, val: str) -> str:
        return str(v.parse_network(val))


class FirewallState(BaseModel):
    """Complete desired state. Backends render this atomically."""

    policy: Policy = Policy()
    rules: list[FirewallRule] = Field(default_factory=list)
    whitelist: list[str] = Field(default_factory=list)
    bans: list[Ban] = Field(default_factory=list)
    protection: Protection = Protection()

    @field_validator("whitelist")
    @classmethod
    def _wl(cls, items: list[str]) -> list[str]:
        return [str(v.parse_network(i)) for i in items]

    def validate_consistency(self) -> None:
        """Reject states that could lock the admin out or ban protected addresses."""
        for ban in self.bans:
            bn = ipaddress.ip_network(ban.network)
            if bn.prefixlen == 0:
                raise ValidationFailed("refusing to ban the whole address space")
            for w in self.whitelist:
                wn = ipaddress.ip_network(w)
                if wn.version == bn.version and (wn.overlaps(bn)):
                    raise ValidationFailed(f"ban {ban.network} overlaps whitelist entry {w}")
        for name, nets in self.protection.blocklists.items():
            for n in nets:
                bn = ipaddress.ip_network(n)
                for w in self.whitelist:
                    wn = ipaddress.ip_network(w)
                    if wn.version == bn.version and wn.overlaps(bn):
                        raise ValidationFailed(f"blocklist {name} entry {n} overlaps whitelist {w}")
        if self.policy.input == "drop" and not self.policy.management_ports:
            raise ValidationFailed("input policy is drop but no management ports are protected")
