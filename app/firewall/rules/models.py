"""Firewall rule model. Every field is validated before it can reach a backend."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.errors import ValidationFailed
from app.utils import validation as v

Action = Literal["accept", "drop", "reject"]
Direction = Literal["in", "out"]
CtState = Literal["new", "established", "related", "invalid"]
_COMMENT = re.compile(r"^[A-Za-z0-9_ .,:/@()\-]{0,100}$")
_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_RATE = re.compile(r"^[1-9]\d{0,5}/(second|minute|hour)$")


class FirewallRule(BaseModel):
    """A single filter rule. Lower ``priority`` is evaluated first."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: int | None = None
    name: str = "rule"
    enabled: bool = True
    priority: int = Field(default=1000, ge=0, le=9999)
    direction: Direction = "in"
    action: Action = "drop"
    protocol: str = "any"
    source: str | None = None
    destination: str | None = None
    sport: list[str] = []
    dport: list[str] = []
    interface: str | None = None
    states: list[CtState] = []
    rate_limit: str | None = None
    log: bool = False
    group: str | None = None
    comment: str = ""

    @field_validator("name", "group")
    @classmethod
    def _name(cls, val: str | None) -> str | None:
        if val is not None and not _NAME.fullmatch(val):
            raise ValueError("invalid name")
        return val

    @field_validator("comment")
    @classmethod
    def _comment(cls, val: str) -> str:
        if not _COMMENT.fullmatch(val):
            raise ValueError("comment contains disallowed characters")
        return val

    @field_validator("protocol")
    @classmethod
    def _proto(cls, val: str) -> str:
        return v.parse_protocol(val)

    @field_validator("source", "destination")
    @classmethod
    def _net(cls, val: str | None) -> str | None:
        return None if val is None else str(v.parse_network(val))

    @field_validator("sport", "dport")
    @classmethod
    def _ports(cls, val: list[str]) -> list[str]:
        out = []
        for item in val:
            lo, hi = v.parse_port_range(str(item))
            out.append(str(lo) if lo == hi else f"{lo}-{hi}")
        return out

    @field_validator("interface")
    @classmethod
    def _iface(cls, val: str | None) -> str | None:
        return None if val is None else v.parse_interface(val)

    @field_validator("rate_limit")
    @classmethod
    def _rate(cls, val: str | None) -> str | None:
        if val is not None and not _RATE.fullmatch(val):
            raise ValueError("rate_limit must look like 10/second")
        return val

    @model_validator(mode="after")
    def _cross(self) -> FirewallRule:
        try:
            v.check_protocol_ports(self.protocol, bool(self.sport or self.dport))
        except ValidationFailed as exc:
            raise ValueError(exc.detail) from exc
        nets = [n for n in (self.source, self.destination) if n]
        versions = {v.parse_network(n).version for n in nets}
        if len(versions) > 1:
            raise ValueError("source and destination must be the same IP family")
        if versions:
            ver = versions.pop()
            if self.protocol == "icmp" and ver == 6:
                raise ValueError("use icmpv6 with IPv6 addresses")
            if self.protocol == "icmpv6" and ver == 4:
                raise ValueError("use icmp with IPv4 addresses")
        return self

    @property
    def family(self) -> Literal[4, 6, 0]:
        """4 or 6 if the rule is family-specific, 0 for both."""
        for n in (self.source, self.destination):
            if n:
                return v.parse_network(n).version  # type: ignore[return-value]
        return {"icmp": 4, "icmpv6": 6}.get(self.protocol, 0)  # type: ignore[return-value]

    def port_intervals(self, which: Literal["sport", "dport"]) -> list[tuple[int, int]]:
        return [v.parse_port_range(p) for p in getattr(self, which)]
