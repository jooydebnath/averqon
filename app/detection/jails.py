"""Jails: filter + thresholds. Produces ban-recommended events when maxretry is hit in findtime."""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.detection.events import SecurityEvent, Severity
from app.detection.filters import FILTERS, match_line
from app.detection.window import SlidingWindow
from app.utils import validation as v

_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


class JailConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    filter: str
    enabled: bool = True
    logpaths: list[str] = []  # files to tail
    journal_units: list[str] = []  # alternative: systemd journal units
    maxretry: int = Field(default=5, ge=1, le=10_000)
    findtime: int = Field(default=600, ge=1, le=86_400)
    bantime: int = Field(default=3600, description="seconds; -1 = permanent")
    ignoreip: list[str] = []
    severity: Severity = "medium"

    @field_validator("name")
    @classmethod
    def _n(cls, val: str) -> str:
        if not _NAME.fullmatch(val):
            raise ValueError("invalid jail name")
        return val

    @field_validator("filter")
    @classmethod
    def _f(cls, val: str) -> str:
        if val not in FILTERS:
            raise ValueError(f"unknown filter {val!r}")
        return val

    @field_validator("bantime")
    @classmethod
    def _b(cls, val: int) -> int:
        if val != -1 and not 1 <= val <= 10 * 365 * 86400:
            raise ValueError("bantime must be -1 or a positive number of seconds")
        return val

    @field_validator("logpaths")
    @classmethod
    def _p(cls, val: list[str]) -> list[str]:
        for p in val:
            if not p.startswith("/") or ".." in p.split("/") or "\x00" in p:
                raise ValueError("logpath must be an absolute path without '..'")
        return val

    @field_validator("journal_units")
    @classmethod
    def _u(cls, val: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", u) for u in val):
            raise ValueError("invalid journal unit")
        return val

    @field_validator("ignoreip")
    @classmethod
    def _i(cls, val: list[str]) -> list[str]:
        return [str(v.parse_network(x)) for x in val]

    @model_validator(mode="after")
    def _src(self) -> JailConfig:
        if self.enabled and not (self.logpaths or self.journal_units):
            raise ValueError("an enabled jail needs logpaths or journal_units")
        return self


def default_jails(distro_like: list[str] | None = None, distro_id: str = "") -> list[JailConfig]:
    """Sensible defaults; auth log path differs between Debian-family and RHEL-family."""
    rhel = bool({"rhel", "fedora", "centos"} & {*(distro_like or []), distro_id})
    auth = "/var/log/secure" if rhel else "/var/log/auth.log"
    return [
        JailConfig(name="sshd", filter="sshd", logpaths=[auth], maxretry=5, findtime=600, bantime=3600, severity="high"),
        JailConfig(name="nginx-auth", filter="nginx-auth", logpaths=["/var/log/nginx/access.log", "/var/log/nginx/error.log"],
                   maxretry=10, findtime=600, bantime=1800, enabled=False),
        JailConfig(name="apache-auth", filter="apache-auth",
                   logpaths=["/var/log/apache2/access.log" if not rhel else "/var/log/httpd/access_log"],
                   maxretry=10, findtime=600, bantime=1800, enabled=False),
    ]


class JailEngine:
    """Feeds lines through jails; emits events (every failure) and ban recommendations."""

    def __init__(self, jails: list[JailConfig], *, clock: Callable[[], float] = time.time) -> None:
        self.jails = {j.name: j for j in jails if j.enabled}
        self.clock = clock
        self._win = {n: SlidingWindow(j.findtime) for n, j in self.jails.items()}
        self._ignore = {n: [ipaddress.ip_network(x) for x in j.ignoreip] for n, j in self.jails.items()}
        self.counters: dict[str, int] = {n: 0 for n in self.jails}

    def failures(self, jail: str, ip: str) -> int:
        return len(self._win[jail].items(ip, self.clock()))

    def process_line(self, jail: str, line: str) -> list[SecurityEvent]:
        cfg = self.jails.get(jail)
        if cfg is None:
            return []
        hit = match_line(cfg.filter, line)
        if hit is None:
            return []
        kind, ip = hit
        addr = ipaddress.ip_address(ip)
        if any(addr.version == n.version and addr in n for n in self._ignore[jail]):
            return []
        now = self.clock()
        count = self._win[jail].add(ip, now)
        self.counters[jail] += 1
        events = [SecurityEvent(kind=kind, source_ip=ip, severity="low", jail=jail,
                                message=f"{jail}: failure {count}/{cfg.maxretry}", details={"count": count})]
        if count >= cfg.maxretry:
            self._win[jail].reset(ip)
            events.append(SecurityEvent(
                kind="jail_threshold", source_ip=ip, severity=cfg.severity, jail=jail, ban_recommended=True,
                message=f"{jail}: {cfg.maxretry} failures within {cfg.findtime}s",
                details={"bantime": cfg.bantime, "maxretry": cfg.maxretry, "findtime": cfg.findtime}))
        return events

    def housekeeping(self) -> None:
        now = self.clock()
        for w in self._win.values():
            w.purge(now)


Mode = Literal["file", "journal"]
