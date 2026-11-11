"""Security event types shared by detection, IDS and IPS."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

Severity = Literal["low", "medium", "high", "critical"]
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class SecurityEvent:
    kind: str  # ssh_auth_failure | http_auth_failure | port_scan | jail_threshold | ...
    source_ip: str
    severity: Severity = "low"
    jail: str | None = None
    message: str = ""
    details: dict = field(default_factory=dict)
    ts: datetime = field(default_factory=lambda: datetime.now(UTC))
    ban_recommended: bool = False
