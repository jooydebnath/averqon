"""Notification model and channel interface."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol


@dataclass
class Notification:
    title: str
    body: str
    severity: str = "medium"
    fields: dict[str, str] = field(default_factory=dict)
    ts: datetime = field(default_factory=lambda: datetime.now(UTC))

    def text(self) -> str:
        extra = "\n".join(f"{k}: {v}" for k, v in self.fields.items())
        return f"[{self.severity.upper()}] {self.title}\n{self.body}" + (f"\n{extra}" if extra else "")


class Channel(Protocol):
    name: str

    def send(self, n: Notification) -> None:
        """Deliver or raise. Must enforce its own timeouts."""
