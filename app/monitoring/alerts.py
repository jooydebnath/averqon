"""Resource threshold alerts with cooldown."""

from __future__ import annotations

import time
from collections.abc import Callable

from app.core.config import NotificationSettings
from app.monitoring.system import system_snapshot
from app.notifications.base import Notification
from app.notifications.dispatcher import Dispatcher


class ResourceMonitor:
    def __init__(self, dispatcher: Dispatcher, cfg: NotificationSettings, *, snapshot: Callable[[], dict] = system_snapshot,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.d, self.cfg, self.snapshot, self.clock = dispatcher, cfg, snapshot, clock
        self._last: dict[str, float] = {}

    def check(self) -> list[str]:
        snap = self.snapshot()
        checks = {"cpu": (snap["cpu_percent"], self.cfg.cpu_alert_percent),
                  "memory": (snap["memory"]["percent"], self.cfg.memory_alert_percent),
                  "disk": (snap["disk"]["percent"], self.cfg.disk_alert_percent)}
        fired = []
        now = self.clock()
        for name, (val, limit) in checks.items():
            if val >= limit and now - self._last.get(name, -1e12) >= self.cfg.alert_cooldown_seconds:
                self._last[name] = now
                fired.append(name)
                self.d.notify(Notification(f"High {name} usage", f"{name} at {val:.0f}% (threshold {limit}%)", "high",
                                           {"metric": name, "value": f"{val:.1f}"}))
        return fired
