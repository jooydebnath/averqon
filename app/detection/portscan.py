"""Port-scan heuristic: many distinct destination ports from one source within a window."""

from __future__ import annotations

import time
from collections.abc import Callable

from app.detection.events import SecurityEvent
from app.detection.window import SlidingWindow


class PortScanDetector:
    """Feed ``observe(src, dport)`` from dropped-packet logs.

    A scan is flagged when ``distinct_ports`` different ports are probed within ``window``
    seconds. Limitation: only sees packets the firewall drops and logs (rate-limited), so
    slow scans below the window/threshold are intentionally not detected.
    """

    def __init__(self, distinct_ports: int = 15, window: int = 60, *, clock: Callable[[], float] = time.time) -> None:
        self.threshold, self.clock = distinct_ports, clock
        self._win = SlidingWindow(window)

    def observe(self, src: str, dport: int | None) -> SecurityEvent | None:
        if dport is None:
            return None
        now = self.clock()
        self._win.add(src, now, dport)
        ports = {p for p in self._win.items(src, now) if isinstance(p, int)}
        if len(ports) >= self.threshold:
            self._win.reset(src)
            return SecurityEvent(
                kind="port_scan", source_ip=src, severity="high", ban_recommended=True,
                message=f"{len(ports)} distinct ports probed", details={"ports": sorted(ports)[:50]})
        return None
