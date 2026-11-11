"""Fan-out with severity filter, de-duplication and retry. Never raises into the caller."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from app.core.config import NotificationSettings
from app.detection.events import SEVERITY_ORDER, SecurityEvent
from app.notifications.base import Channel, Notification
from app.notifications.channels import EmailChannel, TelegramChannel, WebhookChannel

log = logging.getLogger(__name__)


def build_channels(cfg: NotificationSettings) -> list[Channel]:
    out: list[Channel] = []
    if cfg.telegram.enabled:
        out.append(TelegramChannel(cfg.telegram))
    if cfg.email.enabled:
        out.append(EmailChannel(cfg.email))
    if cfg.webhook.enabled:
        out.append(WebhookChannel(cfg.webhook))
    return out


class Dispatcher:
    def __init__(self, channels: list[Channel], cfg: NotificationSettings, *, clock: Callable[[], float] = time.monotonic,
                 retries: int = 2, backoff: float = 1.0, sync: bool = False) -> None:
        self.channels, self.cfg, self.clock = channels, cfg, clock
        self.retries, self.backoff, self.sync = retries, backoff, sync
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="notify")
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()
        self.sent = 0
        self.failed = 0

    def _dup(self, key: str) -> bool:
        now = self.clock()
        with self._lock:
            if len(self._seen) > 10_000:
                self._seen = {k: t for k, t in self._seen.items() if now - t < self.cfg.dedupe_seconds}
            last = self._seen.get(key)
            if last is not None and now - last < self.cfg.dedupe_seconds:
                return True
            self._seen[key] = now
            return False

    def notify(self, n: Notification, *, dedupe_key: str | None = None) -> bool:
        """Queue delivery. Returns False if filtered/deduplicated."""
        if SEVERITY_ORDER.get(n.severity, 0) < SEVERITY_ORDER[self.cfg.min_severity] or not self.channels:
            return False
        if dedupe_key and self._dup(dedupe_key):
            return False
        for ch in self.channels:
            if self.sync:
                self._deliver(ch, n)
            else:
                self._pool.submit(self._deliver, ch, n)
        return True

    def _deliver(self, ch: Channel, n: Notification) -> None:
        for attempt in range(self.retries + 1):
            try:
                ch.send(n)
                self.sent += 1
                return
            except Exception as exc:  # noqa: BLE001 - delivery problems must never crash detection
                log.warning("%s delivery failed (attempt %d): %s", ch.name, attempt + 1, type(exc).__name__)
                if attempt < self.retries:
                    time.sleep(self.backoff * (2 ** attempt))
        self.failed += 1

    def event_listener(self) -> Callable[[SecurityEvent, str], None]:
        """Adapter for IDSEngine.listeners."""
        def listener(ev: SecurityEvent, action: str) -> None:
            if ev.severity in ("low",) and action != "banned":
                return
            title = f"{ev.kind} from {ev.source_ip}" + (" (banned)" if action == "banned" else "")
            self.notify(Notification(title, ev.message, ev.severity,
                                     {"ip": ev.source_ip, "jail": ev.jail or "-", "action": action}),
                        dedupe_key=f"{ev.kind}:{ev.source_ip}:{action}")
        return listener

    def close(self) -> None:
        self._pool.shutdown(wait=True)
