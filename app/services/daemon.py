"""Long-running detection daemon: log sources -> jails/portscan -> IDS -> IPS, plus housekeeping.

PRIVILEGED (indirectly): auto-bans call the firewall manager. In the split-privilege deployment the
manager handed to the daemon is an executor client, so the daemon itself stays unprivileged apart
from read access to log files.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from pathlib import Path

from app.core.config import IdsSettings
from app.detection.filters import parse_kernel_drop
from app.detection.jails import JailConfig, JailEngine
from app.detection.portscan import PortScanDetector
from app.detection.tailer import follow_journal, tail_file
from app.ids.engine import IDSEngine

log = logging.getLogger(__name__)


def build_jails(settings: IdsSettings, defaults: list[JailConfig]) -> list[JailConfig]:
    if settings.jails is None:
        return defaults
    return [JailConfig(**j) for j in settings.jails]


class Daemon:
    def __init__(self, ids: IDSEngine, jails: list[JailConfig], settings: IdsSettings, firewall=None,
                 *, housekeeping_interval: float = 30.0,
                 periodic: list[tuple[float, Callable[[], object]]] | None = None) -> None:
        self.ids, self.cfg, self.fw = ids, settings, firewall
        self.jails = JailEngine(jails)
        self.portscan = PortScanDetector(settings.portscan_ports, settings.portscan_window)
        self.stop = asyncio.Event()
        self.interval = housekeeping_interval
        self.lines_processed = 0
        self.periodic = [[interval, fn, time.monotonic()] for interval, fn in (periodic or [])]

    async def _dispatch(self, events) -> None:
        for ev in events:
            try:
                await asyncio.to_thread(self.ids.handle, ev)
            except Exception:
                log.exception("event handling failed")

    async def _consume(self, source, handler) -> None:
        try:
            async for line in source:
                self.lines_processed += 1
                await handler(line)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("log source crashed")

    def _jail_handler(self, jail: str):
        async def h(line: str) -> None:
            await self._dispatch(self.jails.process_line(jail, line))
        return h

    async def _kernel_handler(self, line: str) -> None:
        parsed = parse_kernel_drop(line)
        if parsed:
            ev = self.portscan.observe(parsed[0], parsed[2])
            if ev:
                await self._dispatch([ev])

    async def _housekeeping(self) -> None:
        while not self.stop.is_set():
            now = time.monotonic()
            for item in self.periodic:
                if now - item[2] >= item[0]:
                    item[2] = now
                    try:
                        await asyncio.to_thread(item[1])
                    except Exception:
                        log.exception("periodic task failed")
            try:
                self.jails.housekeeping()
                if self.fw is not None:
                    await asyncio.to_thread(self.fw.expire_bans)
            except Exception:
                log.exception("housekeeping failed")
            try:
                await asyncio.wait_for(self.stop.wait(), self.interval)
            except TimeoutError:
                pass

    def sources(self) -> list[tuple[object, object]]:
        out: list[tuple[object, object]] = []
        for name, j in self.jails.jails.items():
            h = self._jail_handler(name)
            out += [(tail_file(Path(p), stop=self.stop), h) for p in j.logpaths]
            if j.journal_units:
                out.append((follow_journal(j.journal_units, stop=self.stop), h))
        if self.cfg.portscan_enabled:
            if self.cfg.kernel_log_path:
                out.append((tail_file(Path(self.cfg.kernel_log_path), stop=self.stop), self._kernel_handler))
            else:
                out.append((follow_journal([], kernel=True, stop=self.stop), self._kernel_handler))
        return out

    async def run(self) -> None:
        tasks = [asyncio.create_task(self._consume(s, h)) for s, h in self.sources()]
        tasks.append(asyncio.create_task(self._housekeeping()))
        log.info("daemon started: %d sources", len(tasks) - 1)
        await self.stop.wait()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
