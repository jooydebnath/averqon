"""Transactional ruleset application with backup, rollback and dead-man confirmation.

PRIVILEGED: functions here call backend.apply/restore/teardown.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.core.errors import BackendError, ValidationFailed
from app.firewall.backends.base import FirewallBackend
from app.firewall.policies.policy import FirewallState
from app.firewall.rules.conflicts import Conflict, find_conflicts

log = logging.getLogger(__name__)


class RolledBack(BackendError):
    code = "rolled_back"
    public_message = "Change was rolled back"


@dataclass
class ApplyResult:
    applied: bool
    dry_run: bool
    ruleset: str
    backup_path: Path | None
    conflicts: list[Conflict]


def tcp_probe(host: str, port: int, timeout: float = 3.0) -> bool:
    """Connectivity check: can we still open a TCP connection (e.g. the management port)?"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class BackupStore:
    """Snapshots stored 0600 in a 0700 directory."""

    def __init__(self, directory: Path, keep: int = 20) -> None:
        self.dir, self.keep = directory, keep

    def save(self, snapshot: str | None) -> Path | None:
        if snapshot is None:
            return None
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.dir, 0o700)
        path = self.dir / f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}.snapshot"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(snapshot)
        for old in sorted(self.dir.glob("*.snapshot"))[: -self.keep]:
            old.unlink()
        return path

    def latest(self) -> str | None:
        files = sorted(self.dir.glob("*.snapshot")) if self.dir.exists() else []
        return files[-1].read_text() if files else None

    def read(self, path: Path) -> str:
        if path.resolve().parent != self.dir.resolve():
            raise ValidationFailed("snapshot outside backup directory")
        return path.read_text()


def _prepare(backend: FirewallBackend, state: FirewallState, allow_conflicts: bool) -> tuple[str, list[Conflict]]:
    conflicts = find_conflicts(state.rules)
    errors = [c for c in conflicts if c.severity == "error"]
    if errors and not allow_conflicts:
        raise ValidationFailed("rule conflicts: " + "; ".join(c.message for c in errors))
    ruleset = backend.render(state)
    backend.check(ruleset)
    return ruleset, conflicts


def safe_apply(
    backend: FirewallBackend, state: FirewallState, store: BackupStore, *,
    dry_run: bool = False, allow_conflicts: bool = False,
    connectivity_check: Callable[[], bool] | None = None,
) -> ApplyResult:
    """Validate -> backup -> apply -> verify connectivity -> roll back on any failure."""
    ruleset, conflicts = _prepare(backend, state, allow_conflicts)
    if dry_run:
        return ApplyResult(False, True, ruleset, None, conflicts)
    snapshot = backend.export()
    path = store.save(snapshot)
    try:
        backend.apply(ruleset)
    except BackendError:
        _rollback(backend, snapshot)
        raise
    if connectivity_check is not None and not connectivity_check():
        _rollback(backend, snapshot)
        raise RolledBack("connectivity check failed after apply; previous ruleset restored")
    return ApplyResult(True, False, ruleset, path, conflicts)


def _rollback(backend: FirewallBackend, snapshot: str | None) -> None:
    try:
        backend.restore(snapshot)
        log.warning("firewall rolled back to previous snapshot")
    except BackendError:
        log.critical("ROLLBACK FAILED; running emergency teardown")
        backend.teardown()
        raise


async def apply_with_confirmation(
    backend: FirewallBackend, state: FirewallState, store: BackupStore, confirmed: asyncio.Event,
    *, timeout: float = 60.0, allow_conflicts: bool = False,
) -> ApplyResult:
    """Dead-man switch: apply, then roll back unless ``confirmed`` is set within ``timeout``."""
    ruleset, conflicts = _prepare(backend, state, allow_conflicts)
    snapshot = backend.export()
    path = store.save(snapshot)
    try:
        backend.apply(ruleset)
    except BackendError:
        _rollback(backend, snapshot)
        raise
    try:
        await asyncio.wait_for(confirmed.wait(), timeout)
    except TimeoutError:
        _rollback(backend, snapshot)
        raise RolledBack("change not confirmed in time; previous ruleset restored") from None
    return ApplyResult(True, False, ruleset, path, conflicts)


def emergency_disable(backend: FirewallBackend) -> None:
    """Emergency recovery: remove all Averqon-owned firewall objects (host rules untouched)."""
    backend.teardown()
    log.warning("emergency teardown completed")
