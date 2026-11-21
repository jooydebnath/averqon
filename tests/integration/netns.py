"""Throwaway network namespaces for real kernel-enforcement tests.

A :class:`Lab` is a pair of namespaces joined by a veth pair, so packets really
cross a link and hit the netfilter hooks::

    srv  10.10.0.1  <--veth-->  10.10.0.2  cli
         (firewall here)                    (+ extra source addresses)

The firewall under test is applied *inside* ``srv`` through a runner that
prefixes every command with ``ip netns exec``. Nothing outside these namespaces
is ever touched, and both namespaces are deleted when the lab exits.

Requires root (CAP_SYS_ADMIN + CAP_NET_ADMIN) plus ``ip``, ``nft`` and
``iptables``. IPv6 is configured by writing to ``/proc/sys`` directly, so no
``sysctl`` binary is needed.

Use :func:`netns_available` to skip cleanly everywhere else.
"""

from __future__ import annotations

import contextlib
import os
import select
import shutil
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Self

from app.utils.process import CommandResult, run_command

PROBE = str(Path(__file__).with_name("probe.py"))
SRV_ADDR = "10.10.0.1"
CLI_ADDR = "10.10.0.2"
SRV_ADDR6 = "fd00:10:10::1"
CLI_ADDR6 = "fd00:10:10::2"


def netns_available() -> bool:
    """True only when we are root and user+network namespaces actually work here."""
    if os.geteuid() != 0 or not all(shutil.which(b) for b in ("ip", "nft", "iptables", "unshare")):
        return False
    probe = subprocess.run(["unshare", "-n", "true"], capture_output=True, check=False)
    return probe.returncode == 0


class NetnsError(RuntimeError):
    """Raised when the host cannot build the lab (no IPv6, missing modules, ...)."""


class Lab:
    """Two namespaces joined by a veth pair; deleted on exit."""

    def __init__(self, *, ipv6: bool = False) -> None:
        tag = uuid.uuid4().hex[:8]
        self.srv = f"avq-srv-{tag}"
        self.cli = f"avq-cli-{tag}"
        self.want_ipv6 = ipv6
        self.ipv6 = False
        self._started: list[subprocess.Popen[str]] = []
        self._up = False

    # ------------------------------------------------------------- life cycle
    def __enter__(self) -> Self:
        try:
            self._build()
        except Exception:
            self.close()
            raise
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _build(self) -> None:
        self._cmd(["ip", "netns", "add", self.srv])
        self._cmd(["ip", "netns", "add", self.cli])
        self._up = True
        self._cmd(["ip", "-n", self.srv, "link", "add", "va", "type", "veth", "peer", "name", "vb"])
        self._cmd(["ip", "-n", self.srv, "link", "set", "vb", "netns", self.cli])
        self._cmd(["ip", "-n", self.srv, "addr", "add", f"{SRV_ADDR}/24", "dev", "va"])
        self._cmd(["ip", "-n", self.cli, "addr", "add", f"{CLI_ADDR}/24", "dev", "vb"])
        for ns in (self.srv, self.cli):
            self._cmd(["ip", "-n", ns, "link", "set", "lo", "up"])
        self._cmd(["ip", "-n", self.srv, "link", "set", "va", "up"])
        self._cmd(["ip", "-n", self.cli, "link", "set", "vb", "up"])
        if self.want_ipv6:
            self.ipv6 = self._enable_ipv6()

    def _enable_ipv6(self) -> bool:
        """Best effort: some kernels/containers have IPv6 disabled in new namespaces."""
        try:
            for ns, dev, addr in ((self.srv, "va", SRV_ADDR6), (self.cli, "vb", CLI_ADDR6)):
                self._sysctl(ns, f"net/ipv6/conf/{dev}/disable_ipv6", "0")
                self._sysctl(ns, f"net/ipv6/conf/{dev}/accept_dad", "0")
                self._cmd(["ip", "-n", ns, "-6", "addr", "add", f"{addr}/64", "nodad", "dev", dev])
            # A veth pair needs a moment before the addresses are usable.
            time.sleep(0.2)
            ping = self.run(self.srv, "ip", "-6", "addr", "show", "dev", "va", check=False)
            return SRV_ADDR6 in ping.stdout
        except (AssertionError, OSError):
            return False

    def close(self) -> None:
        for proc in list(self._started):
            self._stop(proc)
        if self._up:
            for ns in (self.cli, self.srv):
                subprocess.run(["ip", "netns", "delete", ns], capture_output=True, check=False)
            self._up = False

    # ---------------------------------------------------------------- commands
    @staticmethod
    def _cmd(argv: list[str], *, timeout: float = 20.0) -> subprocess.CompletedProcess[str]:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode != 0:
            raise NetnsError(f"{' '.join(argv)} failed: {proc.stderr.strip()}")
        return proc

    def run(self, ns: str, *argv: str, check: bool = True, timeout: float = 20.0
            ) -> subprocess.CompletedProcess[str]:
        """Run ``argv`` inside namespace ``ns``."""
        proc = subprocess.run(["ip", "netns", "exec", ns, *argv], capture_output=True,
                              text=True, timeout=timeout, check=False)
        if check and proc.returncode != 0:
            raise AssertionError(f"{' '.join(argv)} failed in {ns}: {proc.stderr.strip()}")
        return proc

    def _sysctl(self, ns: str, key: str, value: str) -> None:
        self.run(ns, "sh", "-c", f"echo {value} > /proc/sys/{key}")

    def runner(self, ns: str):
        """A :data:`~app.firewall.backends.base.Runner` that executes inside ``ns``."""
        def run(argv, *, timeout: float = 10.0, input_text: str | None = None) -> CommandResult:
            return run_command(["ip", "netns", "exec", ns, *argv], timeout=timeout, input_text=input_text)
        return run

    # ----------------------------------------------------------------- clients
    def add_client_ip(self, addr: str) -> None:
        """Give the client a second source address (for per-source assertions)."""
        suffix = "/128" if ":" in addr else "/32"
        nodad = ["nodad"] if ":" in addr else []
        self.run(self.cli, "ip", "addr", "add", f"{addr}{suffix}", *nodad, "dev", "vb")

    @contextlib.contextmanager
    def server(self, host: str, port: int, proto: str = "tcp", *, ns: str | None = None
               ) -> Iterator[None]:
        """Start a probe server inside ``ns`` (default: the protected namespace)."""
        ns = ns or self.srv
        proc = subprocess.Popen(
            ["ip", "netns", "exec", ns, sys.executable, PROBE, "serve",
             "--host", host, "--port", str(port), "--proto", proto],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self._started.append(proc)
        try:
            if not self._wait_ready(proc):
                detail = proc.stderr.read().strip() if proc.poll() is not None else "timed out"
                raise AssertionError(f"probe server on {host}:{port}/{proto} did not start: {detail}")
            yield
        finally:
            self._started.remove(proc)
            self._stop(proc)

    @staticmethod
    def _wait_ready(proc: subprocess.Popen[str], timeout: float = 10.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return False
            readable, _, _ = select.select([proc.stdout], [], [], 0.1)
            if readable:
                line = proc.stdout.readline() if proc.stdout else ""
                if line.strip() == "READY":
                    return True
        return False

    @staticmethod
    def _stop(proc: subprocess.Popen[str]) -> None:
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(5)
        if proc.poll() is None:
            proc.kill()
            proc.wait(5)
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()

    def probe(self, host: str, port: int, proto: str = "tcp", *, source: str | None = None,
              timeout: float = 1.0) -> tuple[bool, float, str]:
        """Try to reach ``host:port`` from the client namespace.

        Returns ``(reachable, seconds, stderr)``. A dropped packet costs the full
        ``timeout``; a rejected one fails immediately.
        """
        argv = ["ip", "netns", "exec", self.cli, sys.executable, PROBE, "client",
                "--host", host, "--port", str(port), "--proto", proto, "--timeout", str(timeout)]
        if source:
            argv += ["--source", source]
        started = time.monotonic()
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 20, check=False)
        return proc.returncode == 0, time.monotonic() - started, proc.stderr.strip()

    def reachable(self, host: str, port: int, **kwargs: object) -> bool:
        return self.probe(host, port, **kwargs)[0]  # type: ignore[arg-type]

    def wait_reachable(self, host: str, port: int, *, attempts: int = 6,
                       timeout: float = 0.6, **kwargs: object) -> bool:
        """Like :meth:`reachable`, but retries: the first packet after a new address
        can be lost while neighbour discovery resolves it."""
        for _ in range(attempts):
            if self.probe(host, port, timeout=timeout, **kwargs)[0]:  # type: ignore[arg-type]
                return True
            time.sleep(0.2)
        return False

    def flood(self, host: str, port: int, *, count: int = 80, proto: str = "tcp",
              source: str | None = None) -> None:
        """Send ``count`` SYNs from one source, without completing a handshake."""
        argv = [sys.executable, PROBE, "flood", "--host", host, "--port", str(port),
                "--proto", proto, "--count", str(count)]
        if source:
            argv += ["--source", source]
        self.run(self.cli, *argv)
