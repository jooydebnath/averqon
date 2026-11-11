"""Kernel hardening via /proc/sys with a strict allow-list.

PRIVILEGED: ``apply_hardening`` writes kernel parameters. Only the keys below can ever be set.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

HARDENING: dict[str, str] = {
    "net.ipv4.tcp_syncookies": "1",  # SYN-flood mitigation when the backlog overflows
    "net.ipv4.tcp_max_syn_backlog": "4096",
    "net.ipv4.conf.all.rp_filter": "1",  # reverse-path filter against spoofed sources
    "net.ipv4.conf.default.rp_filter": "1",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv6.conf.all.accept_redirects": "0",
    "net.ipv4.conf.all.log_martians": "1",
}


@dataclass(frozen=True)
class SysctlChange:
    key: str
    current: str | None
    desired: str

    @property
    def needs_change(self) -> bool:
        return self.current != self.desired


def _path(root: Path, key: str) -> Path:
    if key not in HARDENING:
        raise ValueError(f"sysctl key not allowed: {key}")
    return root / key.replace(".", "/")


def plan(root: Path = Path("/proc/sys")) -> list[SysctlChange]:
    out = []
    for key, desired in HARDENING.items():
        try:
            cur = _path(root, key).read_text().strip()
        except OSError:
            cur = None
        out.append(SysctlChange(key, cur, desired))
    return out


def apply_hardening(root: Path = Path("/proc/sys")) -> list[SysctlChange]:
    """Apply changes that are needed and possible; returns the changes made."""
    done = []
    for ch in plan(root):
        if ch.current is not None and ch.needs_change:
            _path(root, ch.key).write_text(ch.desired + "\n")
            done.append(ch)
    return done


def render_conf() -> str:
    return "# Managed by Averqon\n" + "".join(f"{k} = {v}\n" for k, v in HARDENING.items())
