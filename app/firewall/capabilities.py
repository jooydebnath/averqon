"""Detect distribution, kernel and firewall tooling. Never assume distros are alike."""

from __future__ import annotations

import platform
import re
import shutil
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

from app.core.errors import BackendError
from app.utils.process import CommandResult, run_command

Runner = Callable[[Sequence[str]], CommandResult]
_ADMIN_PATH = ("/usr/sbin", "/sbin", "/usr/bin", "/bin")


@dataclass
class Capabilities:
    distro_id: str = "unknown"
    distro_version: str = ""
    distro_like: list[str] = field(default_factory=list)
    kernel: str = ""
    kernel_tuple: tuple[int, int] = (0, 0)
    nft_path: str | None = None
    nft_version: str | None = None
    iptables_path: str | None = None
    ip6tables_path: str | None = None
    iptables_restore_path: str | None = None
    iptables_flavor: str | None = None  # "nf_tables" | "legacy"
    conntrack: bool = False
    is_root: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def nftables_usable(self) -> bool:
        return self.nft_path is not None and self.kernel_tuple >= (3, 13)

    @property
    def iptables_usable(self) -> bool:
        return bool(self.iptables_path and self.ip6tables_path and self.iptables_restore_path)

    @property
    def preferred_backend(self) -> str | None:
        if self.nftables_usable:
            return "nftables"
        return "iptables" if self.iptables_usable else None

    def to_dict(self) -> dict:
        return asdict(self) | {"preferred_backend": self.preferred_backend}


def parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _which(name: str) -> str | None:
    return shutil.which(name) or shutil.which(name, path=":".join(_ADMIN_PATH))


def detect_capabilities(
    *, os_release: Path = Path("/etc/os-release"), runner: Runner = run_command,
    kernel_release: str | None = None, which: Callable[[str], str | None] = _which,
    is_root: bool | None = None, conntrack_path: Path = Path("/proc/net/nf_conntrack"),
) -> Capabilities:
    """Probe the host. All side-effect inputs are injectable for testing."""
    import os

    caps = Capabilities()
    try:
        info = parse_os_release(os_release.read_text())
        caps.distro_id = info.get("ID", "unknown").lower()
        caps.distro_version = info.get("VERSION_ID", "")
        caps.distro_like = info.get("ID_LIKE", "").lower().split()
    except OSError:
        caps.warnings.append("cannot read os-release")
    caps.kernel = kernel_release or platform.release()
    m = re.match(r"(\d+)\.(\d+)", caps.kernel)
    caps.kernel_tuple = (int(m[1]), int(m[2])) if m else (0, 0)
    caps.is_root = (os.geteuid() == 0) if is_root is None else is_root

    caps.nft_path = which("nft")
    if caps.nft_path:
        try:
            r = runner([caps.nft_path, "--version"])
            vm = re.search(r"v?(\d+\.\d+(?:\.\d+)?)", r.stdout)
            caps.nft_version = vm[1] if r.returncode == 0 and vm else None
        except BackendError as exc:
            caps.warnings.append(f"nft --version failed: {exc.detail}")
    caps.iptables_path = which("iptables")
    caps.ip6tables_path = which("ip6tables")
    caps.iptables_restore_path = which("iptables-restore")
    if caps.iptables_path:
        try:
            out = runner([caps.iptables_path, "--version"]).stdout
            caps.iptables_flavor = "nf_tables" if "nf_tables" in out else "legacy"
        except BackendError as exc:
            caps.warnings.append(f"iptables --version failed: {exc.detail}")
    caps.conntrack = conntrack_path.exists() or caps.kernel_tuple >= (4, 18)
    if caps.preferred_backend is None:
        caps.warnings.append("no usable firewall backend found")
    if not caps.is_root:
        caps.warnings.append("not running as root: enforcement unavailable")
    return caps
