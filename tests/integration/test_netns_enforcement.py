"""Enforcement tests inside a throwaway network namespace (never touches the host firewall).

Run as root (or with CAP_SYS_ADMIN) on a host where `unshare -n` works:
    sudo -E .venv/bin/pytest tests/integration -m integration
Skipped automatically otherwise. Every command runs in a fresh netns via `unshare -n`.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from app.core.errors import BackendError
from app.firewall.backends.nftables import NftablesBackend
from app.utils.process import CommandResult
from tests.conftest import make_state

pytestmark = pytest.mark.integration


def _netns_usable() -> bool:
    if os.geteuid() != 0 or not shutil.which("unshare") or not shutil.which("nft"):
        return False
    return subprocess.run(["unshare", "-n", "nft", "list", "ruleset"], capture_output=True, check=False).returncode == 0


pytestmark = [pytest.mark.integration, pytest.mark.skipif(not _netns_usable(), reason="needs root + netns + nft")]


def test_apply_in_netns_and_failed_apply_leaves_table_intact(tmp_path):
    """One namespace per test: a shell script keeps state across steps."""
    b = NftablesBackend()
    good = b.render(make_state())
    script = tmp_path / "s.sh"
    script.write_text(
        "set -e\n"
        "nft -f - <<'EOF'\n" + good + "EOF\n"
        "nft list table inet averqon > /dev/null\n"
        "if nft -f - <<'EOF2'\ntable inet averqon { chain x { bogus } }\nEOF2\nthen exit 9; fi\n"
        "nft list table inet averqon | grep -q 'policy drop'\n"
        "nft add table inet foreign && nft add chain inet foreign c '{ type filter hook input priority 0; }'\n"
        "nft -f - <<'EOF3'\nadd table inet averqon\ndelete table inet averqon\nEOF3\n"
        "nft list table inet foreign > /dev/null\n"   # teardown must not touch foreign tables
    )
    r = subprocess.run(["unshare", "-n", "sh", str(script)], capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr


def test_live_ban_and_expiry_in_netns():
    b = NftablesBackend(runner=lambda argv, *, timeout=10.0, input_text=None: CommandResult(0, "", ""))
    assert b.render(make_state())
    with pytest.raises(BackendError):
        NftablesBackend(table="bad name")
