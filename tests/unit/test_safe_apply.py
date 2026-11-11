import asyncio

import pytest

from app.core.errors import BackendError, ValidationFailed
from app.firewall.backends.nftables import NftablesBackend
from app.firewall.rules.models import FirewallRule as R
from app.services.safe_apply import (
    BackupStore,
    RolledBack,
    apply_with_confirmation,
    emergency_disable,
    safe_apply,
)
from tests.conftest import make_state


@pytest.fixture
def env(fake_nft, tmp_path):
    return NftablesBackend(runner=fake_nft), fake_nft, BackupStore(tmp_path / "bk")


def test_dry_run_changes_nothing(env, sample_state):
    b, nft, store = env
    r = safe_apply(b, sample_state, store, dry_run=True)
    assert r.dry_run and not r.applied and nft.table is None
    assert not any(c[1:3] == ["-f", "-"] for c in nft.calls)


def test_apply_and_backup_of_previous(env, sample_state):
    b, nft, store = env
    safe_apply(b, make_state(), store)
    first = nft.table
    r = safe_apply(b, sample_state, store)
    assert r.applied and r.backup_path and oct(r.backup_path.stat().st_mode & 0o777) == "0o600"
    assert oct(store.dir.stat().st_mode & 0o777) == "0o700"
    assert nft.table != first and "table inet averqon {" + first in r.backup_path.read_text()


def test_connectivity_failure_rolls_back(env, sample_state):
    b, nft, store = env
    safe_apply(b, make_state(), store)
    before = nft.table
    with pytest.raises(RolledBack):
        safe_apply(b, sample_state, store, connectivity_check=lambda: False)
    assert nft.table == before


def test_first_apply_rollback_removes_table(env, sample_state):
    b, nft, store = env
    with pytest.raises(RolledBack):
        safe_apply(b, sample_state, store, connectivity_check=lambda: False)
    assert nft.table is None


def test_apply_failure_rolls_back(env, sample_state):
    b, nft, store = env
    safe_apply(b, make_state(), store)
    before = nft.table
    nft.fail_apply = 1
    with pytest.raises(BackendError):
        safe_apply(b, sample_state, store)
    assert nft.table == before


def test_conflicts_block_unless_forced(env):
    b, nft, store = env
    bad = make_state(rules=[R(id=1, action="accept", protocol="tcp", priority=1),
                            R(id=2, action="drop", protocol="tcp", dport=["22"], priority=2)])
    with pytest.raises(ValidationFailed):
        safe_apply(b, bad, store)
    assert nft.table is None
    assert safe_apply(b, bad, store, allow_conflicts=True).applied


def test_lockout_state_rejected_before_touching_firewall(env):
    b, nft, store = env
    with pytest.raises(ValidationFailed):
        safe_apply(b, make_state(policy={"management_ports": []}), store)
    assert nft.calls == []


def test_failed_rollback_triggers_emergency_teardown(env, sample_state):
    b, nft, store = env
    safe_apply(b, make_state(), store)
    nft.fail_apply = 0
    orig = b.restore

    def bad_restore(snapshot):
        raise BackendError("restore broke")

    b.restore = bad_restore
    with pytest.raises(BackendError):
        safe_apply(b, sample_state, store, connectivity_check=lambda: False)
    assert nft.table is None  # teardown ran
    b.restore = orig


async def test_deadman_rolls_back_without_confirmation(env, sample_state):
    b, nft, store = env
    safe_apply(b, make_state(), store)
    before = nft.table
    with pytest.raises(RolledBack):
        await apply_with_confirmation(b, sample_state, store, asyncio.Event(), timeout=0.05)
    assert nft.table == before


async def test_deadman_keeps_change_when_confirmed(env, sample_state):
    b, nft, store = env
    ev = asyncio.Event()
    asyncio.get_running_loop().call_later(0.02, ev.set)
    r = await apply_with_confirmation(b, sample_state, store, ev, timeout=1)
    assert r.applied and nft.table is not None


def test_emergency_disable(env, sample_state):
    b, nft, store = env
    safe_apply(b, sample_state, store)
    emergency_disable(b)
    assert nft.table is None


def test_backup_retention_and_path_guard(tmp_path):
    s = BackupStore(tmp_path / "b", keep=2)
    for i in range(4):
        s.save(f"snap{i}")
    assert len(list(s.dir.glob("*.snapshot"))) == 2 and s.latest() == "snap3"
    with pytest.raises(ValidationFailed):
        s.read(tmp_path / "b" / ".." / "x")
    assert BackupStore(tmp_path / "none").latest() is None and s.save(None) is None


def test_tcp_probe():
    import socket

    from app.services.safe_apply import tcp_probe
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    assert tcp_probe("127.0.0.1", srv.getsockname()[1])
    port = srv.getsockname()[1]; srv.close()
    assert not tcp_probe("127.0.0.1", port, timeout=0.5)
