import asyncio
import os
import stat

import pytest

from app.core.config import FirewallSettings
from app.core.errors import BackendError, ValidationFailed
from app.database.base import Base, make_engine, make_session_factory
from app.executor.protocol import ExecutorClient
from app.executor.server import ExecutorServer
from app.firewall.backends.nftables import NftablesBackend
from app.services.facade import LocalFacade
from app.services.firewall_manager import FirewallManager, NotFound
from app.services.safe_apply import BackupStore


@pytest.fixture
def facade(fake_nft, tmp_path):
    e = make_engine(f"sqlite:///{tmp_path/'e.db'}")
    Base.metadata.create_all(e)
    m = FirewallManager(NftablesBackend(runner=fake_nft), make_session_factory(e), BackupStore(tmp_path / "bk"),
                        FirewallSettings(blocklist_dir=tmp_path / "bl"))
    return LocalFacade(m)


@pytest.fixture
async def server(facade, tmp_path):
    srv = ExecutorServer(facade, tmp_path / "run" / "x.sock", {os.getuid()})
    await srv.start()
    yield srv, ExecutorClient(str(srv.path), timeout=5)
    await srv.stop()


async def call(client, method, **kw):
    return await asyncio.to_thread(client.call, method, **kw)


async def test_roundtrip_and_permissions(server):
    srv, c = server
    assert stat.S_IMODE(os.stat(srv.path).st_mode) == 0o660
    r = await call(c, "add_rule", rule={"name": "w", "action": "accept", "protocol": "tcp", "dport": ["80"]}, actor="t")
    assert r["id"]
    assert (await call(c, "list_rules"))[0]["dport"] == ["80"]
    b = await call(c, "ban", network="203.0.113.5", actor="t", ttl_seconds=60)
    assert b["network"] == "203.0.113.5/32" and isinstance(b["created_at"], str)
    assert await call(c, "unban", network="203.0.113.5", actor="t") == 1
    assert (await call(c, "status"))["installed"] is True


async def test_error_translation(server):
    _, c = server
    with pytest.raises(ValidationFailed):
        await call(c, "ban", network="0.0.0.0/0", actor="t")
    with pytest.raises(NotFound):
        await call(c, "unban", network="1.2.3.4", actor="t")
    with pytest.raises(ValidationFailed):
        await call(c, "add_rule", rule={"name": "x", "source": "evil;"}, actor="t")


@pytest.mark.parametrize("method", ["__init__", "m", "constructor", "EXPORTED", "os.system", "", None])
async def test_non_exported_methods_rejected(server, method):
    _, c = server
    with pytest.raises(ValidationFailed):
        await call(c, str(method) if method is not None else "x")


async def test_bad_params_and_garbage(server):
    srv, c = server
    with pytest.raises(ValidationFailed):
        await call(c, "ban", network="1.2.3.4", actor="t", evil="x")
    with pytest.raises(ValidationFailed):
        await call(c, "ban")
    r, w = await asyncio.open_unix_connection(str(srv.path))
    w.write(b"not json\n")
    assert b"invalid json" in await r.readline()
    w.close()
    r, w = await asyncio.open_unix_connection(str(srv.path))
    w.write(b"[1,2]\n")
    assert b'"ok":false' in await r.readline()
    w.close()


async def test_unauthorised_uid_rejected(facade, tmp_path):
    srv = ExecutorServer(facade, tmp_path / "s.sock", {os.getuid() + 1})
    await srv.start()
    try:
        with pytest.raises(BackendError):
            await call(ExecutorClient(str(srv.path), timeout=2), "status")
    finally:
        await srv.stop()


def test_client_without_server(tmp_path):
    with pytest.raises(BackendError):
        ExecutorClient(str(tmp_path / "none.sock")).call("status")


async def test_ips_over_executor_socket(server):
    """Daemon-side IPS works through the unix socket (no direct kernel access)."""
    from app.core.config import IdsSettings
    from app.detection.events import SecurityEvent
    from app.ips.service import IPSService
    _srv, c = server

    def run():
        ips = IPSService(c, IdsSettings(escalation_multiplier=2))
        ev = SecurityEvent(kind="jail_threshold", source_ip="203.0.113.50", severity="high", jail="sshd",
                           ban_recommended=True, message="m", details={"bantime": 100})
        first = ips.handle(ev)
        again = ips.handle(ev)
        wl = ips.handle(SecurityEvent(kind="x", source_ip="127.0.0.1", ban_recommended=True))
        return first, again, wl

    assert await asyncio.to_thread(run) == ("banned", "already_banned", "protected_address")
