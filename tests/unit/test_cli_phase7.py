import json
from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

import cli.main as cli
from app.audit.service import record_audit
from app.core.config import Settings
from app.database.base import Base, make_engine, make_session_factory, session_scope
from app.database.models import IdsEventRow

run = CliRunner()


@pytest.fixture
def db(monkeypatch, tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path/'c.db'}")
    Base.metadata.create_all(engine)
    sessions = make_session_factory(engine)
    monkeypatch.setattr(cli, "get_sessions", lambda _c: (sessions, Settings()))
    monkeypatch.setenv("AVERQON_PASSWORD", "a-very-long-password")
    return sessions


def j(*args):
    r = run.invoke(cli.app, list(args))
    return r.exit_code, r.stdout


def test_user_lifecycle(db):
    assert j("user", "create", "alice", "--role", "admin")[0] == 0
    assert j("user", "create", "alice")[0] == 1  # duplicate
    for bad in (["bo", "--role", "viewer"], ["bob", "--role", "root"], ["b ob"]):
        assert j("user", "create", *bad)[0] == 1
    _code, out = j("user", "list", "--json")
    assert json.loads(out) == [{"username": "alice", "role": "admin", "enabled": True}]
    assert "password" not in out and "scrypt" not in out
    assert j("user", "passwd", "alice")[0] == 0 and j("user", "passwd", "ghost")[0] == 1


def test_weak_password_rejected(db, monkeypatch):
    monkeypatch.setenv("AVERQON_PASSWORD", "short")
    code, out = j("user", "create", "carol", "--json")
    assert code == 1 and json.loads(out)["ok"] is False


def test_password_not_accepted_as_argument(db):
    assert j("user", "create", "dave", "--password", "x" * 20)[0] == 2  # unknown option -> usage error


def test_ids_and_logs(db):
    with session_scope(db) as s:
        s.add(IdsEventRow(ts=datetime.now(UTC), kind="port_scan", severity="high", source_ip="203.0.113.5", message="m", details={}, action="banned"))
        record_audit(s, actor="alice", action="ip.ban", target="203.0.113.5/32")
    code, out = j("ids", "status", "--json")
    assert code == 0 and json.loads(out)["by_severity"] == {"high": 1}
    code, out = j("ids", "events", "--json", "--severity", "high")
    assert json.loads(out)["total"] == 1
    assert "port_scan" in j("ids", "events")[1] and "ip.ban" in j("logs")[1]
    assert json.loads(j("logs", "--actor", "nobody", "--json")[1]) == []


def test_harden_plan_is_readonly_by_default():
    code, out = j("firewall", "harden", "--json")
    assert code == 0 and json.loads(out)["changed"] == [] and json.loads(out)["plan"]


def test_init_db(tmp_path, monkeypatch):
    monkeypatch.setenv("AVERQON_DATABASE__URL", f"sqlite:///{tmp_path/'m.db'}")
    code, out = j("init-db")
    assert code == 0 and "up to date" in out
    from sqlalchemy import create_engine, inspect
    assert {"users", "ids_events", "bans", "audit_log"} <= set(inspect(create_engine(f"sqlite:///{tmp_path/'m.db'}")).get_table_names())


def test_runtime_wiring(tmp_path, fake_nft):
    from app.core.config import FirewallSettings
    from app.firewall.backends.nftables import NftablesBackend
    from app.services.facade import LocalFacade
    from app.services.firewall_manager import FirewallManager
    from app.services.runtime import build_daemon
    from app.services.safe_apply import BackupStore
    s = Settings(database={"url": f"sqlite:///{tmp_path/'r.db'}"}, firewall=FirewallSettings(blocklist_dir=tmp_path / "bl"),
                 ids={"jails": [{"name": "sshd", "filter": "sshd", "logpaths": [str(tmp_path / "auth.log")]}]})
    engine = make_engine(s.database.url)
    Base.metadata.create_all(engine)
    mgr = FirewallManager(NftablesBackend(runner=fake_nft), make_session_factory(engine), BackupStore(tmp_path / "bk"), s.firewall)
    daemon, disp = build_daemon(s, LocalFacade(mgr))
    assert list(daemon.jails.jails) == ["sshd"] and len(daemon.periodic) == 2
    disp.close()


def test_run_api_refuses_plain_http_on_public_address_in_production():
    from app.core.errors import ConfigError
    from app.services.runtime import run_api
    with pytest.raises(ConfigError):
        run_api(Settings(environment="production", secret_key="p" * 40, api={"host": "0.0.0.0"}))


async def test_executor_requires_allowed_uids():
    from app.core.errors import ConfigError
    from app.services.runtime import run_executor
    with pytest.raises(ConfigError):
        await run_executor(Settings())
