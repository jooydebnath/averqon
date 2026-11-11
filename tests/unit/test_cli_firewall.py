import json

import pytest
from typer.testing import CliRunner

import cli.main as cli
from app.core.config import FirewallSettings
from app.database.base import Base, make_engine, make_session_factory
from app.firewall.backends.nftables import NftablesBackend
from app.services.firewall_manager import FirewallManager
from app.services.safe_apply import BackupStore

run = CliRunner()


@pytest.fixture
def env(monkeypatch, fake_nft, tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path/'t.db'}")
    Base.metadata.create_all(engine)
    m = FirewallManager(NftablesBackend(runner=fake_nft), make_session_factory(engine),
                        BackupStore(tmp_path / "bk"), FirewallSettings())
    monkeypatch.setattr(cli, "get_manager", lambda _c: m)
    return m, fake_nft


def j(args):
    r = run.invoke(cli.app, args)
    return r.exit_code, r.stdout


def test_rules_roundtrip(env):
    code, out = j(["firewall", "rules", "add", "--action", "accept", "--protocol", "tcp", "--dport", "443", "--dport", "8000-8100", "--name", "web", "--json"])
    assert code == 0 and json.loads(out)["rule"]["dport"] == ["443", "8000-8100"]
    code, out = j(["firewall", "rules", "list", "--json"])
    rid = json.loads(out)[0]["id"]
    assert j(["firewall", "rules", "remove", str(rid)])[0] == 0
    assert j(["firewall", "rules", "list"])[1].strip() == "no rules"


def test_invalid_input_clean_error(env):
    for args in (["--action", "accept", "--source", "1.2.3.4;ls"], ["--action", "bogus"],
                 ["--action", "drop", "--protocol", "icmp", "--dport", "5"]):
        code, out = j(["firewall", "rules", "add", "--json", *args])
        assert code == 1 and json.loads(out)["ok"] is False


def test_dry_run_and_apply(env):
    _m, nft = env
    code, out = j(["firewall", "apply", "--dry-run"])
    assert code == 0 and "add table inet averqon" in out and nft.table is None
    assert j(["firewall", "apply"])[0] == 0 and nft.table


def test_ban_flow_and_protection(env):
    assert j(["ip", "ban", "203.0.113.9", "--ttl", "60"])[0] == 0
    assert "203.0.113.9" in j(["ip", "list"])[1]
    assert j(["ip", "ban", "0.0.0.0/0"])[0] == 1
    assert j(["ip", "unban", "203.0.113.9"])[0] == 0
    assert j(["ip", "unban", "203.0.113.9"])[0] == 1


def test_backup_restore_emergency(env):
    _m, nft = env
    assert j(["backup"])[0] == 0 and "nothing" in j(["backup"])[1]
    j(["firewall", "apply"])
    _c, out = j(["backup", "--json"])
    assert json.loads(out)["ok"] is True
    j(["firewall", "emergency-disable"])
    assert nft.table is None
    assert j(["restore"])[0] == 0 and nft.table
    assert j(["firewall", "status", "--json"])[0] == 0


def test_status_runs_without_root():
    code, out = j(["status", "--json"])
    assert code == 0 and "capabilities" in json.loads(out)
