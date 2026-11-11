from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.config import FirewallSettings
from app.core.errors import BackendError, ValidationFailed
from app.database.base import Base, make_engine, make_session_factory, session_scope
from app.database.models import AuditLogEntry, BanRow
from app.firewall.backends.nftables import NftablesBackend
from app.firewall.rules.models import FirewallRule as R
from app.services.firewall_manager import FirewallManager, NotFound
from app.services.safe_apply import BackupStore


@pytest.fixture
def mgr(fake_nft, tmp_path):
    engine = make_engine("sqlite://")
    Base.metadata.create_all(engine)
    return FirewallManager(NftablesBackend(runner=fake_nft), make_session_factory(engine),
                           BackupStore(tmp_path / "bk"), FirewallSettings(admin_ips=["198.51.100.7"]))


def audit(m):
    with session_scope(m.sessions) as s:
        return [a.action for a in s.scalars(select(AuditLogEntry))]


def test_rule_crud_applies_and_audits(mgr, fake_nft):
    r = mgr.add_rule(R(name="web", action="accept", protocol="tcp", dport=["80"]), actor="alice")
    assert r.id and "tcp dport { 80 }" in fake_nft.table
    mgr.update_rule(r.id, R(name="web", action="accept", protocol="tcp", dport=["8080"]), actor="alice")
    assert "{ 8080 }" in fake_nft.table and "{ 80 }" not in fake_nft.table
    mgr.delete_rule(r.id, actor="bob")
    assert mgr.list_rules() == [] and "8080" not in fake_nft.table
    assert audit(mgr) == ["rule.add", "rule.update", "rule.delete"]
    with pytest.raises(NotFound):
        mgr.delete_rule(999, actor="x")


def test_failed_apply_rolls_db_back(mgr, fake_nft):
    mgr.add_rule(R(name="a", action="accept", protocol="tcp", dport=["1"]), actor="x")
    fake_nft.fail_apply = 1
    with pytest.raises(BackendError):
        mgr.add_rule(R(name="b", action="accept", protocol="tcp", dport=["2"]), actor="x")
    assert [r.name for r in mgr.list_rules()] == ["a"]


def test_conflict_blocks_and_db_unchanged(mgr):
    mgr.add_rule(R(name="all", action="accept", protocol="tcp", priority=1), actor="x")
    with pytest.raises(ValidationFailed):
        mgr.add_rule(R(name="no22", action="drop", protocol="tcp", dport=["22"], priority=2), actor="x")
    assert len(mgr.list_rules()) == 1
    mgr.add_rule(R(name="no22", action="drop", protocol="tcp", dport=["22"], priority=2), actor="x", allow_conflicts=True)
    assert len(mgr.list_rules()) == 2


def test_dry_run_persists_nothing(mgr, fake_nft):
    mgr.add_rule(R(name="x", action="drop", protocol="tcp", dport=["9"]), actor="x", dry_run=True)
    assert mgr.list_rules() == [] and fake_nft.table is None


def test_ban_unban_history(mgr, fake_nft):
    mgr.ban("203.0.113.5", actor="alice", ttl_seconds=60, reason="ssh brute")
    assert [b.network for b in mgr.list_bans()] == ["203.0.113.5/32"]
    assert mgr.unban("203.0.113.5", actor="alice") == 1
    assert mgr.list_bans() == [] and len(mgr.list_bans(active_only=False)) == 1
    with pytest.raises(NotFound):
        mgr.unban("203.0.113.5", actor="alice")


@pytest.mark.parametrize("target", ["198.51.100.7", "198.51.100.0/24", "0.0.0.0/0", "::/0", "1.2.3.4;x"])
def test_cannot_ban_admin_or_everything(mgr, target):
    with pytest.raises((ValidationFailed, ValueError)):
        mgr.ban(target, actor="x")
    assert mgr.list_bans() == []


def test_ban_ttl_bounds(mgr):
    for bad in (0, -5, 10**10):
        with pytest.raises(ValidationFailed):
            mgr.ban("1.2.3.4", actor="x", ttl_seconds=bad)


def test_whitelist_ends_overlapping_bans_and_ban_survives_reapply(mgr, fake_nft):
    mgr.ban("203.0.113.0/24", actor="x")
    mgr.apply()
    assert "203.0.113.0/24" in fake_nft.table  # bans persist across full reloads
    mgr.whitelist_add("203.0.113.9", actor="x")
    assert mgr.list_bans() == [] and "203.0.113.9/32" in fake_nft.table
    with pytest.raises(ValidationFailed):
        mgr.ban("203.0.113.9", actor="x")
    mgr.whitelist_remove("203.0.113.9", actor="x")
    with pytest.raises(NotFound):
        mgr.whitelist_remove("203.0.113.9", actor="x")


def test_expire_bans(mgr):
    row = mgr.ban("203.0.113.5", actor="x", ttl_seconds=60)
    with session_scope(mgr.sessions) as s:
        s.get(BanRow, row.id).expires_at = datetime.now(UTC) - timedelta(seconds=1)
    assert mgr.expire_bans() == 1 and mgr.list_bans() == [] and mgr.expire_bans() == 0


def test_admin_ips_always_whitelisted(mgr, fake_nft):
    mgr.apply()
    assert "198.51.100.7/32" in fake_nft.table
    assert mgr.status()["installed"] is True
