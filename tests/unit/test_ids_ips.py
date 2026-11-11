import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import FirewallSettings, IdsSettings
from app.database.base import Base, make_engine, make_session_factory, session_scope
from app.database.models import BanRow, IdsEventRow
from app.detection.events import SecurityEvent
from app.detection.jails import JailConfig
from app.firewall.backends.nftables import NftablesBackend
from app.ids.engine import IDSEngine
from app.ips.service import IPSService
from app.services.daemon import Daemon, build_jails
from app.services.facade import LocalFacade
from app.services.firewall_manager import FirewallManager
from app.services.safe_apply import BackupStore


@pytest.fixture
def stack(fake_nft, tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path/'ids.db'}")
    Base.metadata.create_all(engine)
    sessions = make_session_factory(engine)
    mgr = FirewallManager(NftablesBackend(runner=fake_nft), sessions, BackupStore(tmp_path / "bk"),
                          FirewallSettings(admin_ips=["198.51.100.7"], blocklist_dir=tmp_path / "bl"))

    def build(**kw):
        cfg = IdsSettings(**kw)
        ips = IPSService(LocalFacade(mgr), cfg, own_ips={"10.9.9.9"})
        return IDSEngine(sessions, ips, cfg, low_event_interval=0), ips

    return mgr, build, sessions


def ban_ev(ip, **kw):
    return SecurityEvent(kind="jail_threshold", source_ip=ip, severity=kw.pop("severity", "high"), jail="sshd",
                         ban_recommended=True, message="x", details={"bantime": kw.pop("bantime", 100)})


def test_autoban_and_audit_trail(stack):
    mgr, build, _s = stack
    ids, _ = build()
    assert ids.handle(ban_ev("203.0.113.5")) == "banned"
    assert [b.network for b in mgr.list_bans()] == ["203.0.113.5/32"]
    rows, total = ids.query()
    assert total == 1 and rows[0].action == "banned" and rows[0].source_ip == "203.0.113.5"


@pytest.mark.parametrize(("ip", "expect"), [
    ("198.51.100.7", "whitelisted"), ("127.0.0.1", "protected_address"), ("::1", "protected_address"),
    ("169.254.1.1", "protected_address"), ("0.0.0.0", "protected_address"), ("10.9.9.9", "protected_address"),
    ("224.0.0.1", "protected_address"),
])
def test_never_bans_protected(stack, ip, expect):
    mgr, build, _ = stack
    ids, _ = build()
    assert ids.handle(ban_ev(ip)) == expect and mgr.list_bans() == []


def test_already_banned_and_flags(stack):
    mgr, build, _ = stack
    ids, _ = build()
    ids.handle(ban_ev("203.0.113.5"))
    assert ids.handle(ban_ev("203.0.113.5")) == "already_banned"
    ids2, _ = build(autoban=False)
    assert ids2.handle(ban_ev("203.0.113.6")) == "autoban_disabled" and len(mgr.list_bans()) == 1
    ids3, _ = build(autoban_min_severity="critical")
    assert ids3.handle(ban_ev("203.0.113.7", severity="high")) == "below_threshold"
    ids4, _ = build(ignore_networks=["203.0.113.0/24"])
    assert ids4.handle(ban_ev("203.0.113.8")) == "ignored" and ids4.query()[1] == 0 + ids4.query()[1]


def test_escalation_and_permanent(stack):
    mgr, build, sessions = stack
    ids, ips = build(escalation_multiplier=2, max_bantime=500, permanent_after=4)
    ttls = []
    for _ in range(4):
        ids.handle(ban_ev("203.0.113.5", bantime=100))
        with session_scope(sessions) as s:
            b = s.query(BanRow).order_by(BanRow.id.desc()).first()
            ttls.append(None if b.expires_at is None else round((b.expires_at.replace(tzinfo=UTC) - b.created_at.replace(tzinfo=UTC)).total_seconds(), -1))
        mgr.unban("203.0.113.5", actor="t")
    assert ttls == [100, 200, 400, None]
    assert ips.compute_bantime("203.0.113.99", -1) is None


def test_cap(stack):
    mgr, build, _ = stack
    ids, ips = build(max_bantime=150, permanent_after=0)
    for _ in range(3):
        ids.handle(ban_ev("203.0.113.5", bantime=100))
        mgr.unban("203.0.113.5", actor="t")
    assert ips.compute_bantime("203.0.113.5", 100) == 150


def test_severity_classification_and_sampling(stack):
    _, build, _ = stack
    ids, _ = build()
    scan = SecurityEvent(kind="port_scan", source_ip="203.0.113.5", severity="low")
    ids.handle(scan)
    assert ids.query(severity="high")[1] == 1
    clock = [100.0]
    from app.ids.engine import IDSEngine as E
    sampled = E(ids.sessions, ids.ips, ids.cfg, clock=lambda: clock[0], low_event_interval=5)
    low = SecurityEvent(kind="ssh_auth_failure", source_ip="203.0.113.50", severity="low")
    assert sampled.handle(low) == "none"
    assert sampled.handle(low) == "sampled_out"
    clock[0] += 6
    assert sampled.handle(low) == "none"


def test_listeners_and_failure_isolation(stack):
    _, build, _ = stack
    ids, _ = build()
    seen = []
    ids.listeners += [lambda e, a: (_ for _ in ()).throw(RuntimeError("boom")), lambda e, a: seen.append(a)]
    ids.handle(ban_ev("203.0.113.5"))
    assert seen == ["banned"]


def test_stats_filters_and_prune(stack):
    _, build, sessions = stack
    ids, _ = build()
    ids.handle(ban_ev("203.0.113.5"))
    ids.handle(SecurityEvent(kind="ssh_auth_failure", source_ip="203.0.113.5", severity="low"))
    st = ids.stats()
    assert st["by_kind"]["jail_threshold"] == 1 and st["top_sources"][0] == {"ip": "203.0.113.5", "count": 2}
    assert ids.query(kind="ssh_auth_failure")[1] == 1 and ids.query(source_ip="1.1.1.1")[1] == 0
    assert ids.query(since=datetime.now(UTC) + timedelta(hours=1))[1] == 0 and ids.query(limit=1)[0][0].id
    with session_scope(sessions) as s:
        s.query(IdsEventRow).first().ts = datetime.now(UTC) - timedelta(days=200)
    assert ids.prune(90) == 1


async def test_daemon_end_to_end_with_log_file(stack, tmp_path):
    mgr, build, _ = stack
    ids, _ = build()
    log = tmp_path / "auth.log"
    log.write_text("")
    jails = [JailConfig(name="sshd", filter="sshd", logpaths=[str(log)], maxretry=3, findtime=60, bantime=300)]
    d = Daemon(ids, jails, ids.cfg, LocalFacade(mgr), housekeeping_interval=0.05)
    runner = asyncio.create_task(d.run())
    await asyncio.sleep(0.2)
    with log.open("a") as fh:
        for _ in range(3):
            fh.write("sshd[1]: Failed password for root from 203.0.113.77 port 22 ssh2\n")
    for _ in range(100):
        if mgr.list_bans():
            break
        await asyncio.sleep(0.05)
    d.stop.set()
    await asyncio.wait_for(runner, 3)
    assert [b.network for b in mgr.list_bans()] == ["203.0.113.77/32"] and d.lines_processed >= 3


def test_build_jails_override():
    assert build_jails(IdsSettings(), ["d"]) == ["d"]  # type: ignore[list-item]
    js = build_jails(IdsSettings(jails=[{"name": "x", "filter": "sshd", "journal_units": ["ssh"]}]), [])
    assert js[0].name == "x"
