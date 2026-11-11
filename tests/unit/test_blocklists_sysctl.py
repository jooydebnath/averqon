import pytest

from app.core.errors import ValidationFailed
from app.firewall import sysctl
from app.services import blocklists as bl

FEED = """# comment
45.33.0.0/16 ; SBL123
45.33.9.7
10.0.0.0/8
192.168.1.0/24
127.0.0.1
0.0.0.0/0
1.0.0.0/4
8.8.8.8/8
not-an-ip
2001:db8::/32   # doc range
2606:4700::/32
224.0.0.0/4
45.33.0.0/16
"""


def test_parse_feed_sanitises():
    r = bl.parse_feed(FEED)
    assert "45.33.0.0/16" in r.networks and "45.33.9.7/32" in r.networks and "2606:4700::/32" in r.networks
    assert r.networks.count("45.33.0.0/16") == 1
    for bad in ("10.0.0.0/8", "192.168.1.0/24", "127.0.0.1/32", "0.0.0.0/0", "1.0.0.0/4", "224.0.0.0/4", "8.8.8.8/8"):
        assert bad not in r.networks
    assert r.rejected >= 8


def test_parse_feed_limits():
    text = "\n".join(f"{i}.1.1.1" for i in range(11, 100))
    assert len(bl.parse_feed(text, max_entries=10).networks) == 10


def test_fetch_requires_https_and_store(tmp_path):
    for url in ("http://x/feed", "file:///etc/passwd", "ftp://x"):
        with pytest.raises(ValidationFailed):
            bl.fetch_feed(url)
    s = bl.BlocklistStore(tmp_path / "bl")
    s.save("threat", ["45.33.0.0/16"])
    assert oct((tmp_path / "bl" / "threat.txt").stat().st_mode & 0o777) == "0o600"
    assert s.load_all() == {"threat": ["45.33.0.0/16"]}
    for bad in ("Bad", "../x", "a b", ""):
        with pytest.raises(ValidationFailed):
            s.save(bad, [])
    (tmp_path / "bl" / "Evil.txt").write_text("1.2.3.0/24")
    assert list(s.load_all()) == ["threat"]


def test_update_feed_keeps_previous_on_empty(tmp_path, monkeypatch):
    s = bl.BlocklistStore(tmp_path)
    s.save("t", ["45.33.0.0/16"])
    monkeypatch.setattr(bl, "fetch_feed", lambda url: "garbage\n10.0.0.0/8\n")
    with pytest.raises(ValidationFailed):
        s.update_feed("t", "https://x")
    assert s.load_all()["t"] == ["45.33.0.0/16"]
    monkeypatch.setattr(bl, "fetch_feed", lambda url: "185.220.0.0/15\n")
    assert s.update_feed("t", "https://x") == 1


def test_geo_countries(tmp_path):
    z = tmp_path / "zones"
    z.mkdir()
    (z / "xx.zone").write_text("185.220.0.0/15\n")
    (z / "xx6.zone").write_text("2a0b:f4c0::/32\n")
    s = bl.BlocklistStore(tmp_path / "bl")
    assert s.load_countries(z, ["xx"]) == 2 and set(s.load_all()["geo_xx"]) == {"185.220.0.0/15", "2a0b:f4c0::/32"}
    for bad in ("../etc", "xxx", "X1"):
        with pytest.raises(ValidationFailed):
            s.load_countries(z, [bad])


def test_manager_loads_blocklists_dropping_whitelist_overlap(tmp_path, fake_nft):
    from app.core.config import FirewallSettings
    from app.database.base import Base, make_engine, make_session_factory
    from app.firewall.backends.nftables import NftablesBackend
    from app.services.firewall_manager import FirewallManager
    from app.services.safe_apply import BackupStore
    e = make_engine("sqlite://")
    Base.metadata.create_all(e)
    m = FirewallManager(NftablesBackend(runner=fake_nft), make_session_factory(e), BackupStore(tmp_path / "b"),
                        FirewallSettings(admin_ips=["45.33.1.1"], blocklist_dir=tmp_path / "bl"))
    m.blocklists.save("threat", ["45.33.0.0/16", "185.220.0.0/15"])
    m.apply()
    assert "185.220.0.0/15" in fake_nft.table and "45.33.0.0/16" not in fake_nft.table


def test_sysctl_allowlist_plan_apply(tmp_path):
    for k in ("net.ipv4.tcp_syncookies", "net.ipv4.conf.all.rp_filter"):
        p = tmp_path / k.replace(".", "/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("0\n")
    plan = sysctl.plan(tmp_path)
    missing = [c for c in plan if c.current is None]
    assert len(missing) == len(sysctl.HARDENING) - 2
    done = sysctl.apply_hardening(tmp_path)
    assert {c.key for c in done} == {"net.ipv4.tcp_syncookies", "net.ipv4.conf.all.rp_filter"}
    assert (tmp_path / "net/ipv4/tcp_syncookies").read_text().strip() == "1"
    assert not (tmp_path / "net/ipv4/tcp_max_syn_backlog").exists()  # never creates keys
    with pytest.raises(ValueError):
        sysctl._path(tmp_path, "kernel.core_pattern")
    assert "tcp_syncookies = 1" in sysctl.render_conf()
