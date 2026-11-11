import re
import shutil
from datetime import UTC, datetime, timedelta

import pytest

from app.core.errors import BackendError, ValidationFailed
from app.firewall.backends.nftables import NftablesBackend
from app.firewall.policies.policy import Ban, FirewallState
from tests.conftest import make_state


def test_render_structure(sample_state):
    out = NftablesBackend().render(sample_state)
    assert out.startswith("add table inet averqon\ndelete table inet averqon\ntable inet averqon {")
    assert "tcp dport { 80, 443, 8000-8100 } counter accept" in out
    assert "ip saddr 10.0.0.0/8 udp dport { 53 } counter accept" in out
    assert 'ip6 saddr 2001:db8::/32 tcp dport { 25 } log prefix "averqon: " counter drop comment "no smtp"' in out
    assert 'oifname "eth0" tcp dport { 23 } ct state { new } limit rate 5/minute counter drop' in out
    assert "policy drop;" in out and "tcp dport { 22 } accept" in out
    assert "192.0.2.10" in out and "2001:db8:ffff::1" in out
    # whitelist is evaluated before bans, bans before management/user rules
    assert out.index("@whitelist4 accept") < out.index("@banned4 counter drop") < out.index("tcp dport { 22 }")


def test_never_flushes_ruleset():
    out = NftablesBackend().render(make_state())
    assert "flush ruleset" not in out and out.count("delete table") == 1


def test_priority_order_and_disabled():
    from app.firewall.rules.models import FirewallRule as R
    s = make_state(rules=[R(id=1, name="b", priority=200, protocol="tcp", dport=["2"], action="accept"),
                          R(id=2, name="a", priority=100, protocol="tcp", dport=["1"], action="accept"),
                          R(id=3, name="off", enabled=False, protocol="tcp", dport=["3"], action="accept")])
    out = NftablesBackend().render(s)
    assert out.index("{ 1 }") < out.index("{ 2 }") and "{ 3 }" not in out


def test_bans_timeouts():
    now = datetime.now(UTC)
    s = make_state(bans=[Ban(network="1.2.3.4"), Ban(network="5.6.7.8", expires_at=now + timedelta(seconds=100)),
                         Ban(network="9.9.9.9", expires_at=now - timedelta(seconds=5)), Ban(network="2001:db8::/64")])
    out = NftablesBackend().render(s)
    assert "1.2.3.4/32" in out and re.search(r"5\.6\.7\.8/32 timeout (99|100)s", out)
    assert "9.9.9.9" not in out and "2001:db8::/64" in out


def test_render_rejects_inconsistent_state():
    with pytest.raises(ValidationFailed):
        NftablesBackend().render(FirewallState(whitelist=["1.2.3.4"], bans=[Ban(network="1.2.3.4")]))


def test_bad_table_name():
    for bad in ["x; flush ruleset", "A", "", "1a"]:
        with pytest.raises(BackendError):
            NftablesBackend(table=bad)


@pytest.mark.skipif(not shutil.which("nft"), reason="nft not installed")
def test_real_nft_syntax_accepts_render(sample_state):
    """Uses the real nft parser. Unprivileged runs still catch every syntax error."""
    b = NftablesBackend()
    b.check(b.render(sample_state))
    b.check(b.render(make_state(policy={"input": "accept", "management_ports": [], "allow_ping": False})))


@pytest.mark.skipif(not shutil.which("nft"), reason="nft not installed")
def test_real_nft_syntax_rejects_garbage():
    with pytest.raises(BackendError):
        NftablesBackend().check("table inet averqon { chain x { bogus } }\n")


def test_apply_check_failure_raises(fake_nft):
    b = NftablesBackend(runner=fake_nft)
    fake_nft.fail_apply = 1
    with pytest.raises(BackendError):
        b.apply("x")


def test_live_ban_commands(fake_nft):
    b = NftablesBackend(runner=fake_nft)
    b.ban("1.2.3.4", 60)
    b.ban("2001:db8::1", None)
    b.unban("1.2.3.4")
    assert fake_nft.calls[0][1:] == ["add", "element", "inet", "averqon", "banned4", "{ 1.2.3.4/32 timeout 60s }"]
    assert fake_nft.calls[1][-2:] == ["banned6", "{ 2001:db8::1/128 }"]
    for bad in ("0.0.0.0/0", "::/0", "1.1.1.1; ls", "1.1.1.1}"):
        with pytest.raises((BackendError, ValidationFailed)):
            b.ban(bad, 1)


def test_no_shell_metacharacters_reach_argv(fake_nft):
    b = NftablesBackend(runner=fake_nft)
    with pytest.raises(ValidationFailed):
        b.ban("1.2.3.4 } ; flush ruleset ; {", 1)
    assert fake_nft.calls == []


def test_counters_parse():
    import json

    from app.utils.process import CommandResult
    payload = {"nftables": [{"rule": {"expr": [{"counter": {"packets": 3, "bytes": 300}}]}},
                            {"rule": {"expr": [{"counter": {"packets": 2, "bytes": 20}}]}}, {"table": {}}]}
    b = NftablesBackend(runner=lambda a, **k: CommandResult(0, json.dumps(payload), ""))
    assert b.counters() == {"packets": 5, "bytes": 320}
    assert NftablesBackend(runner=lambda a, **k: CommandResult(1, "", "e")).counters() == {}


@pytest.mark.parametrize("out", ["", "not json", "[]", '{"nftables": [{"rule": {"expr": [{"counter": {}}]}}]}'])
def test_counters_malformed_output_does_not_crash(out):
    from app.utils.process import CommandResult
    assert NftablesBackend(runner=lambda a, **k: CommandResult(0, out, "")).counters() in ({}, {"packets": 0, "bytes": 0})


def _prot_state():
    from app.firewall.policies.policy import Protection
    return make_state(protection=Protection(
        syn_rate="200/second", conn_limit_per_ip=100, new_conn_rate_per_ip="50/second", log_drops=True,
        blocklists={"geo_xx": ["198.18.0.0/15", "2001:db8:dead::/48"], "threat": ["203.0.113.0/24"]}))


def test_protection_render_and_real_syntax():
    b = NftablesBackend()
    out = b.render(_prot_state())
    assert "add @synflood4 { ip saddr limit rate over 200/second burst 400 packets } counter drop" in out
    assert "add @connlimit6 { ip6 saddr ct count over 100 } counter drop" in out
    assert "set bl_geo_xx4 { type ipv4_addr; flags interval; elements = { 198.18.0.0/15 } }" in out
    assert "ip6 saddr @bl_threat6 counter drop" in out and 'log prefix "averqon-drop: "' in out
    assert out.index("@banned4 counter drop") < out.index("@bl_threat4") < out.index("@synflood4") < out.index("tcp dport { 22 }")
    if shutil.which("nft"):
        b.check(out)


def test_blocklist_whitelist_overlap_rejected():
    from app.firewall.policies.policy import Protection
    with pytest.raises(ValidationFailed):
        NftablesBackend().render(make_state(whitelist=["203.0.113.5"], protection=Protection(blocklists={"t": ["203.0.113.0/24"]})))


def test_protection_input_validation():
    from pydantic import ValidationError

    from app.firewall.policies.policy import Protection
    for kw in ({"syn_rate": "5/day"}, {"syn_rate": "0/second"}, {"blocklists": {"Bad Name": []}},
               {"blocklists": {"ok": ["1.2.3.4;x"]}}, {"conn_limit_per_ip": 0}, {"bogus": 1}):
        with pytest.raises(ValidationError):
            Protection(**kw)
