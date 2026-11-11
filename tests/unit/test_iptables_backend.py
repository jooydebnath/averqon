import pytest

from app.core.errors import BackendError
from app.firewall.backends.iptables import IptablesBackend
from app.utils.process import CommandResult
from tests.conftest import make_state


def test_render_families(sample_state):
    out = IptablesBackend().render(sample_state)
    v4, v6 = out.split("#v6\n")
    assert ":AVERQON-IN - [0:0]" in v4 and v4.rstrip().endswith("COMMIT")
    assert "-p tcp -m multiport --dports 80,443,8000:8100 -j ACCEPT" in v4
    assert "-s 10.0.0.0/8 -p udp -m multiport --dports 53 -j ACCEPT" in v4
    assert "2001:db8::/32" not in v4 and "2001:db8::/32" in v6
    assert "-A AVERQON-IN -j LOG --log-prefix" not in v4  # v6-only rule
    assert "-A AVERQON-IN -s 2001:db8::/32 -p tcp -m multiport --dports 25 -j LOG" in v6
    assert "-o eth0 -p tcp -m multiport --dports 23 -m conntrack --ctstate NEW -m limit --limit 5/minute -j DROP" in v4
    assert "-A AVERQON-IN -j DROP" in v4 and "-A AVERQON-OUT -j DROP" not in v4
    assert "-s 192.0.2.10/32 -j ACCEPT" in v4 and "-s 192.0.2.10/32" not in v6
    assert "ipv6-icmp" in v6 and "-p icmp " in v4


def test_never_touches_host_policy_or_flushes_host_chains(sample_state):
    out = IptablesBackend().render(sample_state)
    assert ":INPUT" not in out and ":OUTPUT" not in out and "-F INPUT" not in out
    assert "--noflush" not in out  # flag is passed on the command line, not in payload


def test_apply_uses_noflush_and_hooks():
    calls = []

    def run(argv, *, timeout=10.0, input_text=None):
        calls.append((list(argv), input_text))
        return CommandResult(1 if "-C" in argv else 0, "", "")

    b = IptablesBackend(runner=run)
    b.apply(b.render(make_state()))
    restores = [c for c in calls if c[0][0].endswith("restore")]
    assert [c[0] for c in restores] == [["iptables-restore", "--noflush"], ["ip6tables-restore", "--noflush"]]
    assert ["iptables", "-I", "INPUT", "1", "-j", "AVERQON-IN"] in [c[0] for c in calls]


def test_partial_failure_tears_down_both():
    calls = []

    def run(argv, *, timeout=10.0, input_text=None):
        calls.append(list(argv))
        if argv[0] == "ip6tables-restore":
            return CommandResult(1, "", "bad")
        return CommandResult(1 if ("-D" in argv or "-C" in argv) else 0, "", "")

    b = IptablesBackend(runner=run)
    with pytest.raises(BackendError):
        b.apply(b.render(make_state()))
    assert ["iptables", "-X", "AVERQON-IN"] in calls


def test_ban_validation():
    b = IptablesBackend(runner=lambda a, **k: CommandResult(0, "", ""))
    for bad in ("0.0.0.0/0", "::/0", "1.1.1.1;ls"):
        with pytest.raises((BackendError, ValueError)):
            b.ban(bad, None)


SAVE = "*filter\n:INPUT ACCEPT [0:0]\n:AVERQON-IN - [0:0]\n-A INPUT -j AVERQON-IN\n-A AVERQON-IN -j DROP\nCOMMIT\n"


def test_export_only_includes_owned_chains_and_restore_roundtrip():
    calls = []

    def run(argv, *, timeout=10.0, input_text=None):
        calls.append((list(argv), input_text))
        return CommandResult(0, SAVE if "save" in argv[0] else "", "")

    b = IptablesBackend(runner=run)
    snap = b.export()
    assert snap and ":INPUT" not in snap and "-A INPUT" not in snap and ":AVERQON-IN" in snap
    b.restore(snap)
    assert any(c[0] == ["iptables-restore", "--noflush"] for c in calls)


def test_export_none_when_absent_or_failing():
    ok = IptablesBackend(runner=lambda a, **k: CommandResult(0, "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n", ""))
    assert ok.export() is None
    bad = IptablesBackend(runner=lambda a, **k: CommandResult(1, "", "x"))
    assert bad.export() is None


def test_teardown_only_touches_own_chains():
    calls = []

    def run(argv, *, timeout=10.0, input_text=None):
        calls.append(list(argv))
        return CommandResult(1 if "-D" in argv else 0, "", "")

    IptablesBackend(runner=run).teardown()
    flat = [" ".join(c) for c in calls]
    assert all("AVERQON" in f for f in flat) and not any(f.endswith("-F INPUT") for f in flat)


def test_restore_none_tears_down_and_unban_and_counters():
    calls = []

    def run(argv, *, timeout=10.0, input_text=None):
        calls.append(list(argv))
        out = "Chain AVERQON-IN\n pkts bytes target\n  5  500 DROP all\n  x y z\n" if "-L" in argv else ""
        return CommandResult(1 if "-D" in argv else 0, out, "")

    b = IptablesBackend(runner=run)
    b.restore(None)
    b.unban("1.2.3.4")
    b.ban("2001:db8::1", None)
    assert ["ip6tables", "-I", "AVERQON-IN", "3", "-s", "2001:db8::1/128", "-j", "DROP"] in calls
    assert b.counters() == {"packets": 10, "bytes": 1000}


def test_check_reports_real_errors_but_tolerates_permission():
    deny = IptablesBackend(runner=lambda a, **k: CommandResult(1, "", "Permission denied (you must be root)"))
    deny.check(deny.render(make_state()))
    bad = IptablesBackend(runner=lambda a, **k: CommandResult(1, "", "iptables-restore: line 3 failed"))
    with pytest.raises(BackendError):
        bad.check(bad.render(make_state()))


def test_protection_rendering_and_size_guard():
    from app.firewall.policies.policy import Protection
    b = IptablesBackend()
    out = b.render(make_state(protection=Protection(syn_rate="200/second", conn_limit_per_ip=50, log_drops=True,
                                                    new_conn_rate_per_ip="20/second", blocklists={"t": ["203.0.113.0/24", "2001:db8::/32"]})))
    v4, v6 = out.split("#v6\n")
    assert "--hashlimit-above 200/sec --hashlimit-burst 400 --hashlimit-mode srcip" in v4
    assert "--connlimit-above 50 --connlimit-mask 32" in v4 and "--connlimit-mask 128" in v6
    assert "-s 203.0.113.0/24 -j DROP" in v4 and "-s 2001:db8::/32 -j DROP" in v6 and "-s 2001:db8::/32" not in v4
    assert 'averqon-drop' in v4
    big = Protection(blocklists={"t": [f"10.{i//256}.{i%256}.0/24" for i in range(2500)]})
    with pytest.raises(BackendError):
        b.render(make_state(protection=big))
