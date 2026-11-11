import asyncio

import pytest
from pydantic import ValidationError

from app.detection.filters import available_filters, match_line, parse_kernel_drop
from app.detection.jails import JailConfig, JailEngine, default_jails
from app.detection.portscan import PortScanDetector
from app.detection.tailer import follow_journal, tail_file
from app.detection.window import SlidingWindow

SSH = [
    ("Jan 1 sshd[1]: Failed password for root from 203.0.113.5 port 4242 ssh2", "203.0.113.5"),
    ("sshd[1]: Failed password for invalid user admin from 2001:db8::5 port 22 ssh2", "2001:db8::5"),
    ("sshd[1]: Invalid user oracle from 198.51.100.9 port 55", "198.51.100.9"),
    ("sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.44  user=root", "192.0.2.44"),
    ("sshd[1]: Connection closed by authenticating user root 192.0.2.1 port 1 [preauth]", "192.0.2.1"),
    ("sshd[1]: Failed password for x from ::ffff:192.0.2.77 port 22 ssh2", "192.0.2.77"),
    ("sshd[1]: maximum authentication attempts exceeded for root from 192.0.2.8 port 22 ssh2 [preauth]", "192.0.2.8"),
    ("sshd[1]: Did not receive identification string from 192.0.2.9 port 1", "192.0.2.9"),
]


@pytest.mark.parametrize(("line", "ip"), SSH)
def test_sshd_matches(line, ip):
    assert match_line("sshd", line) == ("ssh_auth_failure", ip)


@pytest.mark.parametrize("line", [
    "sshd[1]: Accepted publickey for bob from 203.0.113.5 port 22 ssh2",
    "sshd[1]: Failed password for root from not.an.ip.example port 22 ssh2",
    "sshd[1]: Failed password for root from 999.1.1.1 port 22 ssh2",
    "", "random text", "Failed password for from  port",
])
def test_sshd_non_matches(line):
    assert match_line("sshd", line) is None


def test_web_filters():
    ng = '203.0.113.7 - bob [10/Oct/2024:13:55:36 +0000] "GET /admin HTTP/1.1" 401 12 "-" "curl"'
    assert match_line("nginx-auth", ng) == ("http_auth_failure", "203.0.113.7")
    assert match_line("nginx-auth", ng.replace("401", "200")) is None
    err = '2024/10/10 13:55:36 [error] 1#1: *1 user "bob": password mismatch, client: 198.51.100.2, server: x'
    assert match_line("nginx-auth", err)[1] == "198.51.100.2"
    ap = "[Thu Oct 10 13:55:36 2024] [auth_basic:error] [pid 1] [client 192.0.2.3:5555] AH01617: user bob: authentication failure for /x"
    assert match_line("apache-auth", ap)[1] == "192.0.2.3"
    assert match_line("http-scan", ng.replace("401", "404")) == ("http_scan", "203.0.113.7")


def test_filters_resist_redos_and_huge_lines():
    import time
    for name in available_filters():
        t = time.time()
        match_line(name, "Failed password for " + "a " * 50_000)
        match_line(name, "[client " + "1" * 100_000)
        assert time.time() - t < 1.0


def test_kernel_parser():
    ln = "kernel: averqon-drop: IN=eth0 OUT= MAC=aa SRC=203.0.113.9 DST=10.0.0.1 LEN=40 PROTO=TCP SPT=4444 DPT=2222 WINDOW=1"
    assert parse_kernel_drop(ln) == ("203.0.113.9", "tcp", 2222)
    assert parse_kernel_drop("averqon-drop: SRC=2001:db8::1 DST=x PROTO=ICMPV6 TYPE=128")[2] is None
    assert parse_kernel_drop("unrelated SRC=1.2.3.4 DPT=1") is None
    assert parse_kernel_drop("averqon-drop: SRC=bad DST=x PROTO=TCP DPT=1") is None


def test_sliding_window_bounds():
    w = SlidingWindow(10, max_keys=3)
    for i, k in enumerate("abcd"):
        w.add(k, float(i))
    assert len(w) == 3 and w.items("a", 3.0) == []
    assert w.add("b", 5.0) == 2 and w.add("b", 20.0) == 1  # old entry expired
    w.purge(100.0)
    assert len(w) == 0


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


def jail(**kw):
    base = {"name": "sshd", "filter": "sshd", "logpaths": ["/var/log/auth.log"], "maxretry": 3, "findtime": 60}
    return JailConfig(**base | kw)


def test_jail_threshold_window_and_reset():
    clk = Clock()
    e = JailEngine([jail()], clock=clk)
    line = SSH[0][0]
    assert not any(ev.ban_recommended for ev in e.process_line("sshd", line))
    clk.t += 10
    e.process_line("sshd", line)
    clk.t += 10
    evs = e.process_line("sshd", line)
    ban = [x for x in evs if x.ban_recommended]
    assert len(ban) == 1 and ban[0].details["bantime"] == 3600 and ban[0].source_ip == "203.0.113.5"
    assert e.failures("sshd", "203.0.113.5") == 0  # counter reset after trigger
    # failures spread beyond findtime never trigger
    for _ in range(10):
        clk.t += 40
        assert not any(x.ban_recommended for x in e.process_line("sshd", line))


def test_jail_independent_ips_ignoreip_and_disabled():
    clk = Clock()
    e = JailEngine([jail(maxretry=2, ignoreip=["203.0.113.0/24"]), jail(name="off", enabled=False, logpaths=[])], clock=clk)
    assert e.process_line("sshd", SSH[0][0]) == []  # ignored net
    other = SSH[2][0]
    assert not any(x.ban_recommended for x in e.process_line("sshd", other))
    assert any(x.ban_recommended for x in e.process_line("sshd", other))
    assert e.process_line("off", other) == [] and e.process_line("missing", other) == []
    e.housekeeping()


@pytest.mark.parametrize("kw", [{"filter": "nope"}, {"name": "Bad Name"}, {"bantime": 0}, {"bantime": -2},
                                {"maxretry": 0}, {"logpaths": ["relative.log"]}, {"logpaths": ["/var/../etc/shadow"]},
                                {"journal_units": ["ssh; reboot"]}, {"ignoreip": ["x"]}, {"logpaths": []}, {"extra": 1}])
def test_jail_validation(kw):
    with pytest.raises(ValidationError):
        jail(**kw)


def test_default_jails_per_distro():
    assert default_jails(["debian"])[0].logpaths == ["/var/log/auth.log"]
    assert default_jails(["rhel", "fedora"])[0].logpaths == ["/var/log/secure"]
    assert default_jails([], "rocky")[0].logpaths == ["/var/log/auth.log"]  # unknown id w/o ID_LIKE falls back
    assert [j.name for j in default_jails() if j.enabled] == ["sshd"]


def test_portscan():
    clk = Clock()
    d = PortScanDetector(distinct_ports=5, window=30, clock=clk)
    for p in (1, 2, 3, 4):
        assert d.observe("1.2.3.4", p) is None
    for _ in range(50):  # same port repeatedly is not a scan
        assert d.observe("5.6.7.8", 22) is None
    assert d.observe("1.2.3.4", None) is None
    ev = d.observe("1.2.3.4", 5)
    assert ev and ev.kind == "port_scan" and ev.ban_recommended and ev.details["ports"] == [1, 2, 3, 4, 5]
    clk.t += 100
    assert d.observe("9.9.9.9", 1) is None
    for p in (1, 2, 3, 4):  # slow scan across window: no detection
        clk.t += 20
        assert d.observe("8.8.8.8", p) is None


async def test_tail_file_follows_rotation_and_truncation(tmp_path):
    f = tmp_path / "log"
    f.write_text("old\n")
    stop = asyncio.Event()
    got: list[str] = []

    async def reader():
        async for line in tail_file(f, poll=0.01, stop=stop):
            got.append(line)

    t = asyncio.create_task(reader())
    await asyncio.sleep(0.05)
    with f.open("a") as fh:
        fh.write("one\ntwo")
        fh.flush()
        await asyncio.sleep(0.05)
        fh.write("-part\n")
    await asyncio.sleep(0.1)
    f.rename(tmp_path / "log.1")
    f.write_text("rotated\n")
    await asyncio.sleep(0.1)
    f.write_text("t\n")  # truncate + rewrite
    await asyncio.sleep(0.1)
    stop.set()
    await asyncio.wait_for(t, 2)
    assert got[:2] == ["one", "two-part"] and "rotated" in got and "old" not in got and got[-1] == "t"


async def test_follow_journal_with_fake_binary(tmp_path):
    fake = tmp_path / "journalctl"
    fake.write_text("#!/bin/sh\necho line1\necho line2\n")
    fake.chmod(0o755)
    got = [ln async for ln in follow_journal(["ssh"], journalctl=str(fake))]
    assert got == ["line1", "line2"]


def test_apache_ipv6_with_port():
    ap = "[client 2001:db8::7:5555] AH01617: user bob: authentication failure for /x"
    assert match_line("apache-auth", ap) == ("http_auth_failure", "2001:db8::7")
