"""Real kernel enforcement: packets are sent across a veth pair inside throwaway
network namespaces (never touches the host firewall).

Run as root on a host where ``unshare -n`` works:
    sudo -E pytest -m integration tests/integration
or without touching the host at all:
    ./scripts/test-kernel.sh

Skipped automatically otherwise.
"""

from __future__ import annotations

import time

import pytest

from app.core.errors import BackendError
from app.firewall.backends.nftables import NftablesBackend
from app.firewall.policies.policy import Ban, FirewallState, Policy, Protection
from app.firewall.rules.models import FirewallRule
from tests.integration.netns import CLI_ADDR, SRV_ADDR, Lab, netns_available

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not netns_available(), reason="needs root + netns + nft + iptables"),
]

OPEN_PORT = 9000
BLOCKED_PORT = 9001
SECOND_SOURCE = "10.10.0.11"


def state(**kwargs) -> FirewallState:
    """A default-deny state that only lets management traffic reach OPEN_PORT."""
    kwargs.setdefault("policy", Policy(input="drop", management_ports=[OPEN_PORT]))
    return FirewallState(**kwargs)


def apply(nft: NftablesBackend, wanted: FirewallState) -> None:
    ruleset = nft.render(wanted)
    nft.check(ruleset)
    nft.apply(ruleset)


def test_default_deny_blocks_packets_and_teardown_restores_connectivity():
    with Lab() as lab, lab.server(SRV_ADDR, OPEN_PORT), lab.server(SRV_ADDR, BLOCKED_PORT):
        assert lab.wait_reachable(SRV_ADDR, OPEN_PORT)
        assert lab.wait_reachable(SRV_ADDR, BLOCKED_PORT)

        nft = NftablesBackend(runner=lab.runner(lab.srv))
        apply(nft, state())

        assert lab.wait_reachable(SRV_ADDR, OPEN_PORT), "management port must stay reachable"
        assert not lab.reachable(SRV_ADDR, BLOCKED_PORT), "default-deny did not drop the packet"

        nft.teardown()
        assert lab.wait_reachable(SRV_ADDR, BLOCKED_PORT), "teardown left the kernel dropping traffic"


def test_ban_drops_only_the_banned_source_and_unban_restores_it():
    with Lab() as lab, lab.server(SRV_ADDR, OPEN_PORT):
        lab.add_client_ip(SECOND_SOURCE)
        assert lab.wait_reachable(SRV_ADDR, OPEN_PORT, source=CLI_ADDR), "source is not usable"
        nft = NftablesBackend(runner=lab.runner(lab.srv))
        apply(nft, state(bans=[Ban(network=f"{CLI_ADDR}/32")]))

        assert not lab.reachable(SRV_ADDR, OPEN_PORT, source=CLI_ADDR)
        assert lab.wait_reachable(SRV_ADDR, OPEN_PORT, source=SECOND_SOURCE), "ban was not per-source"
        assert nft.counters().get("packets", 0) >= 1, "kernel counter did not record the drop"

        nft.unban(f"{CLI_ADDR}/32")
        assert lab.wait_reachable(SRV_ADDR, OPEN_PORT, source=CLI_ADDR)


def test_kernel_expires_timed_bans_without_any_daemon():
    """The ban timeout lives in the nftables set, so it survives even if we never run."""
    with Lab() as lab, lab.server(SRV_ADDR, OPEN_PORT):
        nft = NftablesBackend(runner=lab.runner(lab.srv))
        apply(nft, state())
        nft.ban(f"{CLI_ADDR}/32", ttl_seconds=2)

        assert not lab.reachable(SRV_ADDR, OPEN_PORT)
        assert "timeout" in lab.run(lab.srv, "nft", "list", "set", "inet", "averqon", "banned4").stdout

        time.sleep(2.6)
        assert lab.wait_reachable(SRV_ADDR, OPEN_PORT), "kernel did not expire the timed ban"


def test_whitelisted_source_bypasses_the_drop_policy():
    with Lab() as lab, lab.server(SRV_ADDR, OPEN_PORT), lab.server(SRV_ADDR, BLOCKED_PORT):
        lab.add_client_ip(SECOND_SOURCE)
        nft = NftablesBackend(runner=lab.runner(lab.srv))
        apply(nft, state(whitelist=[f"{CLI_ADDR}/32"]))

        assert lab.wait_reachable(SRV_ADDR, BLOCKED_PORT, source=CLI_ADDR)
        assert not lab.reachable(SRV_ADDR, BLOCKED_PORT, source=SECOND_SOURCE)


def test_blocklist_set_drops_packets():
    with Lab() as lab, lab.server(SRV_ADDR, OPEN_PORT):
        lab.add_client_ip(SECOND_SOURCE)
        assert lab.wait_reachable(SRV_ADDR, OPEN_PORT, source=CLI_ADDR), "source is not usable"
        nft = NftablesBackend(runner=lab.runner(lab.srv))
        apply(nft, state(protection=Protection(blocklists={"feed": [f"{CLI_ADDR}/32"]})))

        assert not lab.reachable(SRV_ADDR, OPEN_PORT, source=CLI_ADDR)
        assert lab.wait_reachable(SRV_ADDR, OPEN_PORT, source=SECOND_SOURCE)


def test_reject_fails_fast_while_drop_times_out():
    with Lab() as lab, lab.server(SRV_ADDR, BLOCKED_PORT):
        reject = FirewallRule(id=1, name="reject", action="reject", protocol="tcp",
                              dport=[str(BLOCKED_PORT)], priority=100)
        nft = NftablesBackend(runner=lab.runner(lab.srv))
        apply(nft, state(rules=[reject]))

        ok, elapsed, err = lab.probe(SRV_ADDR, BLOCKED_PORT, timeout=1.0)
        assert not ok
        assert elapsed < 0.8, f"reject should answer with a reset, took {elapsed:.2f}s: {err}"
        assert "refused" in err.lower()

        nft.teardown()
        apply(nft, state())  # default deny: the packet is now silently dropped
        ok, elapsed, _ = lab.probe(SRV_ADDR, BLOCKED_PORT, timeout=1.0)
        assert not ok
        assert elapsed >= 0.9, f"drop should black-hole, took {elapsed:.2f}s"


def test_failed_apply_leaves_the_previous_ruleset_enforcing():
    with Lab() as lab, lab.server(SRV_ADDR, OPEN_PORT), lab.server(SRV_ADDR, BLOCKED_PORT):
        nft = NftablesBackend(runner=lab.runner(lab.srv))
        apply(nft, state())
        assert not lab.reachable(SRV_ADDR, BLOCKED_PORT)

        with pytest.raises(BackendError):
            nft.apply("add table inet averqon\ndelete table inet averqon\ntable inet averqon "
                      "{ chain input { type filter hook input priority 0; meta bogus } }\n")

        assert not lab.reachable(SRV_ADDR, BLOCKED_PORT), "a failed apply removed the live ruleset"
        assert lab.wait_reachable(SRV_ADDR, OPEN_PORT)


def test_teardown_never_touches_foreign_tables():
    with Lab() as lab, lab.server(SRV_ADDR, OPEN_PORT):
        lab.run(lab.srv, "nft", "add", "table", "inet", "host_table")
        lab.run(lab.srv, "nft", "add", "chain", "inet", "host_table", "host_chain",
                "{ type filter hook input priority -10; }")
        nft = NftablesBackend(runner=lab.runner(lab.srv))
        apply(nft, state())

        nft.teardown()

        assert lab.run(lab.srv, "nft", "list", "table", "inet", "host_table", check=False).returncode == 0
        assert lab.run(lab.srv, "nft", "list", "table", "inet", "averqon", check=False).returncode != 0


def test_syn_rate_limit_populates_the_dynamic_set():
    with Lab() as lab, lab.server(SRV_ADDR, OPEN_PORT):
        nft = NftablesBackend(runner=lab.runner(lab.srv))
        apply(nft, state(protection=Protection(syn_rate="5/second", syn_burst=5)))

        lab.flood(SRV_ADDR, 9999, count=120)

        sets = lab.run(lab.srv, "nft", "list", "set", "inet", "averqon", "synflood4").stdout
        assert CLI_ADDR in sets, f"SYN flood source was not throttled:\n{sets}"


def test_ipv6_ban_is_enforced():
    with Lab(ipv6=True) as lab:
        if not lab.ipv6:
            pytest.skip("IPv6 is not available in this namespace")
        with lab.server("fd00:10:10::1", OPEN_PORT):
            lab.add_client_ip("fd00:10:10::11")
            assert lab.wait_reachable("fd00:10:10::1", OPEN_PORT, source="fd00:10:10::2")
            nft = NftablesBackend(runner=lab.runner(lab.srv))
            apply(nft, state(bans=[Ban(network="fd00:10:10::2/128")]))

            assert not lab.reachable("fd00:10:10::1", OPEN_PORT, source="fd00:10:10::2")
            assert lab.wait_reachable("fd00:10:10::1", OPEN_PORT, source="fd00:10:10::11")
