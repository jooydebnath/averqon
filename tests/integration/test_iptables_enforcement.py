"""Real ``iptables-restore``/``ip6tables-restore`` runs against a live kernel.

Same veth lab as ``test_netns_enforcement.py``; the backend drives the real
binaries (``iptables-nft`` on modern distros) inside the protected namespace.
"""

from __future__ import annotations

import pytest

from app.firewall.backends.iptables import IptablesBackend
from app.firewall.policies.policy import Ban, FirewallState, Policy
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
    kwargs.setdefault("policy", Policy(input="drop", management_ports=[OPEN_PORT]))
    return FirewallState(**kwargs)


def apply(ipt: IptablesBackend, wanted: FirewallState) -> None:
    ruleset = ipt.render(wanted)
    ipt.check(ruleset)
    ipt.apply(ruleset)


def test_iptables_backend_enforces_with_real_restore():
    with Lab() as lab, lab.server(SRV_ADDR, OPEN_PORT), lab.server(SRV_ADDR, BLOCKED_PORT):
        ipt = IptablesBackend(runner=lab.runner(lab.srv))
        apply(ipt, state())

        assert lab.wait_reachable(SRV_ADDR, OPEN_PORT), "management port must stay reachable"
        assert not lab.reachable(SRV_ADDR, BLOCKED_PORT)
        assert ipt.counters().get("packets", 0) >= 1

        ipt.teardown()
        assert lab.wait_reachable(SRV_ADDR, BLOCKED_PORT)


def test_iptables_ban_is_per_source_and_unban_restores():
    with Lab() as lab, lab.server(SRV_ADDR, OPEN_PORT):
        lab.add_client_ip(SECOND_SOURCE)
        assert lab.wait_reachable(SRV_ADDR, OPEN_PORT, source=CLI_ADDR), "source is not usable"
        ipt = IptablesBackend(runner=lab.runner(lab.srv))
        apply(ipt, state(bans=[Ban(network=f"{CLI_ADDR}/32")]))

        assert not lab.reachable(SRV_ADDR, OPEN_PORT, source=CLI_ADDR)
        assert lab.wait_reachable(SRV_ADDR, OPEN_PORT, source=SECOND_SOURCE)

        ipt.unban(f"{CLI_ADDR}/32")
        assert lab.wait_reachable(SRV_ADDR, OPEN_PORT, source=CLI_ADDR)


def test_iptables_apply_is_idempotent_and_hooks_are_added_once():
    with Lab() as lab, lab.server(SRV_ADDR, OPEN_PORT):
        ipt = IptablesBackend(runner=lab.runner(lab.srv))
        apply(ipt, state())
        first = lab.run(lab.srv, "iptables", "-S", "AVERQON-IN").stdout
        apply(ipt, state())
        second = lab.run(lab.srv, "iptables", "-S", "AVERQON-IN").stdout

        assert first == second, f"re-apply duplicated rules:\n{first}\n---\n{second}"
        rules = lab.run(lab.srv, "iptables", "-S", "INPUT").stdout
        assert rules.count("-j AVERQON-IN") == 1, rules


def test_iptables_teardown_leaves_host_rules_and_policy_untouched():
    with Lab() as lab, lab.server(SRV_ADDR, OPEN_PORT), lab.server(SRV_ADDR, BLOCKED_PORT):
        lab.run(lab.srv, "iptables", "-N", "HOSTCHAIN")
        lab.run(lab.srv, "iptables", "-A", "HOSTCHAIN", "-p", "tcp",
                "--dport", str(BLOCKED_PORT), "-j", "ACCEPT")
        lab.run(lab.srv, "iptables", "-I", "INPUT", "1", "-j", "HOSTCHAIN")
        lab.run(lab.srv, "iptables", "-A", "HOSTCHAIN", "-j", "DROP")  # proves ordering matters

        ipt = IptablesBackend(runner=lab.runner(lab.srv))
        apply(ipt, state())
        ipt.teardown()

        listing = lab.run(lab.srv, "iptables", "-S").stdout
        assert "-N HOSTCHAIN" in listing
        assert "-j HOSTCHAIN" in listing
        assert "AVERQON-IN" not in listing and "AVERQON-OUT" not in listing
        assert "-P INPUT ACCEPT" in listing, "host INPUT policy must never change"

        # The host's own accept rule still works after we are gone.
        assert lab.wait_reachable(SRV_ADDR, BLOCKED_PORT)


def test_iptables_reject_rule_answers_with_reset():
    with Lab() as lab, lab.server(SRV_ADDR, BLOCKED_PORT):
        rule = FirewallRule(id=1, name="reject", action="reject", protocol="tcp",
                            dport=[str(BLOCKED_PORT)], priority=100)
        ipt = IptablesBackend(runner=lab.runner(lab.srv))
        apply(ipt, state(rules=[rule]))

        ok, elapsed, err = lab.probe(SRV_ADDR, BLOCKED_PORT, timeout=1.0)
        assert not ok and elapsed < 0.8 and "refused" in err.lower(), (elapsed, err)


def test_ip6tables_ban_is_enforced():
    with Lab(ipv6=True) as lab:
        if not lab.ipv6:
            pytest.skip("IPv6 is not available in this namespace")
        with lab.server("fd00:10:10::1", OPEN_PORT):
            lab.add_client_ip("fd00:10:10::11")
            assert lab.wait_reachable("fd00:10:10::1", OPEN_PORT, source="fd00:10:10::2")
            ipt = IptablesBackend(runner=lab.runner(lab.srv))
            apply(ipt, state(bans=[Ban(network="fd00:10:10::2/128")]))

            assert not lab.reachable("fd00:10:10::1", OPEN_PORT, source="fd00:10:10::2")
            assert lab.wait_reachable("fd00:10:10::1", OPEN_PORT, source="fd00:10:10::11")
