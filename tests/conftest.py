from __future__ import annotations

import pytest

from app.firewall.policies.policy import FirewallState, Policy
from app.firewall.rules.models import FirewallRule
from app.utils.process import CommandResult


class FakeNft:
    """In-memory stand-in for the nft binary: tracks one table's text."""

    def __init__(self) -> None:
        self.table: str | None = None
        self.calls: list[list[str]] = []
        self.fail_apply = 0  # fail the Nth next apply

    def __call__(self, argv, *, timeout=10.0, input_text=None):
        self.calls.append(list(argv))
        a = list(argv)
        if a[1:3] == ["-c", "-f"]:
            return CommandResult(0, "", "")
        if a[1:3] == ["-f", "-"]:
            if self.fail_apply:
                self.fail_apply -= 1
                return CommandResult(1, "", "Error: boom")
            body = input_text or ""
            self.table = None if "table inet averqon {" not in body else body.split("table inet averqon {", 1)[1]
            return CommandResult(0, "", "")
        if a[1:4] == ["list", "table", "inet"]:
            if self.table is None:
                return CommandResult(1, "", "Error: No such file or directory")
            return CommandResult(0, "table inet averqon {" + self.table, "")
        return CommandResult(0, "", "")


@pytest.fixture
def fake_nft() -> FakeNft:
    return FakeNft()


def make_state(**kw) -> FirewallState:
    rules = kw.pop("rules", [])
    return FirewallState(policy=Policy(**kw.pop("policy", {})), rules=rules, **kw)


@pytest.fixture
def sample_state() -> FirewallState:
    return make_state(
        rules=[
            FirewallRule(id=1, name="web", action="accept", protocol="tcp", dport=["80", "443", "8000-8100"], priority=100),
            FirewallRule(id=2, name="dns", action="accept", protocol="udp", dport=["53"], source="10.0.0.0/8", priority=110),
            FirewallRule(id=3, name="v6", action="drop", protocol="tcp", source="2001:db8::/32", dport=["25"], priority=120, log=True, comment="no smtp"),
            FirewallRule(id=4, name="out", direction="out", action="drop", protocol="tcp", dport=["23"], interface="eth0", states=["new"], rate_limit="5/minute"),
        ],
        whitelist=["192.0.2.10", "2001:db8:ffff::1"],
    )


@pytest.fixture(autouse=True)
def _fast_scrypt(monkeypatch):
    """Tests use a cheap scrypt cost; production keeps N=2**15 (hash strings carry their own N)."""
    import app.auth.security as sec
    monkeypatch.setattr(sec, "_N", 2**10)


@pytest.fixture
def api(tmp_path, fake_nft):
    from tests.api_helpers import make_api
    client, ctx = make_api(tmp_path, fake_nft)
    client.ctx = ctx
    client.nft = fake_nft
    return client
