from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.core.errors import ValidationFailed
from app.firewall.policies.policy import Ban, FirewallState, Policy


def test_ban_whitelist_overlap_rejected():
    s = FirewallState(whitelist=["10.0.0.0/8"], bans=[Ban(network="10.1.2.3")])
    with pytest.raises(ValidationFailed):
        s.validate_consistency()
    FirewallState(whitelist=["10.0.0.0/8"], bans=[Ban(network="11.1.2.3")]).validate_consistency()
    FirewallState(whitelist=["2001:db8::/32"], bans=[Ban(network="10.1.2.3")]).validate_consistency()


def test_ban_everything_rejected():
    for net in ("0.0.0.0/0", "::/0"):
        with pytest.raises(ValidationFailed):
            FirewallState(bans=[Ban(network=net)]).validate_consistency()


def test_lockout_guard():
    with pytest.raises(ValidationFailed):
        FirewallState(policy=Policy(input="drop", management_ports=[])).validate_consistency()
    FirewallState(policy=Policy(input="accept", management_ports=[])).validate_consistency()


def test_bad_inputs():
    with pytest.raises(ValidationError):
        Policy(management_ports=[0])
    with pytest.raises(ValidationError):
        FirewallState(whitelist=["nope"])
    with pytest.raises(ValidationError):
        Ban(network="1.2.3.4/8")
    assert Ban(network="1.2.3.4", expires_at=datetime.now(UTC) + timedelta(1)).network == "1.2.3.4/32"
