import pytest
from pydantic import ValidationError

from app.firewall.rules.conflicts import find_conflicts
from app.firewall.rules.models import FirewallRule as R


def test_normalisation():
    r = R(protocol="TCP", dport=["80-80", "8000-8100"], source="10.0.0.0/8")
    assert r.protocol == "tcp" and r.dport == ["80", "8000-8100"] and r.family == 4
    assert R(protocol="icmpv6").family == 6 and R().family == 0


@pytest.mark.parametrize("kw", [
    {"protocol": "icmp", "dport": ["1"]}, {"source": "1.2.3.4", "destination": "::1"},
    {"protocol": "icmp", "source": "::1"}, {"protocol": "icmpv6", "source": "1.2.3.4"},
    {"source": "1.2.3.4; reboot"}, {"interface": "eth0;"}, {"comment": 'x" accept #'},
    {"comment": "a\nb"}, {"rate_limit": "10/day"}, {"rate_limit": "0/second"}, {"name": "a b"},
    {"priority": 10000}, {"action": "allow"}, {"states": ["bogus"]}, {"dport": ["70000"]},
    {"protocol": "tcp", "dport": ["90-80"]}, {"extra": 1}, {"direction": "sideways"},
])
def test_invalid(kw):
    with pytest.raises(ValidationError):
        R(**kw)


def test_assignment_revalidates():
    r = R()
    with pytest.raises(ValidationError):
        r.source = "evil;"


def test_conflicts_shadow_and_duplicate():
    allow = R(id=1, name="allow", action="accept", protocol="tcp", dport=["1-1000"], priority=10)
    deny = R(id=2, name="deny", action="drop", protocol="tcp", dport=["22"], priority=20)
    dup = R(id=3, name="dup", action="accept", protocol="tcp", dport=["1-1000"], priority=30)
    red = R(id=4, name="red", action="accept", protocol="tcp", dport=["80"], priority=40)
    got = {(c.kind, c.severity, c.later) for c in find_conflicts([allow, deny, dup, red])}
    assert ("shadowed", "error", "deny#2") in got
    assert ("duplicate", "warning", "dup#3") in got
    assert ("shadowed", "warning", "red#4") in got


def test_no_false_positives():
    rules = [
        R(id=1, action="accept", protocol="tcp", dport=["22"], source="10.0.0.0/8", priority=1),
        R(id=2, action="drop", protocol="tcp", dport=["22"], priority=2),            # broader: fine
        R(id=3, action="drop", protocol="udp", dport=["22"], priority=3),            # other proto
        R(id=4, action="drop", direction="out", protocol="tcp", dport=["22"], priority=4),
        R(id=5, action="accept", protocol="tcp", dport=["80"], rate_limit="5/second", priority=5),
        R(id=6, action="drop", protocol="tcp", dport=["80"], priority=6),            # limited rule doesn't cover
        R(id=7, action="accept", protocol="tcp", source="2001:db8::/32", priority=7),
        R(id=8, action="drop", protocol="tcp", source="10.1.0.0/16", dport=["9"], enabled=False, priority=8),
    ]
    assert find_conflicts(rules) == []


def test_family_specific_not_covering_generic():
    v4 = R(id=1, action="accept", protocol="tcp", source="0.0.0.0/0", priority=1)
    both = R(id=2, action="drop", protocol="tcp", priority=2)
    assert find_conflicts([v4, both]) == []
