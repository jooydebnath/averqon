import pytest

from app.core.errors import ValidationFailed
from app.utils import validation as v


@pytest.mark.parametrize("s", ["1.2.3.4", "::1", "2001:db8::1"])
def test_ip_ok(s):
    assert str(v.parse_ip(s)) == s


@pytest.mark.parametrize("s", ["1.2.3", "1.2.3.4/32", " 1.2.3.4", "fe80::1%eth0", "a;b", "", "1.2.3.4; rm -rf /"])
def test_ip_bad(s):
    with pytest.raises(ValidationFailed):
        v.parse_ip(s)


def test_network_strict_and_floor():
    assert str(v.parse_network("10.0.0.0/8")) == "10.0.0.0/8"
    assert str(v.parse_network("1.2.3.4")) == "1.2.3.4/32"
    assert v.parse_network("2001:db8::/32").version == 6
    with pytest.raises(ValidationFailed):
        v.parse_network("10.0.0.1/8")  # host bits
    with pytest.raises(ValidationFailed):
        v.parse_network("0.0.0.0/0", min_prefix_v4=8)


@pytest.mark.parametrize("p", [1, 22, "443", 65535])
def test_port_ok(p):
    assert v.parse_port(p) == int(p)


@pytest.mark.parametrize("p", [0, 65536, -1, "x", None, True, "22 ", "0x16", "1e2"])
def test_port_bad(p):
    with pytest.raises(ValidationFailed):
        v.parse_port(p)


def test_port_range():
    assert v.parse_port_range("80") == (80, 80)
    assert v.parse_port_range("8000-8100") == (8000, 8100)
    for bad in ["90-80", "1-", "-5", "a-b", "1-2-3"]:
        with pytest.raises(ValidationFailed):
            v.parse_port_range(bad)


def test_protocol_and_ports():
    assert v.parse_protocol("TCP") == "tcp"
    with pytest.raises(ValidationFailed):
        v.parse_protocol("gre")
    with pytest.raises(ValidationFailed):
        v.check_protocol_ports("icmp", True)
    v.check_protocol_ports("tcp", True)


@pytest.mark.parametrize("n", ["eth0", "br-lan", "veth1@if2", "wg0"])
def test_iface_ok(n):
    assert v.parse_interface(n) == n


@pytest.mark.parametrize("n", ["", "a" * 16, "eth0; ls", "eth 0", "$(x)", "a\nb", "eth0}"])
def test_iface_bad(n):
    with pytest.raises(ValidationFailed):
        v.parse_interface(n)


@pytest.mark.parametrize("n", ["fe80::1%eth0", "10.0.0.0/255.0.0.0", "10.0.0.0/٨"])
def test_network_rejects_zone_and_netmask(n):
    with pytest.raises(ValidationFailed):
        v.parse_network(n)


@pytest.mark.parametrize("n", [".", ".."])
def test_iface_rejects_dot_names(n):
    with pytest.raises(ValidationFailed):
        v.parse_interface(n)


@pytest.mark.parametrize("p", [float("inf"), float("-inf"), float("nan"), 10**400])
def test_port_extreme_numbers(p):
    with pytest.raises(ValidationFailed):
        v.parse_port(p)
