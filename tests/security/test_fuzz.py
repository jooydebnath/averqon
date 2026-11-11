"""Property/fuzz tests: validators never crash and never emit nft/shell-unsafe output."""
import string

from hypothesis import given, settings
from hypothesis import strategies as st

from app.core.errors import ValidationFailed
from app.utils import validation as v

SAFE_NET = set(string.hexdigits + ".:/")
anything = st.one_of(st.text(max_size=60), st.integers(), st.none(), st.floats(), st.binary(max_size=20))


def only_validation_error(fn, x):
    try:
        return fn(x)
    except ValidationFailed:
        return None


@settings(max_examples=500)
@given(anything)
def test_no_crash(x):
    for fn in (v.parse_ip, v.parse_network, v.parse_port, v.parse_port_range, v.parse_protocol, v.parse_interface):
        only_validation_error(fn, x)


@settings(max_examples=500)
@given(st.text(max_size=60))
def test_accepted_values_are_unsafe_char_free(x):
    ip = only_validation_error(v.parse_ip, x)
    if ip is not None:
        assert set(str(ip)) <= SAFE_NET
    net = only_validation_error(v.parse_network, x)
    if net is not None:
        assert set(str(net)) <= SAFE_NET
    iface = only_validation_error(v.parse_interface, x)
    if iface is not None:
        assert len(iface) <= 15 and not set(iface) & set(" ;|&$`\"'\\{}()<>\n\r\t\x00*")


@given(st.integers(1, 65535), st.integers(1, 65535))
def test_range_roundtrip(a, b):
    lo, hi = min(a, b), max(a, b)
    assert v.parse_port_range(f"{lo}-{hi}") == (lo, hi)
