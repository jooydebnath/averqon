from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from starlette.requests import Request

from app.api.deps import client_ip
from app.core.config import ApiSettings


def make_request(peer: str | None, xff: str | None, proxies: list[str]) -> Request:
    settings = SimpleNamespace(api=ApiSettings(trusted_proxies=proxies))
    app = SimpleNamespace(state=SimpleNamespace(ctx=SimpleNamespace(settings=settings)))
    headers = [(b"x-forwarded-for", xff.encode())] if xff is not None else []
    scope = {"type": "http", "headers": headers, "client": (peer, 1234) if peer else None, "app": app}
    return Request(scope)


@pytest.mark.parametrize(("peer", "xff", "proxies", "expected"), [
    # default: no trusted proxies -> header is attacker-controlled, always ignored
    ("198.51.100.1", "203.0.113.9", [], "198.51.100.1"),
    # peer is not a trusted proxy -> header ignored (spoofing attempt from a direct client)
    ("198.51.100.1", "203.0.113.9", ["10.0.0.1"], "198.51.100.1"),
    # trusted proxy, single hop
    ("10.0.0.1", "203.0.113.9", ["10.0.0.1"], "203.0.113.9"),
    # client-supplied leftmost entries must not win: take the rightmost untrusted hop
    ("10.0.0.1", "6.6.6.6, 203.0.113.9", ["10.0.0.1"], "203.0.113.9"),
    # chain through several trusted proxies (CIDR)
    ("10.0.0.1", "203.0.113.9, 10.0.0.2", ["10.0.0.0/24"], "203.0.113.9"),
    # IPv6 client behind a trusted proxy
    ("10.0.0.1", "2001:db8::5", ["10.0.0.1"], "2001:db8::5"),
    # IPv4-mapped IPv6 peer still matches an IPv4 trusted proxy
    ("::ffff:10.0.0.1", "203.0.113.9", ["10.0.0.1"], "203.0.113.9"),
    # missing / garbage / empty header -> fall back to the connecting peer
    ("10.0.0.1", None, ["10.0.0.1"], "10.0.0.1"),
    ("10.0.0.1", "not-an-ip", ["10.0.0.1"], "10.0.0.1"),
    ("10.0.0.1", "203.0.113.9, garbage", ["10.0.0.1"], "10.0.0.1"),
    ("10.0.0.1", "", ["10.0.0.1"], "10.0.0.1"),
    # every hop trusted -> nothing better than the peer
    ("10.0.0.1", "10.0.0.2", ["10.0.0.0/24"], "10.0.0.1"),
])
def test_client_ip(peer, xff, proxies, expected):
    assert client_ip(make_request(peer, xff, proxies)) == expected


def test_client_ip_without_peer():
    assert client_ip(make_request(None, "203.0.113.9", ["10.0.0.1"])) == "unknown"


@pytest.mark.parametrize("bad", ["nope", "10.0.0.1/33", "0.0.0.0/0", "::/0", "10.0.0.1; drop", ""])
def test_trusted_proxies_validated(bad):
    with pytest.raises(ValidationError):
        ApiSettings(trusted_proxies=[bad])


def test_trusted_proxies_default_is_empty():
    assert ApiSettings().trusted_proxies == []
