"""Strict validators for every value that may reach a firewall backend.

These are the single choke point: backends must only receive values that have
passed through these functions, and they emit structured args (never shell).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

from app.core.errors import ValidationFailed

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

Protocol = Literal["tcp", "udp", "icmp", "icmpv6", "any"]
_PROTOCOLS = {"tcp", "udp", "icmp", "icmpv6", "any"}
_IFACE = re.compile(r"^[A-Za-z0-9_.\-@]{1,15}$")  # IFNAMSIZ-1; no whitespace/shell chars


def parse_ip(value: str) -> IPAddress:
    """Parse a single IP address; rejects CIDRs, zones and whitespace."""
    if not isinstance(value, str) or value != value.strip() or "/" in value or "%" in value:
        raise ValidationFailed("invalid IP address")
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationFailed("invalid IP address") from exc


def parse_network(value: str, *, min_prefix_v4: int = 0, min_prefix_v6: int = 0) -> IPNetwork:
    """Parse a CIDR (strict: no host bits set). Bare IPs become /32 or /128."""
    if not isinstance(value, str) or value != value.strip() or "%" in value:
        raise ValidationFailed("invalid CIDR")
    _, _, mask = value.partition("/")
    if mask and not mask.isascii() or mask and not mask.isdigit():
        raise ValidationFailed("invalid CIDR")  # reject netmask notation
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValidationFailed("invalid CIDR") from exc
    floor = min_prefix_v4 if net.version == 4 else min_prefix_v6
    if net.prefixlen < floor:
        raise ValidationFailed(f"network too broad (prefix < /{floor})")
    return net


def parse_port(value: int | str) -> int:
    """Parse a single port 1-65535."""
    try:
        if isinstance(value, bool):
            raise TypeError
        port = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValidationFailed("invalid port") from exc
    if not 1 <= port <= 65535 or str(port) != str(value):
        raise ValidationFailed("port out of range")
    return port


def parse_port_range(value: str) -> tuple[int, int]:
    """Parse ``"80"`` or ``"8000-8100"`` into an inclusive (lo, hi) tuple."""
    if not isinstance(value, str):
        raise ValidationFailed("invalid port range")
    lo_s, sep, hi_s = value.partition("-")
    lo = parse_port(lo_s)
    hi = parse_port(hi_s) if sep else lo
    if lo > hi:
        raise ValidationFailed("port range start exceeds end")
    return lo, hi


def parse_protocol(value: str) -> Protocol:
    if not isinstance(value, str) or value.lower() not in _PROTOCOLS:
        raise ValidationFailed("invalid protocol")
    return value.lower()  # type: ignore[return-value]


def parse_interface(value: str) -> str:
    """Validate a Linux interface name (max 15 chars, no shell/nft metacharacters)."""
    if not isinstance(value, str) or value in {".", ".."} or not _IFACE.fullmatch(value):
        raise ValidationFailed("invalid interface name")
    return value


def check_protocol_ports(protocol: str, has_ports: bool) -> None:
    """Ports only make sense for tcp/udp."""
    if has_ports and protocol not in {"tcp", "udp"}:
        raise ValidationFailed("ports require tcp or udp")


def normalize_ip(value: str) -> str:
    """Parse an IP and unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d) so bans match real traffic."""
    ip = parse_ip(value)
    if ip.version == 6 and ip.ipv4_mapped is not None:  # type: ignore[union-attr]
        return str(ip.ipv4_mapped)  # type: ignore[union-attr]
    return str(ip)


def is_unbannable(value: str) -> bool:
    """Addresses that must never be banned: loopback, unspecified, multicast, link-local."""
    ip = parse_ip(value)
    return ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local
