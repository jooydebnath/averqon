"""Threat-intel feeds and country (GeoIP) blocklists, with poisoning safeguards.

Feeds are untrusted input: every entry is validated, private/reserved/overly-broad networks
are dropped (a poisoned feed must not be able to block the whole internet or the LAN), and
fetching is https-only with size/time limits.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from app.core.errors import ValidationFailed
from app.utils import validation as v

log = logging.getLogger(__name__)
MAX_BYTES = 5 * 1024 * 1024
MIN_PREFIX_V4, MIN_PREFIX_V6 = 8, 19
_CC = re.compile(r"^[a-z]{2}$")


@dataclass
class ParseResult:
    networks: list[str]
    rejected: int


def parse_feed(text: str, *, max_entries: int = 200_000) -> ParseResult:
    """Parse one-entry-per-line IP/CIDR feeds (supports '#', ';' comments and 'ip ; note' lines)."""
    seen: set[str] = set()
    rejected = 0
    for raw in text.splitlines():
        tok = re.split(r"[#;\s]", raw.strip(), maxsplit=1)[0]
        if not tok:
            continue
        try:
            net = v.parse_network(tok, min_prefix_v4=MIN_PREFIX_V4, min_prefix_v6=MIN_PREFIX_V6)
        except ValidationFailed:
            rejected += 1
            continue
        if net.is_private or net.is_loopback or net.is_multicast or net.is_link_local or net.is_unspecified \
                or net.is_reserved:
            rejected += 1
            continue
        seen.add(str(net))
        if len(seen) >= max_entries:
            break
    return ParseResult(sorted(seen, key=lambda n: (ipaddress.ip_network(n).version, ipaddress.ip_network(n))), rejected)


def fetch_feed(url: str, *, timeout: float = 20.0) -> str:
    """HTTPS-only download with size cap; redirects to non-https are refused."""
    if not url.startswith("https://"):
        raise ValidationFailed("feeds must use https")

    class _NoDowngrade(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
            if not newurl.startswith("https://"):
                raise ValidationFailed("redirect to non-https refused")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(_NoDowngrade)
    with opener.open(urllib.request.Request(url, headers={"User-Agent": "averqon"}), timeout=timeout) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValidationFailed("feed too large")
    return data.decode("utf-8", "replace")


class BlocklistStore:
    """Files under ``directory``: ``<name>.txt`` (0600), written atomically."""

    def __init__(self, directory: Path) -> None:
        self.dir = directory

    def save(self, name: str, networks: list[str]) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,15}", name):
            raise ValidationFailed("invalid blocklist name")
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.dir / f".{name}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(networks) + ("\n" if networks else ""))
        os.replace(tmp, self.dir / f"{name}.txt")

    def load_all(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        if not self.dir.is_dir():
            return out
        for f in sorted(self.dir.glob("*.txt")):
            if re.fullmatch(r"[a-z][a-z0-9_]{0,15}", f.stem):
                out[f.stem] = parse_feed(f.read_text()).networks
        return out

    def update_feed(self, name: str, url: str) -> int:
        res = parse_feed(fetch_feed(url))
        if not res.networks:
            raise ValidationFailed("feed produced no valid entries; keeping previous list")
        self.save(name, res.networks)
        log.info("blocklist %s updated: %d entries (%d rejected)", name, len(res.networks), res.rejected)
        return len(res.networks)

    def load_countries(self, zone_dir: Path, countries: list[str]) -> int:
        """Country blocking from ipdeny-style ``<cc>.zone`` files (4 and 6 combined by caller)."""
        total = 0
        for cc in countries:
            if not _CC.fullmatch(cc):
                raise ValidationFailed("country must be a 2-letter code")
            nets: list[str] = []
            for f in (zone_dir / f"{cc}.zone", zone_dir / f"{cc}6.zone"):
                if f.is_file():
                    nets += parse_feed(f.read_text(), max_entries=100_000).networks
            self.save(f"geo_{cc}", nets)
            total += len(nets)
        return total
