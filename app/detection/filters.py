"""Log line filters (fail2ban-style). Each regex captures the offender in group ``ip``.

Patterns are deliberately simple/anchored on literal text to avoid catastrophic backtracking,
and input lines are length-capped before matching.
"""

from __future__ import annotations

import re

from app.core.errors import ValidationFailed
from app.utils.validation import normalize_ip

MAX_LINE = 4096
_IP = r"(?P<ip>[0-9A-Fa-f:.]{2,45})"

FILTERS: dict[str, tuple[str, list[re.Pattern[str]]]] = {
    # name -> (event kind, patterns)
    "sshd": ("ssh_auth_failure", [re.compile(p) for p in (
        rf"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?\S+ from {_IP} port \d+",
        rf"Invalid user \S* from {_IP}(?: port \d+)?",
        rf"authentication failure;.* rhost={_IP}(?:\s|$)",
        rf"Connection closed by (?:invalid user \S+ |authenticating user \S+ )?{_IP} port \d+ \[preauth\]",
        rf"maximum authentication attempts exceeded for .* from {_IP} port",
        rf"Did not receive identification string from {_IP}",
        rf"Unable to negotiate with {_IP} port",
        rf"Disconnected from (?:invalid user \S+ |authenticating user \S+ )?{_IP} port \d+ \[preauth\]",
    )]),
    "nginx-auth": ("http_auth_failure", [re.compile(p) for p in (
        rf'^{_IP} - \S+ \[[^\]]+\] "[^"]*" (?:401|403) ',
        rf'user "[^"]*": (?:password mismatch|was not found in "[^"]*"), client: {_IP}',
        rf"no user/password was provided for basic authentication, client: {_IP}",
    )]),
    "apache-auth": ("http_auth_failure", [re.compile(p) for p in (
        r"\[client (?P<ipport>[0-9A-Fa-f:.]{2,50})\].*(?:authentication failure|user \S+ not found|password mismatch)",
        rf'^{_IP} \S+ \S+ \[[^\]]+\] "[^"]*" (?:401|403) ',
    )]),
    "http-scan": ("http_scan", [re.compile(rf'^{_IP} \S+ \S+ \[[^\]]+\] "[^"]*" 404 ')]),
}


def available_filters() -> list[str]:
    return sorted(FILTERS)


def match_line(filter_name: str, line: str) -> tuple[str, str] | None:
    """Return (event_kind, normalized_ip) if ``line`` matches, else None.

    Matches whose captured address isn't a valid IP are discarded (e.g. hostnames).
    """
    kind, patterns = FILTERS[filter_name]
    line = line[:MAX_LINE]
    for pat in patterns:
        m = pat.search(line)
        if m:
            try:
                # Apache 2.4 logs "[client ADDR:PORT]"; the port is always the last ':' field.
                ipport = m.groupdict().get("ipport")
                token = ipport.rsplit(":", 1)[0] if ipport and ":" in ipport else (ipport or m.group("ip"))
                return kind, normalize_ip(token)
            except ValidationFailed:
                return None
    return None


_KERN = re.compile(r"averqon-drop: .*?SRC=(?P<src>[0-9A-Fa-f:.]{2,45}) .*?PROTO=(?P<proto>\w+)(?: .*?DPT=(?P<dpt>\d{1,5}))?")


def parse_kernel_drop(line: str) -> tuple[str, str, int | None] | None:
    """Parse a netfilter LOG line produced by our ``averqon-drop:`` prefix -> (src, proto, dport)."""
    m = _KERN.search(line[:MAX_LINE])
    if not m:
        return None
    try:
        src = normalize_ip(m["src"])
    except ValidationFailed:
        return None
    dpt = int(m["dpt"]) if m["dpt"] and 0 < int(m["dpt"]) < 65536 else None
    return src, m["proto"].lower(), dpt
