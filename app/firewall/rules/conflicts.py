"""Rule conflict detection: duplicates and shadowed rules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.firewall.rules.models import FirewallRule
from app.utils import validation as v


@dataclass(frozen=True)
class Conflict:
    kind: Literal["duplicate", "shadowed"]
    severity: Literal["warning", "error"]
    earlier: str
    later: str
    message: str


def _net_covers(a: str | None, b: str | None) -> bool:
    if a is None:
        return True
    if b is None:
        return False
    na, nb = v.parse_network(a), v.parse_network(b)
    return na.version == nb.version and nb.subnet_of(na)  # type: ignore[arg-type]


def _ports_cover(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> bool:
    if not a:
        return True
    if not b:
        return False
    return all(any(alo <= blo and bhi <= ahi for alo, ahi in a) for blo, bhi in b)


def covers(a: FirewallRule, b: FirewallRule) -> bool:
    """True if every packet matched by ``b`` is also matched by ``a``."""
    if a.direction != b.direction or a.rate_limit:
        return False
    if a.protocol not in ("any", b.protocol):
        return False
    if a.interface not in (None, b.interface):
        return False
    if not (_net_covers(a.source, b.source) and _net_covers(a.destination, b.destination)):
        return False
    if a.family and b.family not in (0, a.family) or (a.family and b.family == 0):
        return False
    if not (_ports_cover(a.port_intervals("sport"), b.port_intervals("sport"))
            and _ports_cover(a.port_intervals("dport"), b.port_intervals("dport"))):
        return False
    return not a.states or bool(b.states and set(b.states) <= set(a.states))


def _label(r: FirewallRule) -> str:
    return f"{r.name}#{r.id}" if r.id is not None else r.name


def find_conflicts(rules: list[FirewallRule]) -> list[Conflict]:
    """Compare enabled rules in evaluation order (priority, then id)."""
    ordered = sorted((r for r in rules if r.enabled), key=lambda r: (r.priority, r.id or 0))
    out: list[Conflict] = []
    for i, later in enumerate(ordered):
        for earlier in ordered[:i]:
            if not covers(earlier, later):
                continue
            same = earlier.action == later.action
            if same and covers(later, earlier):
                out.append(Conflict("duplicate", "warning", _label(earlier), _label(later),
                                    "rules are equivalent"))
            elif not same:
                out.append(Conflict("shadowed", "error", _label(earlier), _label(later),
                                    f"{_label(later)} ({later.action}) is never reached: "
                                    f"{_label(earlier)} ({earlier.action}) matches first"))
            else:
                out.append(Conflict("shadowed", "warning", _label(earlier), _label(later),
                                    f"{_label(later)} is redundant"))
            break
    return out
