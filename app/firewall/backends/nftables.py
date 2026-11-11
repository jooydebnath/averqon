"""nftables backend. Owns exactly one table: ``inet <table_name>``."""

from __future__ import annotations

import logging
import re

from app.core.errors import BackendError
from app.firewall.backends.base import FirewallBackend, Runner
from app.firewall.policies.policy import Ban, FirewallState
from app.firewall.rules.models import FirewallRule
from app.utils import validation as v
from app.utils.process import run_command

log = logging.getLogger(__name__)
_TABLE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


def _ports(items: list[str]) -> str:
    return "{ " + ", ".join(items) + " }"


class NftablesBackend(FirewallBackend):
    name = "nftables"

    def __init__(self, table: str = "averqon", nft: str = "nft", runner: Runner = run_command) -> None:
        super().__init__(runner)
        if not _TABLE.fullmatch(table):
            raise BackendError("invalid table name")
        self.table, self.nft = table, nft

    # ---------------------------------------------------------------- rendering
    def _rule(self, r: FirewallRule) -> str:
        p: list[str] = []
        if r.interface:
            p.append(f'{"iifname" if r.direction == "in" else "oifname"} "{r.interface}"')
        for kw, net in (("saddr", r.source), ("daddr", r.destination)):
            if net:
                p.append(f"{'ip6' if v.parse_network(net).version == 6 else 'ip'} {kw} {net}")
        if r.protocol in ("tcp", "udp"):
            if r.sport or r.dport:
                if r.sport:
                    p.append(f"{r.protocol} sport {_ports(r.sport)}")
                if r.dport:
                    p.append(f"{r.protocol} dport {_ports(r.dport)}")
            else:
                p.append(f"meta l4proto {r.protocol}")
        elif r.protocol in ("icmp", "icmpv6"):
            p.append(f"meta l4proto {'icmp' if r.protocol == 'icmp' else 'ipv6-icmp'}")
        if r.states:
            p.append("ct state { " + ", ".join(r.states) + " }")
        if r.rate_limit:
            p.append(f"limit rate {r.rate_limit}")
        if r.log:
            p.append('log prefix "averqon: "')
        p.append("counter")
        p.append(r.action)
        comment = f' comment "{r.comment}"' if r.comment else ""
        return " ".join(p) + comment

    @staticmethod
    def _elements(items: list[Ban], version: int) -> str:
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        out = []
        for b in items:
            net = v.parse_network(b.network)
            if net.version != version:
                continue
            if b.expires_at is None:
                out.append(str(net))
            else:
                left = int((b.expires_at - now).total_seconds())
                if left > 0:
                    out.append(f"{net} timeout {left}s")
        return f"elements = {{ {', '.join(out)} }}" if out else ""

    def _set(self, name: str, version: int, items: list[Ban]) -> str:
        typ = "ipv4_addr" if version == 4 else "ipv6_addr"
        flags = "interval, timeout" if name.startswith("banned") else "interval"
        return f"  set {name} {{ type {typ}; flags {flags}; {self._elements(items, version)} }}"

    def render(self, state: FirewallState) -> str:
        state.validate_consistency()
        pol = state.policy
        wl = [Ban(network=n) for n in state.whitelist]
        t = self.table
        lines = [
            f"add table inet {t}", f"delete table inet {t}", f"table inet {t} {{",
            self._set("whitelist4", 4, wl), self._set("whitelist6", 6, wl),
            self._set("banned4", 4, state.bans), self._set("banned6", 6, state.bans),
        ]
        prot = state.protection
        for ver, typ in ((4, "ipv4_addr"), (6, "ipv6_addr")):
            if prot.syn_rate:
                lines.append(f"  set synflood{ver} {{ type {typ}; flags dynamic, timeout; timeout 1m; size 65535; }}")
            if prot.conn_limit_per_ip:
                lines.append(f"  set connlimit{ver} {{ type {typ}; flags dynamic; size 65535; }}")
            if prot.new_conn_rate_per_ip:
                lines.append(f"  set connrate{ver} {{ type {typ}; flags dynamic, timeout; timeout 1m; size 65535; }}")
            for name, nets in sorted(prot.blocklists.items()):
                els = ", ".join(n for n in nets if v.parse_network(n).version == ver)
                body = f" elements = {{ {els} }}" if els else ""
                lines.append(f"  set bl_{name}{ver} {{ type {typ}; flags interval;{body} }}")
        for chain, hook, default in (("input", "input", pol.input), ("output", "output", pol.output),
                                     ("forward", "forward", pol.forward)):
            direction = {"input": "in", "output": "out"}.get(chain)
            lines.append(f"  chain {chain} {{")
            lines.append(f"    type filter hook {hook} priority 0; policy {default};")
            lines.append("    ct state established,related accept")
            lines.append("    ct state invalid drop")
            if chain == "input":
                lines.append('    iifname "lo" accept')
                lines.append("    ip saddr @whitelist4 accept")
                lines.append("    ip6 saddr @whitelist6 accept")
                lines.append("    ip saddr @banned4 counter drop")
                lines.append("    ip6 saddr @banned6 counter drop")
                for name in sorted(prot.blocklists):
                    lines.append(f"    ip saddr @bl_{name}4 counter drop")
                    lines.append(f"    ip6 saddr @bl_{name}6 counter drop")
                for ver, sel in ((4, "ip"), (6, "ip6")):
                    if prot.syn_rate:
                        lines.append(f"    tcp flags & (fin|syn|rst|ack) == syn add @synflood{ver} "
                                     f"{{ {sel} saddr limit rate over {prot.syn_rate} burst {prot.syn_burst} packets }} counter drop")
                    if prot.new_conn_rate_per_ip:
                        lines.append(f"    ct state new add @connrate{ver} "
                                     f"{{ {sel} saddr limit rate over {prot.new_conn_rate_per_ip} }} counter drop")
                    if prot.conn_limit_per_ip:
                        lines.append(f"    ct state new add @connlimit{ver} "
                                     f"{{ {sel} saddr ct count over {prot.conn_limit_per_ip} }} counter drop")
                if pol.management_ports:
                    lines.append(f"    tcp dport {_ports([str(p) for p in pol.management_ports])} accept")
                if pol.allow_ping:
                    lim = f" limit rate {pol.icmp_rate_limit}" if pol.icmp_rate_limit else ""
                    lines.append(f"    meta l4proto icmp{lim} accept")
                    lines.append(f"    meta l4proto ipv6-icmp{lim} accept")
            elif chain == "output":
                lines.append('    oifname "lo" accept')
                lines.append("    ip daddr @banned4 counter drop")
                lines.append("    ip6 daddr @banned6 counter drop")
            if direction:
                for r in sorted((x for x in state.rules if x.enabled and x.direction == direction),
                                key=lambda x: (x.priority, x.id or 0)):
                    lines.append("    " + self._rule(r))
            if chain == "input" and prot.log_drops and default == "drop":
                lines.append('    limit rate 10/second burst 20 packets log prefix "averqon-drop: "')
            lines.append("  }")
        lines.append("}")
        return "\n".join(lines) + "\n"

    # ---------------------------------------------------------------- execution
    def check(self, ruleset: str) -> None:
        res = self._exec([self.nft, "-c", "-f", "-"], ruleset)
        if res.returncode != 0:
            # Without CAP_NET_ADMIN nft still parses; only the kernel cache step fails.
            if "Operation not permitted" in res.stderr and "syntax error" not in res.stderr:
                return
            raise BackendError(f"nft rejected ruleset: {res.stderr.strip()[:300]}")

    def apply(self, ruleset: str) -> None:
        res = self._exec([self.nft, "-f", "-"], ruleset)
        if res.returncode != 0:
            raise BackendError(f"nft apply failed: {res.stderr.strip()[:300]}")

    def export(self) -> str | None:
        res = self._exec([self.nft, "list", "table", "inet", self.table])
        if res.returncode != 0:
            return None  # table absent
        return f"add table inet {self.table}\ndelete table inet {self.table}\n{res.stdout}"

    def restore(self, snapshot: str | None) -> None:
        if snapshot is None:
            self.teardown()
        else:
            self.apply(snapshot)

    def teardown(self) -> None:
        self.apply(f"add table inet {self.table}\ndelete table inet {self.table}\n")

    def ban(self, network: str, ttl_seconds: int | None) -> None:
        net = v.parse_network(network)
        if net.prefixlen == 0:
            raise BackendError("refusing to ban the whole address space")
        ttl = f" timeout {int(ttl_seconds)}s" if ttl_seconds else ""
        res = self._exec([self.nft, "add", "element", "inet", self.table, f"banned{net.version}",
                          f"{{ {net}{ttl} }}"])
        if res.returncode != 0:
            raise BackendError(f"ban failed: {res.stderr.strip()[:200]}")

    def unban(self, network: str) -> None:
        net = v.parse_network(network)
        res = self._exec([self.nft, "delete", "element", "inet", self.table, f"banned{net.version}",
                          f"{{ {net} }}"])
        if res.returncode != 0 and "No such file" not in res.stderr:
            raise BackendError(f"unban failed: {res.stderr.strip()[:200]}")

    def counters(self) -> dict[str, int]:
        res = self._exec([self.nft, "-j", "list", "table", "inet", self.table])
        if res.returncode != 0:
            return {}
        import json

        packets = bytes_ = 0
        try:
            for item in json.loads(res.stdout).get("nftables", []):
                for expr in item.get("rule", {}).get("expr", []):
                    if "counter" in expr:
                        packets += int(expr["counter"]["packets"])
                        bytes_ += int(expr["counter"]["bytes"])
        except (ValueError, KeyError, TypeError, AttributeError):
            log.warning("could not parse nft counters")
            return {}
        return {"packets": packets, "bytes": bytes_}
