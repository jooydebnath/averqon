"""iptables compatibility backend. Owns only the AVERQON-* user chains."""

from __future__ import annotations

from datetime import UTC, datetime

from app.core.errors import BackendError
from app.firewall.backends.base import FirewallBackend, Runner
from app.firewall.policies.policy import FirewallState
from app.firewall.rules.models import FirewallRule
from app.utils import validation as v
from app.utils.process import run_command

CHAINS = {"in": ("INPUT", "AVERQON-IN"), "out": ("OUTPUT", "AVERQON-OUT")}


class IptablesBackend(FirewallBackend):
    """Renders two ``iptables-restore --noflush`` payloads (v4 then v6).

    Live bans are individual rules, since ipset is not guaranteed to exist. The host's
    INPUT/OUTPUT policies are never changed: the default policy is a terminal rule in
    our own chain.
    """

    name = "iptables"

    def __init__(self, iptables: str = "iptables", ip6tables: str = "ip6tables",
                 restore: str = "iptables-restore", restore6: str = "ip6tables-restore",
                 save: str = "iptables-save", save6: str = "ip6tables-save",
                 runner: Runner = run_command) -> None:
        super().__init__(runner)
        self.bin = {4: iptables, 6: ip6tables}
        self.restore_bin = {4: restore, 6: restore6}
        self.save_bin = {4: save, 6: save6}

    @staticmethod
    def _rule(r: FirewallRule, ver: int) -> str | None:
        if r.family not in (0, ver):
            return None
        p: list[str] = []
        if r.interface:
            p += ["-i" if r.direction == "in" else "-o", r.interface]
        if r.source:
            p += ["-s", r.source]
        if r.destination:
            p += ["-d", r.destination]
        proto = {"icmp": "icmp", "icmpv6": "ipv6-icmp"}.get(r.protocol, r.protocol)
        if proto != "any":
            p += ["-p", proto]
        for flag, ports in (("--sport", r.sport), ("--dport", r.dport)):
            if ports:
                p += ["-m", "multiport", flag + "s", ",".join(x.replace("-", ":") for x in ports)]
        if r.states:
            p += ["-m", "conntrack", "--ctstate", ",".join(s.upper() for s in r.states)]
        if r.rate_limit:
            p += ["-m", "limit", "--limit", r.rate_limit]
        if r.log:
            p += ["-j", "LOG", "--log-prefix", "averqon: "]
            return " ".join(_q(x) for x in p)  # logging rule only; action added below by caller
        target = {"accept": "ACCEPT", "drop": "DROP", "reject": "REJECT"}[r.action]
        return " ".join(_q(x) for x in p + ["-j", target])

    def _render_family(self, state: FirewallState, ver: int) -> str:
        pol = state.policy
        now = datetime.now(UTC)
        out = ["*filter"]
        for _, chain in CHAINS.values():
            out.append(f":{chain} - [0:0]")
        for d, (_, chain) in CHAINS.items():
            add = lambda s, c=chain: out.append(f"-A {c} {s}")
            add("-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
            add("-m conntrack --ctstate INVALID -j DROP")
            if d == "in":
                add("-i lo -j ACCEPT")
                for w in state.whitelist:
                    if v.parse_network(w).version == ver:
                        add(f"-s {w} -j ACCEPT")
            else:
                add("-o lo -j ACCEPT")
            for b in state.bans:
                net = v.parse_network(b.network)
                if net.version != ver or (b.expires_at and b.expires_at <= now):
                    continue
                add(f"{'-s' if d == 'in' else '-d'} {net} -j DROP")
            if d == "in":
                mask = 32 if ver == 4 else 128
                for name, nets in sorted(state.protection.blocklists.items()):
                    for n in nets:
                        if v.parse_network(n).version == ver:
                            add(f"-s {n} -j DROP")
                prot = state.protection
                if prot.syn_rate:
                    add(f"-p tcp --syn -m hashlimit --hashlimit-above {prot.syn_rate.replace('second', 'sec')} "
                        f"--hashlimit-burst {prot.syn_burst} --hashlimit-mode srcip --hashlimit-name syn{ver} -j DROP")
                if prot.new_conn_rate_per_ip:
                    add(f"-m conntrack --ctstate NEW -m hashlimit --hashlimit-above "
                        f"{prot.new_conn_rate_per_ip.replace('second', 'sec')} --hashlimit-mode srcip "
                        f"--hashlimit-name rate{ver} -j DROP")
                if prot.conn_limit_per_ip:
                    add(f"-p tcp -m connlimit --connlimit-above {prot.conn_limit_per_ip} --connlimit-mask {mask} -j DROP")
                if pol.management_ports:
                    add("-p tcp -m multiport --dports " + ",".join(map(str, pol.management_ports)) + " -j ACCEPT")
                if pol.allow_ping:
                    lim = f" -m limit --limit {pol.icmp_rate_limit}" if pol.icmp_rate_limit else ""
                    add(f"-p {'icmp' if ver == 4 else 'ipv6-icmp'}{lim} -j ACCEPT")
            for r in sorted((x for x in state.rules if x.enabled and x.direction == d),
                            key=lambda x: (x.priority, x.id or 0)):
                line = self._rule(r, ver)
                if line is None:
                    continue
                if r.log:
                    add(line)
                    line = self._rule(r.model_copy(update={"log": False}), ver) or ""
                add(line)
            if d == "in" and state.protection.log_drops and pol.input == "drop":
                add('-m limit --limit 10/sec --limit-burst 20 -j LOG --log-prefix "averqon-drop: "')
            if (pol.input if d == "in" else pol.output) == "drop":
                add("-j DROP")
        out.append("COMMIT")
        return "\n".join(out) + "\n"

    def render(self, state: FirewallState) -> str:
        state.validate_consistency()
        if sum(len(n) for n in state.protection.blocklists.values()) > 2000:
            raise BackendError("blocklists too large for the iptables backend (no ipset); use nftables")
        return "#v4\n" + self._render_family(state, 4) + "#v6\n" + self._render_family(state, 6)

    @staticmethod
    def _split(ruleset: str) -> dict[int, str]:
        v4, _, v6 = ruleset.partition("#v6\n")
        return {4: v4.removeprefix("#v4\n"), 6: v6}

    def check(self, ruleset: str) -> None:
        for ver, body in self._split(ruleset).items():
            res = self._exec([self.restore_bin[ver], "--test", "--noflush"], body)
            if res.returncode != 0 and "Permission denied" not in res.stderr and "Operation not permitted" not in res.stderr:
                raise BackendError(f"iptables rejected v{ver} ruleset: {res.stderr.strip()[:300]}")

    def _ensure_jumps(self, ver: int) -> None:
        for base, chain in CHAINS.values():
            if self._exec([self.bin[ver], "-C", base, "-j", chain]).returncode != 0:
                res = self._exec([self.bin[ver], "-I", base, "1", "-j", chain])
                if res.returncode != 0:
                    raise BackendError(f"cannot hook {chain}: {res.stderr.strip()[:200]}")

    def apply(self, ruleset: str) -> None:
        applied = []
        try:
            for ver, body in self._split(ruleset).items():
                res = self._exec([self.restore_bin[ver], "--noflush"], body)
                if res.returncode != 0:
                    raise BackendError(f"iptables-restore v{ver} failed: {res.stderr.strip()[:300]}")
                applied.append(ver)
                self._ensure_jumps(ver)
        except BackendError:
            if applied:  # v4 applied but v6 failed: keep both families consistent
                self.teardown()
            raise

    def export(self) -> str | None:
        parts, found = [], False
        for ver in (4, 6):
            res = self._exec([self.save_bin[ver], "-t", "filter"])
            if res.returncode != 0:
                return None
            body = [ln for ln in res.stdout.splitlines()
                    if ln.startswith((":AVERQON", "-A AVERQON")) or ln in ("*filter", "COMMIT")]
            found = found or any(ln.startswith(":AVERQON") for ln in body)
            parts.append(f"#v{ver}\n" + "\n".join(body) + "\n")
        return "".join(parts) if found else None

    def restore(self, snapshot: str | None) -> None:
        if snapshot is None:
            self.teardown()
        else:
            self.apply(snapshot)

    def teardown(self) -> None:
        for ver in (4, 6):
            for base, chain in CHAINS.values():
                while self._exec([self.bin[ver], "-D", base, "-j", chain]).returncode == 0:
                    pass
                self._exec([self.bin[ver], "-F", chain])
                self._exec([self.bin[ver], "-X", chain])

    def ban(self, network: str, ttl_seconds: int | None) -> None:
        net = v.parse_network(network)
        if net.prefixlen == 0:
            raise BackendError("refusing to ban the whole address space")
        res = self._exec([self.bin[net.version], "-I", "AVERQON-IN", "3", "-s", str(net), "-j", "DROP"])
        if res.returncode != 0:
            raise BackendError(f"ban failed: {res.stderr.strip()[:200]}")
        # TTL expiry for iptables is enforced by the ban manager (Phase 5), not the kernel.

    def unban(self, network: str) -> None:
        net = v.parse_network(network)
        self._exec([self.bin[net.version], "-D", "AVERQON-IN", "-s", str(net), "-j", "DROP"])

    def counters(self) -> dict[str, int]:
        packets = bytes_ = 0
        for ver in (4, 6):
            res = self._exec([self.bin[ver], "-L", "AVERQON-IN", "-n", "-v", "-x"])
            for ln in res.stdout.splitlines()[2:]:
                cols = ln.split()
                if len(cols) > 1 and cols[0].isdigit():
                    packets, bytes_ = packets + int(cols[0]), bytes_ + int(cols[1])
        return {"packets": packets, "bytes": bytes_}


def _q(s: str) -> str:
    import shlex

    return shlex.quote(s)
