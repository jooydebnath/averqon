# Architecture

```
 browser ──HTTPS──> reverse proxy ──> Next.js dashboard (BFF: httpOnly cookie, CSRF checks)
                                          │ Bearer JWT
 CLI / Prometheus / scripts ───────────> REST API (unprivileged, user averqon)
                                          │                         ▲ reads DB (events, audit, users)
 Detection daemon (unprivileged) ─────────┤ unix socket /run/averqon/executor.sock (0660, SO_PEERCRED)
   log tail / journald → jails → IDS → IPS ▼
                                   Executor (root, bounded capabilities)  ── nft -f - / iptables-restore
                                          │                                   (own table / own chains only)
                                          └── SQLite/PostgreSQL (rules, bans, whitelist, audit)
```

## Layers
- `app/utils/validation.py` – the single choke point for every value that can reach a backend (IP, CIDR, port, interface, protocol). `app/utils/process.py` is the only place that spawns processes: argv lists, `shell=False`, timeouts.
- `app/firewall/` – rule model (`rules/`), policy and desired state (`policies/`), `FirewallBackend` ABC with `NftablesBackend` and `IptablesBackend`, capability detection, sysctl hardening.
- `app/services/safe_apply.py` – validate → conflict check → backup → atomic apply → connectivity check → rollback; dead-man confirmation; emergency teardown.
- `app/services/firewall_manager.py` – DB is the source of truth; the firewall is derived. Every mutation is one DB transaction that commits only if the kernel change succeeded.
- `app/services/facade.py` – JSON-friendly interface; the API, daemon and executor all use it (in-process in development, over the socket in production).
- `app/detection/`, `app/ids/`, `app/ips/` – filters, sliding windows, jails, port-scan heuristic → event store and audit trail → escalating bans.
- `app/api/` – FastAPI app, RBAC, rate limiting, safe error handling. `app/auth/` – scrypt hashing, HS256 JWT, role map.
- `app/notifications/`, `app/monitoring/` – channels, dedupe, retries, Prometheus text, resource alerts.

## Key design decisions
1. **Dedicated, owned objects.** nftables: `inet averqon`. iptables: `AVERQON-IN/OUT`. Host rules are never flushed or modified; teardown removes only ours.
2. **One atomic file.** nft applies `add table; delete table; table {…}` as a single transaction, so there is no window with a half-built ruleset. iptables uses `iptables-restore --noflush`, atomic per family; a failure on the second family tears both down.
3. **Evaluation order inside the input chain:** established/related → invalid drop → loopback → whitelist → bans → blocklists → SYN/conn limits → management ports → ICMP → user rules → optional drop log → policy. Whitelist and management access therefore cannot be shadowed by user rules or limits.
4. **Anti-lockout is structural:** management ports and `admin_ips` are rendered unconditionally; bans overlapping the whitelist are refused; `0.0.0.0/0` bans are refused; an input `drop` policy with no management port is refused; applies are rolled back on connectivity-check failure.
5. **Kernel rules do not survive reboot,** so the executor re-applies the stored policy at startup.
