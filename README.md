# Averqon Firewall

Linux firewall and IDS/IPS platform in Python 3.12 (nftables first, iptables compatibility), with a REST API, CLI and Next.js dashboard. It owns its own policy model, detection engine and ban lifecycle; it does not wrap UFW or Fail2ban.

> **Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md) before deploying.** Averqon reduces attack surface and automates responses; it is not DDoS protection, and packet enforcement has been verified in network namespaces and CI, not yet on a production install (see "Verification status").

## What is implemented
| Area | Status |
|---|---|
| Firewall engine: IPv4/IPv6, tcp/udp/icmp, ports and ranges, CIDR allow/block, interface rules, conntrack, default policies, priorities, conflict detection, dry-run, atomic apply, backup, rollback, dead-man confirmation | implemented |
| Backends: `NftablesBackend` (own `inet averqon` table only), `IptablesBackend` (own `AVERQON-*` chains only), capability detection per distro/kernel | implemented |
| Kernel protections: per-IP SYN rate, concurrent-connection limit, new-connection rate, ICMP rate limit, sysctl hardening (syncookies, rp_filter...) | implemented |
| IDS: sshd / nginx / apache filters, jails with maxretry/findtime/bantime, port-scan heuristic, severity, sampling, whitelist/ignore lists, audit trail | implemented |
| IPS: auto-ban with escalation, permanent bans, expiry, history, never bans loopback/link-local/admin/whitelist | implemented |
| Threat-intel feeds (https only, poisoning safeguards) and country blocklists from zone files | implemented (country data is user-supplied, no bundled GeoIP DB) |
| REST API `/api/v1`: JWT auth, RBAC (viewer/auditor/operator/admin), lockout, rate limits, validation, pagination, audit, safe errors | implemented |
| Privilege separation: unprivileged API + daemon talk to a root executor over a unix socket (SO_PEERCRED + method allow-list) | implemented |
| CLI: status, firewall status/apply/rules/harden/refresh-blocklists/emergency-disable, ip ban/unban/list, ids status/events, logs, user, backup, restore, config validate, init-db, serve | implemented |
| Dashboard: 11 pages, live event stream, filters, pagination, charts, confirm dialogs, loading/error states; httpOnly-cookie BFF with CSRF checks | implemented |
| Monitoring: CPU/RAM/disk, interface stats, connections, firewall counters, Prometheus `/api/v1/metrics`; alerts via Telegram, email, signed webhook | implemented |
| Packaging: hardened systemd units, install/upgrade/uninstall/emergency scripts, Alembic migrations | implemented |

## Verification status
- **424 automated tests**: 408 unit/API/security/fuzz tests run anywhere; 16 kernel-enforcement tests need root and run in CI's `enforcement` job. Coverage 95%; `ruff` clean; `bandit` has no medium+ findings.
- **Packet-level enforcement is verified in CI.** `tests/integration` builds two throwaway network namespaces joined by a veth pair, applies each backend through its real binaries (`nft -f -`, `iptables-restore`), and asserts that packets are *dropped, rejected, banned, whitelisted, rate-limited and un-banned* — including kernel-side TTL expiry of bans and that apply/teardown never touch foreign tables, chains or the host `INPUT` policy. Run it yourself with `sudo -E pytest -m integration tests/integration` or `./scripts/test-kernel.sh` (Docker, no host changes). `AVERQON_REQUIRE_KERNEL_TESTS=1` turns a silent skip into a failure.
- Rendered nftables rulesets are also parsed by the **real `nft` binary** (syntax) in the unit tests; apply/rollback logic is tested against an in-memory fake `nft`.
- Not verified: throughput/performance on real hardware, `iptables-legacy` (CI uses the nft-based iptables), and a real install on every distribution. `scripts/install.sh` was exercised with `--dry-run` and the units with `systemd-analyze verify`. Debian 12 and RHEL 9 ship Python < 3.12, so install 3.12+ first.

## Install
    pip install averqon            # CLI, API and daemon (Python 3.12+)
The dashboard and systemd units are not in the wheel; for a full host install use `scripts/install.sh` from this repository (see docs/DEPLOYMENT.md).

## Quick start (development)
    python3 -m venv .venv && . .venv/bin/activate
    pip install -e '.[dev,server]'
    pytest && ruff check .          # 408 tests that need no privileges
    ./scripts/test-kernel.sh        # 16 real-kernel packet tests in a throwaway container
    export AVERQON_SECRET_KEY=$(python -c 'import secrets;print(secrets.token_urlsafe(48))')
    AVERQON_PASSWORD='a-long-password' averqon user create admin --role admin
    averqon serve api              # http://127.0.0.1:8443/docs (development only)
    cd dashboard && npm ci && AVERQON_API_URL=http://127.0.0.1:8443 AVERQON_INSECURE_COOKIES=1 npm run dev

## Production
See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). In short: `sudo ./scripts/install.sh --admin-ip <your IP>`, review `/etc/averqon/averqon.yaml`, create an admin, then enable the services. Recovery at any time: `sudo averqon-emergency-disable`.

## Documentation
[Architecture](docs/ARCHITECTURE.md) · [Security model](docs/SECURITY.md) · [Deployment](docs/DEPLOYMENT.md) · [Limitations](docs/LIMITATIONS.md) · [Testing](docs/TESTING.md)

## License
Apache-2.0
