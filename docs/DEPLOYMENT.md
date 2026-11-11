# Production deployment

## 0. Before you start
- Have **out-of-band console access** (cloud console, IPMI, KVM). Firewalls can lock you out.
- Python 3.12+ and (for the dashboard) Node 20+. Ubuntu 24.04 and Fedora ship 3.12; Debian 12 and RHEL/Rocky/Alma 9 need Python 3.12 installed separately.
- Decide your admin source IP(s) and SSH port(s).

## 1. Install
    sudo ./scripts/install.sh --dry-run --admin-ip 203.0.113.5   # review what will happen
    sudo ./scripts/install.sh --admin-ip 203.0.113.5
If run over SSH the installer also whitelists your current client address and the sshd port(s) from `sshd -T`. Nothing is started yet.

## 2. Configure
Edit `/etc/averqon/averqon.yaml` (see `configs/averqon.example.yaml`). Put secrets in `/etc/averqon/averqon.env` (0600). For PostgreSQL set `database.url` to `postgresql+psycopg://…` (`pip install 'averqon[postgres]'`) and run `averqon init-db`.
Validate: `averqon config validate /etc/averqon/averqon.yaml`.

## 3. Create the first admin
    AVERQON_PASSWORD='long unique password' averqon user create admin --role admin --config /etc/averqon/averqon.yaml

## 4. Dry run, then enable
    averqon firewall apply --dry-run --config /etc/averqon/averqon.yaml     # prints the exact ruleset
    sudo systemctl enable --now averqon-executor averqon-api averqon-daemon averqon-dashboard
`--enable` on the installer does the same but refuses to run without an admin IP. Keep a second SSH session open for the first apply; connectivity is also probed automatically and rolled back on failure.

## 5. TLS
Never expose the API/dashboard over plain HTTP. Put nginx/Caddy in front (TLS 1.2+, HSTS), keep both services on `127.0.0.1`, forward to `:3000` (dashboard) and optionally `:8443/api` (API clients, Prometheus). The dashboard sets `Secure` cookies in production, so it must be served via HTTPS.

## 6. Monitoring
Prometheus scrape: `GET /api/v1/metrics` with a viewer token (`Authorization: Bearer …`). Health: `GET /api/v1/system/health` (503 when degraded).

## Upgrade / rollback / uninstall
    sudo ./scripts/upgrade.sh        # backs up config, DB and ruleset; restores on failure
    sudo ./scripts/uninstall.sh [--purge]
## Emergency recovery
Console login, then `sudo averqon-emergency-disable` (works without Python, DB or API; removes only Averqon's table/chains). Re-apply with `systemctl restart averqon-executor`.

## Distribution notes
- nftables is preferred when the kernel is ≥ 3.13 and `nft` exists; otherwise iptables (legacy or nft-backed). RHEL-family jails default to `/var/log/secure`; Debian-family to `/var/log/auth.log`. On journal-only systems set `journal_units` in the jail (e.g. `ssh`, `sshd`).
- Firewalld/ufw managing the same host: Averqon does not touch their rules, but their drops/accepts still compose with ours (netfilter evaluates every hook). Prefer disabling the other manager to avoid surprises.
