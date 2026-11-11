# Security model

## Trust boundaries
| Component | Runs as | Can do |
|---|---|---|
| Executor | root, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN CAP_DAC_READ_SEARCH` | program the firewall, nothing else |
| API, daemon | `averqon`, no capabilities | read DB, call the executor's allow-listed methods |
| Dashboard | `averqon`, no capabilities | proxy to the API |

The executor socket is `0660 root:averqon`, additionally checks the peer uid (`SO_PEERCRED`) against `api.allowed_uids`, exposes only the methods in `LocalFacade.EXPORTED`, binds parameters with `inspect.signature` (unknown/missing params are rejected), and caps messages at 1 MiB.

## Privileged operations (all in the executor process)
`NftablesBackend.apply/restore/teardown/ban/unban`, `IptablesBackend.*`, `sysctl.apply_hardening` (allow-listed keys only), startup policy apply, backup directory writes. Each is documented with a `PRIVILEGED` note in its docstring.

## Input handling
- All firewall inputs pass `app/utils/validation.py` (strict CIDR without host bits, no zone IDs/netmask notation, port range checks, interface names ≤15 chars with no metacharacters, comments restricted to a safe alphabet). Rule models forbid extra fields; clients cannot supply `id`.
- No shell is ever used (`shell=False`, enforced by a static test). nft rulesets are generated from validated values only. Fuzz tests assert accepted values never contain shell/nft metacharacters.
- API validation errors report field and reason, never the submitted value.

## Authentication and authorization
- scrypt (N=2^15) password hashes, 12+ character minimum, constant-work verification for unknown users, generic failure message.
- HS256 JWT, algorithm pinned, `exp/iat/iss/jti/sub` required, 30 min default lifetime, revocation list (logout) and per-user `token_version` (bumped on role/enable/password change). **Role is read from the database on every request**, so demotion is immediate.
- Lockout after 5 failures (15 min), per-IP and per-username login rate limits, global and write rate limits (per user).
- RBAC matrix is tested for every endpoint × role. Denials are audited.
- The dashboard keeps the token in an `HttpOnly; SameSite=Strict; Secure` cookie (never in JavaScript). State-changing requests also need same-origin `Origin` and the custom `x-averqon-csrf` header. The API itself only accepts `Authorization: Bearer`, so it is not CSRF-exposed.
- `X-Forwarded-For` is ignored for rate limiting/audit (spoofable); terminate TLS and rate-limit upstream if you need real client IPs.

## Secrets
Never in the repo or YAML. `AVERQON_SECRET_KEY` and channel credentials live in `/etc/averqon/averqon.env` (0600 root). Config files readable by group/other are rejected. Logs redact `password/token/secret/api_key` values. Webhook errors never include URLs (bot tokens live in Telegram URLs).

## Outbound requests
Feeds: https only, 5 MB cap, no downgrade redirects, entries sanitized (private/reserved/overly broad networks dropped; whitelist overlaps removed). Webhooks: SSRF guard (https, no credentials in URL, DNS result must be public unless `allow_private`), redirects not followed, HMAC-SHA256 signature header. Email headers are CR/LF-sanitized.

## Auditability
`audit_log` records actor, action, target, outcome and source IP for logins, denials, user changes and every firewall mutation. IDS events store the action taken. Backups are 0600 in a 0700 directory.

## Reporting
Security issues: contact the maintainers privately; do not open public issues for vulnerabilities.
