# Testing

    pytest                      # everything (408 tests)
    pytest tests/security       # RBAC matrix, token forgery, injection, hygiene
    pytest -m integration       # namespace enforcement tests (needs root; skipped otherwise)
    ruff check . && bandit -r app cli -ll

- `tests/unit` – validators, rules, conflicts, backends (rendering + real `nft` parser), safe-apply/rollback/dead-man, jails, filters, daemon, notifications, CLI, migrations (schema must equal models).
- `tests/security` – every endpoint × role, forged/expired/alg-none tokens, lockout, rate limits, malicious rule payloads, no input echo, SQL-injection attempts, body-size limit, CORS, error leakage, hygiene checks (no `shell=True`/`eval`, subprocess only in `process.py`, systemd hardening, only the executor is root).
- Fuzzing: Hypothesis over all validators.
- The host firewall is never modified by ordinary tests; enforcement tests run inside `unshare -n` namespaces only.
