# Testing

    pytest                      # 408 tests that run anywhere (263 unit + 145 security)
    pytest tests/security       # RBAC matrix, token forgery, injection, hygiene
    pytest -m integration       # 16 packet-level kernel tests (needs root; skipped otherwise)
    ./scripts/test-kernel.sh    # same, inside a throwaway --privileged container (no host changes)
    ruff check . && bandit -r app cli -ll

- `tests/unit` – validators, rules, conflicts, backends (rendering + real `nft` parser), safe-apply/rollback/dead-man, jails, filters, daemon, notifications, CLI, migrations (schema must equal models).
- `tests/security` – every endpoint × role, forged/expired/alg-none tokens, lockout, rate limits, malicious rule payloads, no input echo, SQL-injection attempts, body-size limit, CORS, error leakage, hygiene checks (no `shell=True`/`eval`, subprocess only in `process.py`, systemd hardening, only the executor is root).
- `tests/integration` – real kernels: two namespaces joined by a veth pair, firewall applied to one side, traffic generated from the other (`probe.py`). Asserts packets are dropped, rejected (fast RST), banned per source, un-banned, whitelisted, SYN-rate-limited, and that timed bans expire **in the kernel** with no daemon running. Also checks that teardown leaves foreign nft tables, host iptables chains and the host `INPUT` policy untouched. `tests/integration/Dockerfile` + `scripts/test-kernel.sh` make this reproducible on any machine with Docker.
- Fuzzing: Hypothesis over all validators.
- The host firewall is never modified by ordinary tests; enforcement tests only touch namespaces they create and delete (`NetnsError`/skip if the kernel cannot provide them).
- Set `AVERQON_REQUIRE_KERNEL_TESTS=1` in CI to fail instead of silently skipping when namespaces are unavailable (already set in `scripts/test-kernel.sh` and the `enforcement` job).
