# Contributing

Thanks for helping. Averqon is a security tool that runs as root on real hosts, so changes are held to a high bar on safety and testing.

## Setup
Requires Python 3.12+.

    python3 -m venv .venv && . .venv/bin/activate
    pip install -e '.[dev,server]'
    ruff check . && pytest

Dashboard (optional, Node.js):

    cd dashboard && npm ci && npm run dev

Run the API locally (development only):

    export AVERQON_SECRET_KEY=$(python -c 'import secrets;print(secrets.token_urlsafe(48))')
    averqon serve api

The firewall, executor and integration tests need Linux. On macOS/Windows use a Linux VM or container; the unit and security suites run anywhere.

## Hard rules
- **Never modify the host firewall in tests.** Enforcement tests run inside `unshare -n` network namespaces (`pytest -m integration`, needs root).
- **Every new firewall input goes through `app/utils/validation.py`.** No value reaches a backend unvalidated.
- **Only `app/utils/process.py` spawns processes** (argv lists, `shell=False`, timeouts). No `shell=True`, `eval` or `exec`; `tests/security/test_repo_hygiene.py` enforces this.
- **Only the executor runs as root.** The API and daemon stay unprivileged.
- **Never weaken anti-lockout.** Management ports, `admin_ips` and the whitelist must stay protected (see `docs/ARCHITECTURE.md`).
- **No secrets in the repo,** including test fixtures.

## Where things live
| Area | Path |
|---|---|
| Rule model, backends, sysctl | `app/firewall/` |
| Apply / rollback / dead-man | `app/services/safe_apply.py` |
| Detection filters, jails | `app/detection/` |
| IDS / IPS | `app/ids/`, `app/ips/` |
| REST API, RBAC | `app/api/`, `app/auth/` |
| CLI | `cli/main.py` |
| Dashboard | `dashboard/` |

See `docs/ARCHITECTURE.md` for the full picture and `docs/TESTING.md` for the test layout.

## Tests
- Write the test first; bug fixes need a regression test.
- Put tests in `tests/unit` (logic), `tests/security` (auth, injection, hygiene) or `tests/integration` (kernel, needs root).
- Keep coverage at or above the current level (about 95%).
- Validators should have Hypothesis coverage in `tests/security/test_fuzz.py`.

## Before opening a PR
    ruff check .
    bandit -r app cli -ll
    pytest

- [ ] Tests added or updated, and all pass
- [ ] `ruff` and `bandit` are clean
- [ ] Docs updated if behaviour or limits changed (`docs/LIMITATIONS.md` for new caveats)
- [ ] Database model changes include an Alembic migration (a test checks the schema equals the models)
- [ ] Dashboard changes build (`npm run build`)

## Commits and PRs
- Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`.
- Keep PRs focused; describe what changed, why, and how you tested it. State whether you ran integration tests on a real kernel.

## Good first areas
See the "Verification gaps", "Platform" and "Scope" sections of `docs/LIMITATIONS.md`. Running `sudo -E pytest tests/integration` on a Linux host and reporting results is especially valuable.

## Reporting vulnerabilities
Do not open a public issue. Follow `SECURITY.md`.
