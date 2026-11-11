from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.database.base import session_scope
from app.database.models import AuditLogEntry, UserRow
from tests.api_helpers import PASSWORD, ROLES, auth, login, make_api

RULE = {"name": "web", "action": "accept", "protocol": "tcp", "dport": ["80"]}

# (method, path, json, minimum role that is allowed)
ENDPOINTS = [
    ("GET", "/api/v1/status", None, "viewer"),
    ("GET", "/api/v1/system/health", None, "viewer"),
    ("GET", "/api/v1/firewall/rules", None, "viewer"),
    ("GET", "/api/v1/ips/bans", None, "viewer"),
    ("GET", "/api/v1/ids/events", None, "viewer"),
    ("GET", "/api/v1/ids/stats", None, "viewer"),
    ("GET", "/api/v1/whitelist", None, "viewer"),
    ("GET", "/api/v1/network/interfaces", None, "viewer"),
    ("GET", "/api/v1/network/connections", None, "viewer"),
    ("GET", "/api/v1/metrics", None, "viewer"),
    ("GET", "/api/v1/audit/logs", None, "auditor"),
    ("POST", "/api/v1/firewall/rules", RULE, "operator"),
    ("POST", "/api/v1/ips/ban", {"network": "203.0.113.9"}, "operator"),
    ("POST", "/api/v1/ips/unban", {"network": "203.0.113.200"}, "operator"),
    ("POST", "/api/v1/whitelist", {"network": "192.0.2.1"}, "operator"),
    ("POST", "/api/v1/firewall/apply", None, "operator"),
    ("GET", "/api/v1/users", None, "admin"),
    ("GET", "/api/v1/settings", None, "admin"),
    ("GET", "/api/v1/system/hardening", None, "admin"),
]
ORDER = {r: i for i, r in enumerate(ROLES)}
# Some roles share permissions without being ordered (auditor can't write); express explicitly:
ALLOWED = {
    "viewer": {"viewer"}, "auditor": {"viewer", "auditor"},
    "operator": {"viewer", "operator"}, "admin": set(ROLES),
}


@pytest.mark.parametrize(("method", "path", "body", "need"), ENDPOINTS)
def test_rbac_matrix(api, method, path, body, need):
    # unauthenticated -> 401 always
    assert api.request(method, path, json=body).status_code == 401
    for role in ROLES:
        r = api.request(method, path, json=body, headers=auth(api, role))
        should = (role == need) or (role == "admin") or (need == "viewer") or (
            need == "auditor" and role in ("auditor",)) or (need == "operator" and role == "operator")
        if should:
            assert r.status_code not in (401, 403), f"{role} {method} {path}: {r.status_code} {r.text}"
        else:
            assert r.status_code == 403, f"{role} {method} {path}: {r.status_code}"


def test_denied_attempts_are_audited(api):
    api.post("/api/v1/ips/ban", json={"network": "203.0.113.9"}, headers=auth(api, "viewer"))
    with session_scope(api.ctx.sessions) as s:
        rows = [(r.actor, r.action, r.outcome) for r in s.query(AuditLogEntry)]
    assert ("viewer", "auth.denied", "denied") in rows


def test_login_success_failure_and_no_user_enumeration(api):
    assert login(api, "admin").json()["role"] == "admin"
    bad_pw = login(api, "admin", "wrong-password-123")
    no_user = login(api, "ghost", "wrong-password-123")
    assert bad_pw.status_code == no_user.status_code == 401 and bad_pw.json()["error"]["message"] == no_user.json()["error"]["message"]


def test_lockout_after_failures_blocks_even_correct_password(tmp_path, fake_nft):
    c, ctx = make_api(tmp_path, fake_nft, max_failed_logins=3, lockout_minutes=15)
    for _ in range(3):
        assert login(c, "operator", "bad-password-xyz1").status_code == 401
    assert login(c, "operator").status_code == 401  # locked
    with session_scope(ctx.sessions) as s:
        u = s.query(UserRow).filter_by(username="operator").one()
        u.locked_until = datetime.now(UTC) - timedelta(seconds=1)
    assert login(c, "operator").status_code == 200


def test_login_rate_limited(tmp_path, fake_nft):
    c, _ = make_api(tmp_path, fake_nft, login_rate_per_minute=5)
    codes = [login(c, "admin", "bad-password-xyz1").status_code for _ in range(8)]
    assert codes[:5] == [401] * 5 and set(codes[5:]) == {429}
    r = login(c, "admin")
    assert r.status_code == 429 and r.headers["retry-after"]


def test_global_and_write_rate_limits(tmp_path, fake_nft):
    c, _ = make_api(tmp_path, fake_nft, rate_limit_per_minute=5)
    codes = [c.get("/api/v1/status").status_code for _ in range(8)]
    assert codes[:5] == [401] * 5 and set(codes[5:]) == {429}
    (tmp_path / "w").mkdir()
    c2, _ = make_api(tmp_path / "w", fake_nft, write_rate_per_minute=2)
    h = auth(c2, "operator")
    codes = [c2.post("/api/v1/ips/unban", json={"network": f"203.0.113.{i}"}, headers=h).status_code for i in range(4)]
    assert 429 in codes[2:] and codes[0] in (200, 404)


def test_token_attacks(api):
    good = auth(api, "admin")["Authorization"].split()[1]
    now = datetime.now(UTC)
    claims = {"sub": "admin", "role": "admin", "ver": 0, "jti": "x", "iss": "averqon", "iat": now, "exp": now + timedelta(hours=1)}
    forged = {
        "wrong_secret": jwt.encode(claims, "w" * 40, algorithm="HS256"),
        "expired": jwt.encode(claims | {"exp": now - timedelta(seconds=5)}, "s" * 40, algorithm="HS256"),
        "no_exp": jwt.encode({k: v for k, v in claims.items() if k != "exp"}, "s" * 40, algorithm="HS256"),
        "wrong_iss": jwt.encode(claims | {"iss": "evil"}, "s" * 40, algorithm="HS256"),
        "alg_none": jwt.encode(claims, None, algorithm="none"),
        "hs512": jwt.encode(claims, "s" * 40, algorithm="HS512"),
        "garbage": "a.b.c", "tampered": good[:-3] + ("AAA" if not good.endswith("AAA") else "BBB"),
        "wrong_version": jwt.encode(claims | {"ver": 99}, "s" * 40, algorithm="HS256"),
        "unknown_user": jwt.encode(claims | {"sub": "nobody"}, "s" * 40, algorithm="HS256"),
    }
    for name, tok in forged.items():
        r = api.get("/api/v1/users", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 401, f"{name} accepted: {r.status_code}"
    for bad in ("", "Bearer", "Basic abc", f"bearer{good}"):
        assert api.get("/api/v1/users", headers={"Authorization": bad}).status_code == 401


def test_role_comes_from_db_not_token(api):
    h = auth(api, "viewer")
    with session_scope(api.ctx.sessions) as s:
        s.query(UserRow).filter_by(username="viewer").one().role = "admin"
    assert api.get("/api/v1/users", headers=h).status_code == 200  # DB role honoured (privilege change is live)
    with session_scope(api.ctx.sessions) as s:
        s.query(UserRow).filter_by(username="viewer").one().role = "viewer"
    assert api.get("/api/v1/users", headers=h).status_code == 403


def test_logout_revokes_and_disable_revokes(api):
    h = auth(api, "operator")
    assert api.get("/api/v1/status", headers=h).status_code == 200
    assert api.post("/api/v1/auth/logout", headers=h).status_code == 204
    assert api.get("/api/v1/status", headers=h).status_code == 401
    h2 = auth(api, "operator")
    with session_scope(api.ctx.sessions) as s:
        s.query(UserRow).filter_by(username="operator").one().enabled = False
    assert api.get("/api/v1/status", headers=h2).status_code == 401
    assert login(api, "operator").status_code == 401


def test_user_management_rules(api):
    h = auth(api, "admin")
    r = api.post("/api/v1/users", json={"username": "bob", "password": "a-long-password-1", "role": "viewer"}, headers=h)
    assert r.status_code == 201 and "password" not in r.text
    assert api.post("/api/v1/users", json={"username": "bob", "password": "a-long-password-1", "role": "viewer"}, headers=h).status_code == 409
    for bad in ({"username": "x", "password": "a-long-password-1", "role": "viewer"},
                {"username": "carol", "password": "short", "role": "viewer"},
                {"username": "carol", "password": "a-long-password-1", "role": "root"},
                {"username": "carol", "password": "aaaaaaaaaaaaaaaa", "role": "viewer"},
                {"username": "ca rol", "password": "a-long-password-1", "role": "viewer"},
                {"username": "carol", "password": "a-long-password-1", "role": "viewer", "is_admin": True}):
        assert api.post("/api/v1/users", json=bad, headers=h).status_code == 422, bad
    users = {u["username"]: u for u in api.get("/api/v1/users", headers=h).json()["items"]}
    admin_id = users["admin"]["id"]
    assert api.delete(f"/api/v1/users/{admin_id}", headers=h).status_code == 409  # self / last admin
    assert api.patch(f"/api/v1/users/{admin_id}", json={"role": "viewer"}, headers=h).status_code == 409
    assert api.patch(f"/api/v1/users/{admin_id}", json={"enabled": False}, headers=h).status_code == 409
    bob = users.get("bob") or api.get("/api/v1/users", headers=h).json()["items"][-1]
    # role change revokes bob's existing sessions
    bh = {"Authorization": "Bearer " + login(api, "bob", "a-long-password-1").json()["access_token"]}
    assert api.patch(f"/api/v1/users/{bob['id']}", json={"role": "operator"}, headers=h).status_code == 200
    assert api.get("/api/v1/status", headers=bh).status_code == 401
    assert api.delete(f"/api/v1/users/{bob['id']}", headers=h).status_code == 204
    assert api.patch("/api/v1/users/9999", json={"role": "viewer"}, headers=h).status_code == 404


def test_password_hashing_properties():
    from app.auth.security import hash_password, verify_password
    h1, h2 = hash_password(PASSWORD), hash_password(PASSWORD)
    assert h1 != h2 and PASSWORD not in h1 and verify_password(PASSWORD, h1)
    assert not verify_password("x" * 20, h1) and not verify_password(PASSWORD, "garbage") and not verify_password(PASSWORD, None)
    assert not verify_password(PASSWORD, "scrypt$1$1$1$!!$!!")
    import hashlib
    calls = []
    real = hashlib.scrypt
    hashlib.scrypt = lambda *a, **k: (calls.append(1), real(*a, **k))[1]
    try:
        verify_password("anything-long-enough", None)
    finally:
        hashlib.scrypt = real
    assert calls  # unknown users still pay the hashing cost (no timing oracle)
