import json
from datetime import UTC, datetime

import pytest

from app.api.main import create_app
from app.core.errors import BackendError
from app.database.base import session_scope
from app.database.models import IdsEventRow
from tests.api_helpers import auth, make_api

R = {"name": "web", "action": "accept", "protocol": "tcp", "dport": ["80", "8000-8100"], "priority": 100}


def test_rule_crud_through_api_and_kernel_state(api):
    h = auth(api, "operator")
    r = api.post("/api/v1/firewall/rules", json=R, headers=h)
    assert r.status_code == 201
    rid = r.json()["id"]
    assert "tcp dport { 80, 8000-8100 }" in api.nft.table
    r = api.put(f"/api/v1/firewall/rules/{rid}", json=R | {"dport": ["443"]}, headers=h)
    assert r.status_code == 200 and "{ 443 }" in api.nft.table
    page = api.get("/api/v1/firewall/rules?limit=1", headers=h).json()
    assert page["total"] == 1 and page["limit"] == 1 and page["items"][0]["id"] == rid
    assert api.delete(f"/api/v1/firewall/rules/{rid}", headers=h).status_code == 204
    assert api.delete(f"/api/v1/firewall/rules/{rid}", headers=h).status_code == 404
    assert api.put("/api/v1/firewall/rules/999", json=R, headers=h).status_code == 404


def test_dry_run_and_conflicts_via_api(api):
    h = auth(api, "operator")
    r = api.post("/api/v1/firewall/rules?dry_run=true", json=R, headers=h)
    assert r.status_code == 201 and api.get("/api/v1/firewall/rules", headers=h).json()["total"] == 0
    api.post("/api/v1/firewall/rules", json={"name": "all", "action": "accept", "protocol": "tcp", "priority": 1}, headers=h)
    bad = api.post("/api/v1/firewall/rules", json={"name": "x", "action": "drop", "protocol": "tcp", "dport": ["22"], "priority": 5}, headers=h)
    assert bad.status_code == 422 and "never reached" in bad.json()["error"]["message"]
    assert api.post("/api/v1/firewall/rules?force=true", json={"name": "x", "action": "drop", "protocol": "tcp", "dport": ["22"], "priority": 5}, headers=h).status_code == 201


@pytest.mark.parametrize("payload", [
    {"name": "x", "action": "accept", "source": "1.2.3.4; flush ruleset"},
    {"name": "x", "action": "accept", "source": "1.2.3.4}\nflush ruleset\n{"},
    {"name": "x", "action": "accept", "interface": "eth0\" accept #"}, {"name": "x", "action": "accept", "comment": "\" accept"},
    {"name": "x", "action": "allow"}, {"name": "x", "action": "accept", "dport": ["80"]},
    {"name": "x", "action": "accept", "protocol": "tcp", "dport": ["99999"]}, {"name": "x", "action": "accept", "id": 5},
    {"name": "x", "action": "accept", "priority": -1}, {"name": "../../etc", "action": "accept"}, [], "str", None,
])
def test_malicious_rule_payloads_rejected_and_never_reach_backend(api, payload):
    h = auth(api, "operator")
    before = len(api.nft.calls)
    r = api.post("/api/v1/firewall/rules", json=payload, headers=h)
    assert r.status_code == 422
    assert len(api.nft.calls) == before and "flush" not in json.dumps(api.nft.calls)


def test_validation_errors_do_not_echo_input(api):
    h = auth(api, "operator")
    secret = "SUPER-SECRET-MARKER-123"
    r = api.post("/api/v1/ips/ban", json={"network": secret, "extra": secret}, headers=h)
    assert r.status_code == 422 and secret not in r.text and "fields" in r.json()["error"]
    r = api.post("/api/v1/auth/login", json={"username": "a", "password": secret, "x": 1})
    assert r.status_code == 422 and secret not in r.text


def test_ban_unban_whitelist_flows(api):
    h = auth(api, "operator")
    assert api.post("/api/v1/ips/ban", json={"network": "203.0.113.9", "ttl_seconds": 600, "reason": "t"}, headers=h).status_code == 201
    bans = api.get("/api/v1/ips/bans", headers=h).json()
    assert bans["total"] == 1 and bans["items"][0]["actor"] == "operator" and bans["items"][0]["expires_at"]
    for target in ("198.51.100.7", "198.51.100.0/24", "0.0.0.0/0", "::/0", "garbage"):
        assert api.post("/api/v1/ips/ban", json={"network": target}, headers=h).status_code == 422, target
    assert api.post("/api/v1/ips/unban", json={"network": "203.0.113.9"}, headers=h).json() == {"unbanned": 1}
    assert api.post("/api/v1/ips/unban", json={"network": "203.0.113.9"}, headers=h).status_code == 404
    assert api.post("/api/v1/whitelist", json={"network": "192.0.2.0/24", "comment": "office"}, headers=h).status_code == 201
    wl = api.get("/api/v1/whitelist", headers=h).json()["items"]
    assert {w["network"] for w in wl} == {"198.51.100.7", "192.0.2.0/24"}
    assert api.delete("/api/v1/whitelist/192.0.2.0/24", headers=h).status_code == 204
    assert api.delete("/api/v1/whitelist/not-an-ip", headers=h).status_code == 422
    assert api.post("/api/v1/ips/ban", json={"network": "192.0.2.5", "ttl_seconds": 0}, headers=h).status_code == 422


def test_pagination_bounds(api):
    h = auth(api, "viewer")
    for q in ("limit=0", "limit=201", "limit=-1", "offset=-1", "limit=abc", "offset=99999999999"):
        assert api.get(f"/api/v1/firewall/rules?{q}", headers=h).status_code == 422, q
    assert api.get("/api/v1/firewall/rules?limit=200&offset=5", headers=h).status_code == 200


def seed_events(api):
    with session_scope(api.ctx.sessions) as s:
        for i, (sev, kind, ip) in enumerate([("low", "ssh_auth_failure", "203.0.113.5"), ("high", "port_scan", "203.0.113.6"),
                                             ("high", "jail_threshold", "203.0.113.5")]):
            s.add(IdsEventRow(ts=datetime.now(UTC), kind=kind, severity=sev, source_ip=ip, message=f"m{i}", details={"i": i}, action="none"))


def test_ids_events_filters_stats_and_injection(api):
    seed_events(api)
    h = auth(api, "viewer")
    assert api.get("/api/v1/ids/events", headers=h).json()["total"] == 3
    assert api.get("/api/v1/ids/events?severity=high", headers=h).json()["total"] == 2
    assert api.get("/api/v1/ids/events?source_ip=203.0.113.5&kind=jail_threshold", headers=h).json()["total"] == 1
    assert api.get("/api/v1/ids/events?hours=1", headers=h).json()["total"] == 3
    for bad in ("severity=high' OR '1'='1", "kind=x';DROP TABLE ids_events;--", "source_ip=1.1.1.1' OR 1=1", "hours=0", "severity=HIGH"):
        assert api.get(f"/api/v1/ids/events?{bad}", headers=h).status_code == 422, bad
    assert api.get("/api/v1/ids/events", headers=h).json()["total"] == 3  # table intact
    st = api.get("/api/v1/ids/stats", headers=h).json()
    assert st["by_severity"] == {"low": 1, "high": 2} and st["top_sources"][0]["ip"] == "203.0.113.5"


def test_audit_log_records_actor_and_filters(api):
    h = auth(api, "operator")
    api.post("/api/v1/ips/ban", json={"network": "203.0.113.9"}, headers=h)
    a = auth(api, "auditor")
    logs = api.get("/api/v1/audit/logs?action=ip.ban", headers=a).json()
    assert logs["total"] == 1 and logs["items"][0]["actor"] == "operator" and logs["items"][0]["target"] == "203.0.113.9/32"
    assert api.get("/api/v1/audit/logs?outcome=bogus", headers=a).status_code == 422
    assert api.get("/api/v1/audit/logs?actor=operator&outcome=success", headers=a).json()["total"] >= 1


def test_security_headers_and_error_shapes(api):
    r = api.get("/api/v1/status")
    for k in ("x-content-type-options", "x-frame-options", "content-security-policy", "cache-control", "x-request-id"):
        assert k in r.headers
    assert r.headers["cache-control"] == "no-store" and r.headers["x-frame-options"] == "DENY"
    nf = api.get("/api/v1/nope")
    assert nf.status_code == 404 and nf.json()["error"]["code"] == "not_found"
    assert api.put("/api/v1/status").status_code in (401, 405)
    assert "server" not in {k.lower() for k in api.get("/api/v1/status").headers} or "uvicorn" not in api.get("/api/v1/status").headers.get("server", "")


def test_body_size_limit_and_cors(tmp_path, fake_nft):
    c, _ = make_api(tmp_path, fake_nft, max_body_bytes=2048, cors_origins=["https://dash.example"])
    h = auth(c, "operator")
    big = {"name": "x", "action": "accept", "comment": "a" * 5000}
    assert c.post("/api/v1/firewall/rules", json=big, headers=h).status_code == 413
    ok = c.options("/api/v1/status", headers={"Origin": "https://dash.example", "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "https://dash.example"
    assert "access-control-allow-credentials" not in ok.headers
    evil = c.options("/api/v1/status", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in evil.headers


def test_backend_and_unexpected_failures_do_not_leak(tmp_path, fake_nft):
    c, ctx = make_api(tmp_path, fake_nft)
    h = auth(c, "operator")

    def boom(**kw):
        raise RuntimeError("secret internal path /etc/shadow Traceback")

    ctx.facade.list_rules = boom
    r = c.get("/api/v1/firewall/rules", headers=h)
    assert r.status_code == 500 and "shadow" not in r.text and "Traceback" not in r.text and r.json()["error"]["request_id"]
    ctx.facade.list_rules = lambda: (_ for _ in ()).throw(BackendError("nft rejected ruleset: line 3"))
    r = c.get("/api/v1/firewall/rules", headers=h)
    assert r.status_code == 502 and "line 3" in r.text


def test_health_status_metrics_network_settings(api):
    h = auth(api, "admin")
    api.post("/api/v1/firewall/apply", headers=h)
    hl = api.get("/api/v1/system/health", headers=h)
    assert hl.status_code == 200 and hl.json()["checks"]["database"]["ok"] and hl.json()["checks"]["firewall"]["installed"]
    st = api.get("/api/v1/status", headers=h).json()
    assert st["firewall"]["backend"] == "nftables" and st["active_bans"] == 0 and "version" in st
    m = api.get("/api/v1/metrics", headers=h)
    assert m.headers["content-type"].startswith("text/plain") and "averqon_cpu_percent" in m.text and "# TYPE" in m.text
    assert any(i["name"] for i in api.get("/api/v1/network/interfaces", headers=h).json())
    conns = api.get("/api/v1/network/connections?limit=5", headers=h).json()
    assert "by_state" in conns and len(conns["items"]) <= 5
    s = api.get("/api/v1/settings", headers=h).json()
    assert "secret" not in json.dumps(s).lower() and s["firewall"]["table_name"] == "averqon"
    me = api.get("/api/v1/auth/me", headers=h).json()
    assert "users:manage" in me["permissions"]
    assert "users:manage" not in api.get("/api/v1/auth/me", headers=auth(api, "viewer")).json()["permissions"]
    api.ctx.facade.status = lambda: (_ for _ in ()).throw(BackendError("down"))
    r = api.get("/api/v1/system/health", headers=h)
    assert r.status_code == 503 and r.json()["checks"]["firewall"]["ok"] is False


def test_production_hides_docs_and_requires_executor(tmp_path, fake_nft):
    from app.api.main import build_context
    from app.core.config import Settings
    from app.core.errors import ConfigError
    prod = Settings(environment="production", secret_key="p" * 40, database={"url": f"sqlite:///{tmp_path/'p.db'}"})
    with pytest.raises(ConfigError):
        build_context(prod)
    _, ctx = make_api(tmp_path, fake_nft)
    from fastapi.testclient import TestClient
    app = create_app(prod, ctx)
    c = TestClient(app)
    assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 404


def test_ids_stream_delivers_new_events(api):
    """Real uvicorn server: ASGI test transports buffer responses and cannot test streaming."""
    import socket
    import threading
    import time

    import httpx
    import uvicorn
    h = auth(api, "viewer")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(api.app, host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        got = []
        threading.Timer(0.5, seed_events, args=(api,)).start()
        with httpx.stream("GET", f"http://127.0.0.1:{port}/api/v1/ids/stream", headers=h, timeout=8) as resp:
            assert resp.status_code == 200 and resp.headers["content-type"].startswith("application/x-ndjson")
            for line in resp.iter_lines():
                if line:
                    got.append(json.loads(line))
                    if got[-1]["type"] == "event":
                        break
        assert got[0]["type"] == "hello" and got[-1]["event"]["source_ip"].startswith("203.0.113.")
        # unauthenticated stream is refused
        assert httpx.get(f"http://127.0.0.1:{port}/api/v1/ids/stream", timeout=3).status_code == 401
    finally:
        server.should_exit = True
        t.join(5)
