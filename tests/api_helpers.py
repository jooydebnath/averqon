from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.deps import AppContext
from app.api.main import create_app
from app.api.ratelimit import RateLimiter
from app.auth.security import hash_password
from app.core.config import FirewallSettings, Settings
from app.database.base import Base, make_engine, make_session_factory, session_scope
from app.database.models import UserRow
from app.firewall.backends.nftables import NftablesBackend
from app.ids.engine import IDSEngine
from app.services.facade import LocalFacade
from app.services.firewall_manager import FirewallManager
from app.services.safe_apply import BackupStore

PASSWORD = "correct-horse-battery"
ROLES = ("viewer", "auditor", "operator", "admin")


def make_api(tmp_path, fake_nft, **api):
    settings = Settings(secret_key="s" * 40, environment="development",
                        database={"url": f"sqlite:///{tmp_path/'api.db'}"},
                        firewall=FirewallSettings(admin_ips=["198.51.100.7"], blocklist_dir=tmp_path / "bl"),
                        api={"login_rate_per_minute": 1000, "rate_limit_per_minute": 100000,
                             "write_rate_per_minute": 100000, **api})
    engine = make_engine(settings.database.url)
    Base.metadata.create_all(engine)
    sessions = make_session_factory(engine)
    mgr = FirewallManager(NftablesBackend(runner=fake_nft), sessions, BackupStore(tmp_path / "bk"), settings.firewall)
    ctx = AppContext(settings, sessions, LocalFacade(mgr), IDSEngine(sessions, None, settings.ids), RateLimiter(), "s" * 40)
    with session_scope(sessions) as s:
        for r in ROLES:
            s.add(UserRow(username=r, password_hash=hash_password(PASSWORD), role=r))
    return TestClient(create_app(settings, ctx), raise_server_exceptions=False), ctx


def login(client, user, password=PASSWORD):
    r = client.post("/api/v1/auth/login", json={"username": user, "password": password})
    return r


def auth(client, user):
    r = login(client, user)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


