"""Dependency wiring: settings -> capabilities -> backend -> manager."""

from __future__ import annotations

from app.core.config import Settings
from app.database.base import Base, make_engine, make_session_factory
from app.firewall.backends import select_backend
from app.firewall.backends.base import FirewallBackend
from app.firewall.capabilities import detect_capabilities
from app.services.firewall_manager import FirewallManager
from app.services.safe_apply import BackupStore, tcp_probe


def build_manager(settings: Settings, backend: FirewallBackend | None = None) -> FirewallManager:
    """Create a FirewallManager. ``backend`` may be injected (tests, alternative executors)."""
    if backend is None:
        backend = select_backend(detect_capabilities(), settings.firewall.backend, settings.firewall.table_name)
    engine = make_engine(settings.database.url, echo=settings.database.echo)
    if engine.dialect.name == "sqlite":
        Base.metadata.create_all(engine)  # dev convenience only; production uses Alembic
    port = settings.firewall.management_ports[0] if settings.firewall.management_ports else None
    check = (lambda: tcp_probe("127.0.0.1", port)) if port else None
    return FirewallManager(backend, make_session_factory(engine), BackupStore(settings.firewall.backup_dir),
                           settings.firewall, connectivity_check=check)
