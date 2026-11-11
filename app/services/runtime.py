"""Process entrypoints: executor (privileged), API (unprivileged), daemon (unprivileged)."""

from __future__ import annotations

import asyncio
import logging
import signal
from pathlib import Path

from app.core.config import Settings
from app.core.container import build_manager
from app.core.errors import ConfigError
from app.core.logging import configure_logging
from app.database.base import Base, make_engine, make_session_factory
from app.detection.jails import default_jails
from app.executor.protocol import ExecutorClient
from app.executor.server import ExecutorServer
from app.firewall.capabilities import detect_capabilities
from app.ids.engine import IDSEngine
from app.ips.service import IPSService
from app.monitoring.alerts import ResourceMonitor
from app.notifications.dispatcher import Dispatcher, build_channels
from app.services.daemon import Daemon, build_jails
from app.services.facade import LocalFacade

log = logging.getLogger(__name__)
DEFAULT_SOCKET = "/run/averqon/executor.sock"


def _stop_on_signals(loop: asyncio.AbstractEventLoop, ev: asyncio.Event) -> None:
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, ev.set)


async def run_executor(settings: Settings, group: str | None = "averqon") -> None:
    """PRIVILEGED. Applies the stored policy at startup (kernel rules do not survive reboot), then serves."""
    configure_logging(settings.log_level, settings.log_json)
    if not settings.api.allowed_uids:
        raise ConfigError("api.allowed_uids must list the uid(s) of the API/daemon service users")
    mgr = build_manager(settings)
    try:
        res = await asyncio.to_thread(mgr.apply, actor="startup")
        log.info("startup policy applied (conflicts: %d)", len(res.conflicts))
    except Exception:
        log.exception("startup apply failed; executor continues without enforcing stored policy")
    srv = ExecutorServer(LocalFacade(mgr), Path(settings.api.executor_socket or DEFAULT_SOCKET),
                         set(settings.api.allowed_uids), group)
    await srv.start()
    stop = asyncio.Event()
    _stop_on_signals(asyncio.get_running_loop(), stop)
    await stop.wait()
    await srv.stop()


def run_api(settings: Settings) -> None:
    import uvicorn

    from app.api.main import create_app
    configure_logging(settings.log_level, settings.log_json)
    kw: dict = {}
    if settings.api.tls_certfile and settings.api.tls_keyfile:
        kw = {"ssl_certfile": str(settings.api.tls_certfile), "ssl_keyfile": str(settings.api.tls_keyfile)}
    elif settings.environment == "production" and settings.api.host not in ("127.0.0.1", "::1"):
        raise ConfigError("refusing to serve plain HTTP on a non-loopback address in production; configure TLS")
    uvicorn.run(create_app(settings), host=settings.api.host, port=settings.api.port, log_level=settings.log_level.lower(),
                server_header=False, **kw)


def build_daemon(settings: Settings, facade=None) -> tuple[Daemon, Dispatcher]:
    sessions = make_session_factory(_engine(settings))
    if facade is None:
        facade = (ExecutorClient(settings.api.executor_socket) if settings.api.executor_socket
                  else LocalFacade(build_manager(settings)))
    caps = detect_capabilities()
    dispatcher = Dispatcher(build_channels(settings.notifications), settings.notifications)
    ips = IPSService(facade, settings.ids)
    ids = IDSEngine(sessions, ips, settings.ids, listeners=[dispatcher.event_listener()])
    jails = build_jails(settings.ids, default_jails(caps.distro_like, caps.distro_id))
    monitor = ResourceMonitor(dispatcher, settings.notifications)
    periodic: list = [(60.0, monitor.check), (3600.0, ids.prune)]
    if settings.firewall.threat_feeds or settings.firewall.geo_block_countries:
        periodic.append((settings.firewall.blocklist_refresh_hours * 3600.0, lambda: facade.refresh_blocklists(actor="system")))
    return Daemon(ids, jails, settings.ids, facade, periodic=periodic), dispatcher


def _engine(settings: Settings):
    engine = make_engine(settings.database.url, echo=settings.database.echo)
    if engine.dialect.name == "sqlite":
        Base.metadata.create_all(engine)
    return engine


async def run_daemon(settings: Settings) -> None:
    configure_logging(settings.log_level, settings.log_json)
    daemon, dispatcher = build_daemon(settings)
    _stop_on_signals(asyncio.get_running_loop(), daemon.stop)
    try:
        await daemon.run()
    finally:
        dispatcher.close()
