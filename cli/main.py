"""Averqon CLI. Mutating commands need root (they program the kernel firewall)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from app import __version__
from app.core.config import load_settings
from app.core.container import build_manager
from app.core.errors import AverqonError, ConfigError
from app.firewall.capabilities import detect_capabilities
from app.firewall.rules.models import FirewallRule
from app.services.firewall_manager import FirewallManager

app = typer.Typer(help="Averqon Firewall CLI", no_args_is_help=True)
config_app = typer.Typer(help="Configuration commands")
firewall_app = typer.Typer(help="Firewall commands", no_args_is_help=True)
rules_app = typer.Typer(help="Rule management", no_args_is_help=True)
ip_app = typer.Typer(help="IP ban management", no_args_is_help=True)
app.add_typer(config_app, name="config")
app.add_typer(firewall_app, name="firewall")
firewall_app.add_typer(rules_app, name="rules")
app.add_typer(ip_app, name="ip")

ConfigOpt = Annotated[Path | None, typer.Option("--config", "-c", help="config file")]
JsonOpt = Annotated[bool, typer.Option("--json", help="structured JSON output")]


def get_manager(config: Path | None) -> FirewallManager:
    """Indirection point so tests can inject a manager with a fake backend."""
    return build_manager(load_settings(config))


def _fail(msg: str, as_json: bool) -> typer.Exit:
    typer.echo(json.dumps({"ok": False, "error": msg}) if as_json else f"error: {msg}", err=not as_json)
    return typer.Exit(1)


def _out(data: object, as_json: bool, text: str) -> None:
    typer.echo(json.dumps(data, default=str, indent=2) if as_json else text)


def _guard(fn):  # type: ignore[no-untyped-def]
    """Turn domain/validation errors into clean exit codes (no tracebacks)."""
    import functools

    @functools.wraps(fn)
    def wrapper(*a, **kw):  # type: ignore[no-untyped-def]
        try:
            return fn(*a, **kw)
        except (AverqonError, ValidationError, ValueError) as exc:
            raise _fail(getattr(exc, "detail", None) or str(exc).splitlines()[0], kw.get("json_output", False)) from exc

    return wrapper


ids_app = typer.Typer(help="IDS/IPS commands", no_args_is_help=True)
user_app = typer.Typer(help="User management (needs database access)", no_args_is_help=True)
app.add_typer(ids_app, name="ids")
app.add_typer(user_app, name="user")


def get_sessions(config: Path | None):
    """Indirection point for tests."""
    from app.database.base import Base, make_engine, make_session_factory
    settings = load_settings(config)
    engine = make_engine(settings.database.url)
    if engine.dialect.name == "sqlite":
        Base.metadata.create_all(engine)
    return make_session_factory(engine), settings


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


@config_app.command("validate")
def config_validate(path: Annotated[Path | None, typer.Argument(help="config file")] = None,
                    json_output: JsonOpt = False) -> None:
    """Validate a configuration file."""
    try:
        settings = load_settings(path)
    except ConfigError as exc:
        raise _fail(exc.detail, json_output) from exc
    _out({"valid": True}, json_output, f"OK (environment={settings.environment})")


@app.command()
@_guard
def status(config: ConfigOpt = None, json_output: JsonOpt = False) -> None:
    """Host capabilities and firewall state."""
    caps = detect_capabilities().to_dict()
    data = {"version": __version__, "capabilities": caps}
    try:
        data["firewall"] = get_manager(config).status()
    except AverqonError as exc:
        data["firewall"] = {"error": exc.detail}
    fw = data["firewall"]
    _out(data, json_output, f"averqon {__version__} | {caps['distro_id']} {caps['distro_version']} kernel {caps['kernel']}\n"
         f"preferred backend: {caps['preferred_backend']} | root: {caps['is_root']}\nfirewall: {fw}")


@firewall_app.command("status")
@_guard
def firewall_status(config: ConfigOpt = None, json_output: JsonOpt = False) -> None:
    """Firewall backend state and counters."""
    st = get_manager(config).status()
    _out(st, json_output, f"backend={st['backend']} installed={st['installed']} counters={st['counters']}")


@firewall_app.command("apply")
@_guard
def firewall_apply(config: ConfigOpt = None, dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
                   json_output: JsonOpt = False) -> None:
    """Re-render and apply the stored policy (use --dry-run to only validate and print)."""
    res = get_manager(config).apply(dry_run=dry_run, actor="cli")
    _out({"ok": True, "dry_run": res.dry_run, "applied": res.applied, "conflicts": [c.message for c in res.conflicts]},
         json_output, res.ruleset if dry_run else "applied")


@rules_app.command("list")
@_guard
def rules_list(config: ConfigOpt = None, json_output: JsonOpt = False) -> None:
    """List rules in evaluation order."""
    rules = get_manager(config).list_rules()
    rows = [f"{r.id:>4} {r.priority:>5} {r.direction:<3} {r.action:<6} {r.protocol:<6} "
            f"{r.source or '*'} -> {r.destination or '*'} dport={','.join(r.dport) or '*'} {r.name}" for r in rules]
    _out([r.model_dump() for r in rules], json_output, "\n".join(rows) or "no rules")


@rules_app.command("add")
@_guard
def rules_add(
    action: Annotated[str, typer.Option(help="accept|drop|reject")], name: str = "rule",
    direction: str = "in", protocol: str = "any", source: str | None = None, destination: str | None = None,
    dport: Annotated[list[str] | None, typer.Option(help="repeatable, e.g. 80 or 8000-8100")] = None,
    interface: str | None = None, priority: int = 1000, comment: str = "",
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    force: Annotated[bool, typer.Option(help="allow conflicting rules")] = False,
    config: ConfigOpt = None, json_output: JsonOpt = False,
) -> None:
    """Add a rule (validated, conflict-checked, applied atomically with rollback)."""
    rule = FirewallRule(action=action, name=name, direction=direction, protocol=protocol, source=source,  # type: ignore[arg-type]
                        destination=destination, dport=dport or [], interface=interface, priority=priority, comment=comment)
    saved = get_manager(config).add_rule(rule, actor="cli", dry_run=dry_run, allow_conflicts=force)
    _out({"ok": True, "dry_run": dry_run, "rule": saved.model_dump()}, json_output,
         f"{'would add' if dry_run else 'added'} rule {saved.id or ''} {saved.name}")


@rules_app.command("remove")
@_guard
def rules_remove(rule_id: int, config: ConfigOpt = None, json_output: JsonOpt = False) -> None:
    """Remove a rule by id."""
    get_manager(config).delete_rule(rule_id, actor="cli")
    _out({"ok": True}, json_output, f"removed rule {rule_id}")


@ip_app.command("ban")
@_guard
def ip_ban(network: str, ttl: Annotated[int | None, typer.Option(help="seconds; omit for permanent")] = None,
           reason: str = "", config: ConfigOpt = None, json_output: JsonOpt = False) -> None:
    """Ban an IP or CIDR."""
    row = get_manager(config).ban(network, actor="cli", ttl_seconds=ttl, reason=reason)
    _out({"ok": True, "network": row.network, "expires_at": row.expires_at}, json_output, f"banned {row.network}")


@ip_app.command("unban")
@_guard
def ip_unban(network: str, config: ConfigOpt = None, json_output: JsonOpt = False) -> None:
    """Remove a ban."""
    get_manager(config).unban(network, actor="cli")
    _out({"ok": True}, json_output, f"unbanned {network}")


@ip_app.command("list")
@_guard
def ip_list(config: ConfigOpt = None, json_output: JsonOpt = False) -> None:
    """List active bans."""
    bans = get_manager(config).list_bans()
    _out([{"network": b.network, "expires_at": b.expires_at, "reason": b.reason} for b in bans], json_output,
         "\n".join(f"{b.network} expires={b.expires_at or 'never'} {b.reason}" for b in bans) or "no active bans")


@app.command()
@_guard
def backup(config: ConfigOpt = None, json_output: JsonOpt = False) -> None:
    """Snapshot the currently installed ruleset."""
    mgr = get_manager(config)
    path = mgr.store.save(mgr.backend.export())
    _out({"ok": path is not None, "path": path}, json_output, str(path) if path else "nothing installed to back up")


@app.command()
@_guard
def restore(path: Path | None = None, config: ConfigOpt = None, json_output: JsonOpt = False) -> None:
    """Restore the latest (or a given) snapshot from the backup directory."""
    mgr = get_manager(config)
    snap = mgr.store.read(path) if path else mgr.store.latest()
    if snap is None:
        raise _fail("no snapshot available", json_output)
    mgr.backend.check(snap)
    mgr.backend.restore(snap)
    _out({"ok": True}, json_output, "restored")


@firewall_app.command("emergency-disable")
@_guard
def emergency_disable_cmd(config: ConfigOpt = None, json_output: JsonOpt = False) -> None:
    """Emergency recovery: remove all Averqon firewall objects (host rules untouched)."""
    from app.services.safe_apply import emergency_disable

    emergency_disable(get_manager(config).backend)
    _out({"ok": True}, json_output, "averqon firewall objects removed")


@ids_app.command("status")
@_guard
def ids_status(config: ConfigOpt = None, hours: int = 24, json_output: JsonOpt = False) -> None:
    """Event statistics for the last N hours."""
    from app.ids.engine import IDSEngine
    sessions, settings = get_sessions(config)
    st = IDSEngine(sessions, None, settings.ids).stats(hours)  # type: ignore[arg-type]
    top = ", ".join(f"{t['ip']}({t['count']})" for t in st["top_sources"][:5]) or "-"
    _out(st, json_output, f"last {hours}h: by severity {st['by_severity']} | by kind {st['by_kind']} | top: {top}")


@ids_app.command("events")
@_guard
def ids_events(config: ConfigOpt = None, limit: int = 20, severity: str | None = None, json_output: JsonOpt = False) -> None:
    """Recent IDS events."""
    from app.ids.engine import IDSEngine
    sessions, settings = get_sessions(config)
    rows, total = IDSEngine(sessions, None, settings.ids).query(limit=max(1, min(limit, 500)), severity=severity)  # type: ignore[arg-type]
    data = [{"id": r.id, "ts": r.ts, "kind": r.kind, "severity": r.severity, "source_ip": r.source_ip, "action": r.action,
             "message": r.message} for r in rows]
    _out({"total": total, "items": data}, json_output,
         "\n".join(f"{d['ts']:%F %T} {d['severity']:<8} {d['kind']:<16} {d['source_ip']:<40} {d['action']}" for d in data) or "no events")


@app.command()
@_guard
def logs(config: ConfigOpt = None, limit: int = 20, actor: str | None = None, json_output: JsonOpt = False) -> None:
    """Audit log (administrative actions)."""
    from sqlalchemy import select

    from app.database.base import session_scope
    from app.database.models import AuditLogEntry
    sessions, _ = get_sessions(config)
    with session_scope(sessions) as s:
        q = select(AuditLogEntry).order_by(AuditLogEntry.id.desc()).limit(max(1, min(limit, 500)))
        if actor:
            q = q.where(AuditLogEntry.actor == actor)
        data = [{"id": r.id, "ts": r.created_at, "actor": r.actor, "action": r.action, "target": r.target, "outcome": r.outcome}
                for r in s.scalars(q)]
    _out(data, json_output, "\n".join(f"{d['ts']:%F %T} {d['actor']:<16} {d['action']:<18} {d['target']} [{d['outcome']}]" for d in data) or "no entries")


def _password(prompt_if_missing: bool = True) -> str:
    import os
    env = os.environ.get("AVERQON_PASSWORD")
    if env:
        return env
    return typer.prompt("Password", hide_input=True, confirmation_prompt=True)


@user_app.command("create")
@_guard
def user_create(username: str, role: Annotated[str, typer.Option(help="viewer|auditor|operator|admin")] = "viewer",
                config: ConfigOpt = None, json_output: JsonOpt = False) -> None:
    """Create a user. Password is read from $AVERQON_PASSWORD or prompted (never taken as an argument)."""
    from app.auth.rbac import ROLES
    from app.auth.security import USERNAME, hash_password
    from app.database.base import session_scope
    from app.database.models import UserRow
    if role not in ROLES or not USERNAME.fullmatch(username):
        raise _fail(f"invalid username or role (roles: {', '.join(ROLES)})", json_output)
    pw_hash = hash_password(_password())
    sessions, _ = get_sessions(config)
    with session_scope(sessions) as s:
        from sqlalchemy import select
        if s.scalar(select(UserRow).where(UserRow.username == username)):
            raise _fail("user already exists", json_output)
        s.add(UserRow(username=username, password_hash=pw_hash, role=role))
    _out({"ok": True, "username": username, "role": role}, json_output, f"created {username} ({role})")


@user_app.command("list")
@_guard
def user_list(config: ConfigOpt = None, json_output: JsonOpt = False) -> None:
    from sqlalchemy import select

    from app.database.base import session_scope
    from app.database.models import UserRow
    sessions, _ = get_sessions(config)
    with session_scope(sessions) as s:
        data = [{"username": u.username, "role": u.role, "enabled": u.enabled} for u in s.scalars(select(UserRow).order_by(UserRow.id))]
    _out(data, json_output, "\n".join(f"{d['username']:<24} {d['role']:<9} {'enabled' if d['enabled'] else 'disabled'}" for d in data) or "no users")


@user_app.command("passwd")
@_guard
def user_passwd(username: str, config: ConfigOpt = None, json_output: JsonOpt = False) -> None:
    """Reset a user's password (revokes their sessions and clears lockout)."""
    from sqlalchemy import select

    from app.auth.security import hash_password
    from app.database.base import session_scope
    from app.database.models import UserRow
    pw_hash = hash_password(_password())
    sessions, _ = get_sessions(config)
    with session_scope(sessions) as s:
        u = s.scalar(select(UserRow).where(UserRow.username == username))
        if u is None:
            raise _fail("no such user", json_output)
        u.password_hash, u.token_version, u.failed_logins, u.locked_until = pw_hash, u.token_version + 1, 0, None
    _out({"ok": True}, json_output, "password updated")


@firewall_app.command("harden")
@_guard
def firewall_harden(config: ConfigOpt = None, apply: Annotated[bool, typer.Option("--apply")] = False,
                    json_output: JsonOpt = False) -> None:
    """Show (or with --apply, set) kernel hardening sysctls such as tcp_syncookies."""
    from app.firewall import sysctl
    changed = [c.key for c in sysctl.apply_hardening()] if apply else []
    plan = [{"key": c.key, "current": c.current, "desired": c.desired, "needs_change": c.needs_change} for c in sysctl.plan()]
    _out({"plan": plan, "changed": changed}, json_output,
         "\n".join(f"{'*' if p['needs_change'] else ' '} {p['key']} = {p['current']} (want {p['desired']})" for p in plan)
         + (f"\napplied {len(changed)} change(s)" if apply else "\n(dry run; use --apply as root)"))


@firewall_app.command("refresh-blocklists")
@_guard
def firewall_refresh(config: ConfigOpt = None, json_output: JsonOpt = False) -> None:
    """Fetch threat-intel feeds / load country lists and re-apply the ruleset."""
    counts = get_manager(config).refresh_blocklists(actor="cli")
    _out({"ok": True, "counts": counts}, json_output, f"updated: {counts}")


@app.command("init-db")
def init_db(config: ConfigOpt = None) -> None:
    """Run database migrations (alembic upgrade head)."""
    from alembic import command
    from alembic.config import Config

    import app.database as dbpkg
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(dbpkg.__file__).parent / "migrations"))
    command.upgrade(cfg, "head")
    typer.echo("database is up to date")


serve_app = typer.Typer(help="Run services", no_args_is_help=True)
app.add_typer(serve_app, name="serve")


@serve_app.command("executor")
def serve_executor(config: ConfigOpt = None) -> None:
    """PRIVILEGED firewall executor (run as root via systemd)."""
    import asyncio

    from app.services.runtime import run_executor
    asyncio.run(run_executor(load_settings(config)))


@serve_app.command("api")
def serve_api(config: ConfigOpt = None) -> None:
    """REST API (unprivileged)."""
    from app.services.runtime import run_api
    run_api(load_settings(config))


@serve_app.command("daemon")
def serve_daemon(config: ConfigOpt = None) -> None:
    """Detection daemon: log monitoring, IDS/IPS, alerts (unprivileged)."""
    import asyncio

    from app.services.runtime import run_daemon
    asyncio.run(run_daemon(load_settings(config)))
