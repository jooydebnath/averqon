"""Status, health, network monitoring, metrics, settings."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func, select, text

from app import __version__
from app.api.deps import Ctx, CurrentUser, audit, require
from app.database.base import session_scope
from app.database.models import IdsEventRow
from app.firewall.capabilities import detect_capabilities
from app.monitoring import system as sysmon

router = APIRouter(prefix="/api/v1")


@router.get("/status")
def status(ctx: Ctx, _: Annotated[CurrentUser, Depends(require("status:read"))]) -> dict:
    from datetime import UTC, datetime, timedelta
    fw = ctx.facade.status()
    with session_scope(ctx.sessions) as s:
        events_24h = s.scalar(select(func.count()).select_from(IdsEventRow)
                              .where(IdsEventRow.ts >= datetime.now(UTC) - timedelta(hours=24))) or 0
    return {"version": __version__, "firewall": fw, "rules": len(ctx.facade.list_rules()),
            "active_bans": len(ctx.facade.list_bans(active_only=True)), "events_24h": events_24h}


@router.get("/system/health")
def health(response: Response, ctx: Ctx, _: Annotated[CurrentUser, Depends(require("health:read"))]) -> dict:
    checks: dict[str, dict] = {}
    try:
        with session_scope(ctx.sessions) as s:
            s.execute(text("SELECT 1"))
        checks["database"] = {"ok": True}
    except Exception:  # noqa: BLE001 - health must never raise
        checks["database"] = {"ok": False}
    try:
        fw = ctx.facade.status()
        checks["firewall"] = {"ok": bool(fw.get("installed")), "backend": fw.get("backend"), "installed": fw.get("installed")}
    except Exception:  # noqa: BLE001 - health must never raise
        checks["firewall"] = {"ok": False, "error": "executor unavailable"}
    snap = sysmon.system_snapshot()
    checks["resources"] = {"ok": snap["memory"]["percent"] < 95 and snap["disk"]["percent"] < 95}
    ok = all(c["ok"] for c in checks.values())
    if not ok:
        response.status_code = 503
    return {"ok": ok, "checks": checks, "system": snap, "capabilities": _caps()}


def _caps() -> dict:
    c = detect_capabilities().to_dict()
    return {k: c[k] for k in ("distro_id", "distro_version", "kernel", "nft_version", "iptables_flavor",
                              "preferred_backend", "is_root", "warnings")}


@router.get("/network/interfaces")
def interfaces(_: Annotated[CurrentUser, Depends(require("network:read"))]) -> list[dict]:
    return sysmon.interface_stats()


@router.get("/network/connections")
def connections(_: Annotated[CurrentUser, Depends(require("network:read"))], limit: int = 200) -> dict:
    return sysmon.connections(max(1, min(limit, 1000)))


@router.get("/metrics")
def metrics(ctx: Ctx, _: Annotated[CurrentUser, Depends(require("metrics:read"))]) -> Response:
    fw = ctx.facade.status()
    stats = ctx.ids.stats(24)
    extra = {"active_bans": len(ctx.facade.list_bans(active_only=True)), "rules": len(ctx.facade.list_rules()),
             "firewall_installed": 1 if fw.get("installed") else 0,
             "firewall_packets": fw.get("counters", {}).get("packets", 0),
             "firewall_bytes": fw.get("counters", {}).get("bytes", 0)}
    body = sysmon.prometheus_text(extra, {"ids_events_24h_by_severity": {k: float(v) for k, v in stats["by_severity"].items()}})
    return Response(body, media_type="text/plain; version=0.0.4")


@router.get("/settings")
def settings(ctx: Ctx, _: Annotated[CurrentUser, Depends(require("settings:read"))]) -> dict:
    s = ctx.settings
    return {"environment": s.environment, "log_level": s.log_level,
            "firewall": s.firewall.model_dump(mode="json", exclude={"backup_dir", "blocklist_dir", "geo_zone_dir"}),
            "ids": s.ids.model_dump(mode="json"),
            "api": s.api.model_dump(mode="json", exclude={"executor_socket", "allowed_uids"}),
            "note": "Read-only: edit the configuration file and restart to change settings."}


@router.get("/system/hardening")
def hardening(ctx: Ctx, _: Annotated[CurrentUser, Depends(require("settings:read"))]) -> list[dict]:
    return ctx.facade.hardening_plan()


@router.post("/system/hardening/apply")
def hardening_apply(request: Request, ctx: Ctx, user: Annotated[CurrentUser, Depends(require("settings:write"))]) -> dict:
    changed = ctx.facade.apply_hardening()
    audit(ctx, request, user.username, "system.harden", details={"changed": changed})
    return {"changed": changed}


@router.post("/system/blocklists/refresh")
def refresh_blocklists(request: Request, ctx: Ctx, user: Annotated[CurrentUser, Depends(require("settings:write"))]) -> dict:
    counts = ctx.facade.refresh_blocklists(actor=user.username)
    return {"counts": counts}
