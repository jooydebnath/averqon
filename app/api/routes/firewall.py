"""Firewall rules, bans, whitelist and IDS events."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select

from app.api.deps import Ctx, CurrentUser, Paging, require
from app.database.base import session_scope
from app.database.models import AuditLogEntry, IdsEventRow
from app.schemas.api import BanIn, Page, RuleIn, UnbanIn, WhitelistIn
from app.utils import validation as v

router = APIRouter(prefix="/api/v1")
Read = Annotated[CurrentUser, Depends(require("rules:read"))]


def _slice(items: list, paging: tuple[int, int]) -> dict:
    limit, offset = paging
    return {"items": items[offset:offset + limit], "total": len(items), "limit": limit, "offset": offset}


@router.get("/firewall/rules", response_model=Page[dict])
def list_rules(ctx: Ctx, paging: Paging, _: Read) -> dict:
    return _slice(ctx.facade.list_rules(), paging)


@router.post("/firewall/rules", status_code=201)
def create_rule(rule: RuleIn, ctx: Ctx, user: Annotated[CurrentUser, Depends(require("rules:write"))],
                dry_run: bool = False, force: bool = False) -> dict:
    return ctx.facade.add_rule(rule=rule.model_dump(exclude={"id"}), actor=user.username, dry_run=dry_run, force=force)


@router.put("/firewall/rules/{rule_id}")
def update_rule(rule_id: int, rule: RuleIn, ctx: Ctx,
                user: Annotated[CurrentUser, Depends(require("rules:write"))], force: bool = False) -> dict:
    return ctx.facade.update_rule(rule_id=rule_id, rule=rule.model_dump(exclude={"id"}), actor=user.username, force=force)


@router.delete("/firewall/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: int, ctx: Ctx, user: Annotated[CurrentUser, Depends(require("rules:write"))]) -> None:
    ctx.facade.delete_rule(rule_id=rule_id, actor=user.username)


@router.post("/firewall/apply")
def apply(ctx: Ctx, user: Annotated[CurrentUser, Depends(require("firewall:apply"))], dry_run: bool = False) -> dict:
    return ctx.facade.apply(actor=user.username, dry_run=dry_run)


@router.get("/ips/bans", response_model=Page[dict])
def list_bans(ctx: Ctx, paging: Paging, _: Annotated[CurrentUser, Depends(require("bans:read"))],
              active_only: bool = True) -> dict:
    return _slice(ctx.facade.list_bans(active_only=active_only), paging)


@router.post("/ips/ban", status_code=201)
def ban(body: BanIn, ctx: Ctx, user: Annotated[CurrentUser, Depends(require("bans:write"))]) -> dict:
    return ctx.facade.ban(network=body.network, actor=user.username, ttl_seconds=body.ttl_seconds, reason=body.reason)


@router.post("/ips/unban")
def unban(body: UnbanIn, ctx: Ctx, user: Annotated[CurrentUser, Depends(require("bans:write"))]) -> dict:
    return {"unbanned": ctx.facade.unban(network=body.network, actor=user.username)}


@router.get("/whitelist", response_model=Page[dict])
def whitelist(ctx: Ctx, paging: Paging, _: Annotated[CurrentUser, Depends(require("whitelist:read"))]) -> dict:
    return _slice(ctx.facade.whitelist_list(), paging)


@router.post("/whitelist", status_code=201)
def whitelist_add(body: WhitelistIn, ctx: Ctx, user: Annotated[CurrentUser, Depends(require("whitelist:write"))]) -> dict:
    ctx.facade.whitelist_add(network=body.network, actor=user.username, comment=body.comment)
    return {"network": body.network}


@router.delete("/whitelist/{network:path}", status_code=204)
def whitelist_remove(network: str, ctx: Ctx, user: Annotated[CurrentUser, Depends(require("whitelist:write"))]) -> None:
    ctx.facade.whitelist_remove(network=str(v.parse_network(network)), actor=user.username)


def _event(r: IdsEventRow) -> dict:
    return {"id": r.id, "ts": r.ts.isoformat(), "kind": r.kind, "severity": r.severity, "source_ip": r.source_ip,
            "jail": r.jail, "message": r.message, "details": r.details, "action": r.action}


@router.get("/ids/events", response_model=Page[dict])
def ids_events(ctx: Ctx, paging: Paging, _: Annotated[CurrentUser, Depends(require("events:read"))],
               severity: Annotated[str | None, Query(pattern="^(low|medium|high|critical)$")] = None,
               kind: Annotated[str | None, Query(max_length=32, pattern=r"^[a-z_]+$")] = None,
               source_ip: str | None = None, hours: Annotated[int | None, Query(ge=1, le=24 * 365)] = None) -> dict:
    limit, offset = paging
    if source_ip:
        source_ip = v.normalize_ip(source_ip)
    since = datetime.now(UTC) - timedelta(hours=hours) if hours else None
    rows, total = ctx.ids.query(limit=limit, offset=offset, severity=severity, kind=kind, source_ip=source_ip, since=since)
    return {"items": [_event(r) for r in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/ids/stats")
def ids_stats(ctx: Ctx, _: Annotated[CurrentUser, Depends(require("analytics:read"))],
              hours: Annotated[int, Query(ge=1, le=24 * 90)] = 24) -> dict:
    return ctx.ids.stats(hours)


@router.get("/ids/stream")
async def ids_stream(request: Request, ctx: Ctx, _: Annotated[CurrentUser, Depends(require("events:read"))]) -> StreamingResponse:
    """Newline-delimited JSON stream of new IDS events (consume with fetch + Authorization header)."""
    def latest_id() -> int:
        with session_scope(ctx.sessions) as s:
            return s.scalar(select(func.max(IdsEventRow.id))) or 0

    def fetch_new(after: int) -> list[dict]:
        with session_scope(ctx.sessions) as s:
            return [_event(r) for r in s.scalars(select(IdsEventRow).where(IdsEventRow.id > after).order_by(IdsEventRow.id).limit(100))]

    async def gen():
        last = await asyncio.to_thread(latest_id)
        yield b'{"type":"hello"}\n'
        idle = 0
        while not await request.is_disconnected():
            events = await asyncio.to_thread(fetch_new, last)
            for e in events:
                last = e["id"]
                yield (json.dumps({"type": "event", "event": e}) + "\n").encode()
            idle = 0 if events else idle + 1
            if idle and idle % 15 == 0:
                yield b'{"type":"ping"}\n'
            await asyncio.sleep(1)

    return StreamingResponse(gen(), media_type="application/x-ndjson", headers={"Cache-Control": "no-store"})


@router.get("/audit/logs", response_model=Page[dict])
def audit_logs(ctx: Ctx, paging: Paging, _: Annotated[CurrentUser, Depends(require("audit:read"))],
               actor: Annotated[str | None, Query(max_length=128)] = None,
               action: Annotated[str | None, Query(max_length=64)] = None,
               outcome: Annotated[str | None, Query(pattern="^(success|failure|denied)$")] = None) -> dict:
    limit, offset = paging
    with session_scope(ctx.sessions) as s:
        q = select(AuditLogEntry)
        for col, val in ((AuditLogEntry.actor, actor), (AuditLogEntry.action, action), (AuditLogEntry.outcome, outcome)):
            if val:
                q = q.where(col == val)
        total = s.scalar(select(func.count()).select_from(q.subquery())) or 0
        rows = s.scalars(q.order_by(AuditLogEntry.id.desc()).limit(limit).offset(offset))
        items = [{"id": r.id, "ts": r.created_at.isoformat(), "actor": r.actor, "action": r.action, "target": r.target,
                  "outcome": r.outcome, "source_ip": r.source_ip, "details": r.details} for r in rows]
    if limit < 1:
        raise HTTPException(422, "bad limit")
    return {"items": items, "total": total, "limit": limit, "offset": offset}
