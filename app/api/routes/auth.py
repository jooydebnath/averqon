"""Authentication and user management."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select

from app.api.deps import (
    Ctx,
    CurrentUser,
    Paging,
    audit,
    client_ip,
    current_user,
    rate_limit,
    require,
)
from app.auth.security import create_token, hash_password, verify_password
from app.core.errors import ValidationFailed
from app.database.base import session_scope
from app.database.models import RevokedToken, UserRow
from app.schemas.api import LoginIn, Page, TokenOut, UserCreate, UserUpdate

router = APIRouter(prefix="/api/v1")


def user_out(u: UserRow) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role, "enabled": u.enabled,
            "last_login": u.last_login.isoformat() if u.last_login else None,
            "locked": bool(u.locked_until and u.locked_until.replace(tzinfo=UTC) > datetime.now(UTC))}


@router.post("/auth/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, ctx: Ctx) -> TokenOut:
    ip = client_ip(request)
    cfg = ctx.settings.api
    rate_limit(ctx, "login-ip", ip, cfg.login_rate_per_minute)
    rate_limit(ctx, "login-user", body.username.lower(), cfg.login_rate_per_minute)
    fail = HTTPException(401, "Invalid credentials")
    with session_scope(ctx.sessions) as s:
        user = s.scalar(select(UserRow).where(UserRow.username == body.username))
        now = datetime.now(UTC)
        locked = bool(user and user.locked_until and user.locked_until.replace(tzinfo=UTC) > now)
        ok = verify_password(body.password, user.password_hash if user else None)  # constant work either way
        if not (user and ok and user.enabled and not locked):
            if user and not locked:
                user.failed_logins += 1
                if user.failed_logins >= cfg.max_failed_logins:
                    user.locked_until = now + timedelta(minutes=cfg.lockout_minutes)
                    user.failed_logins = 0
            outcome_user = body.username[:64]
            s.flush()
            from app.audit.service import record_audit
            record_audit(s, actor=outcome_user, action="auth.login", outcome="failure", source_ip=ip,
                         details={"locked": locked})
            s.commit()
            raise fail
        user.failed_logins, user.locked_until, user.last_login = 0, None, now
        token, _, exp = create_token(ctx.secret, username=user.username, role=user.role,
                                     version=user.token_version, ttl_minutes=cfg.token_ttl_minutes)
        out = TokenOut(access_token=token, expires_at=exp.isoformat(), role=user.role, username=user.username)
        from app.audit.service import record_audit
        record_audit(s, actor=user.username, action="auth.login", source_ip=ip)
        return out


@router.get("/auth/me")
def me(user: Annotated[CurrentUser, Depends(current_user)]) -> dict:
    from app.auth.rbac import PERMISSIONS
    return {"username": user.username, "role": user.role, "permissions": sorted(PERMISSIONS.get(user.role, []))}


@router.post("/auth/logout", status_code=204)
def logout(request: Request, ctx: Ctx, user: Annotated[CurrentUser, Depends(current_user)]) -> None:
    from app.auth.security import decode_token
    claims = decode_token(ctx.secret, request.headers["authorization"].split(" ", 1)[1])
    with session_scope(ctx.sessions) as s:
        s.merge(RevokedToken(jti=user.jti, expires_at=datetime.fromtimestamp(claims["exp"], UTC)))
        s.query(RevokedToken).filter(RevokedToken.expires_at < datetime.now(UTC)).delete()
    audit(ctx, request, user.username, "auth.logout")


@router.get("/users", response_model=Page[dict])
def list_users(ctx: Ctx, paging: Paging, _: Annotated[CurrentUser, Depends(require("users:manage"))]) -> dict:
    limit, offset = paging
    with session_scope(ctx.sessions) as s:
        total = s.scalar(select(func.count()).select_from(UserRow)) or 0
        rows = s.scalars(select(UserRow).order_by(UserRow.id).limit(limit).offset(offset))
        return {"items": [user_out(u) for u in rows], "total": total, "limit": limit, "offset": offset}


@router.post("/users", status_code=201)
def create_user(body: UserCreate, request: Request, ctx: Ctx,
                admin: Annotated[CurrentUser, Depends(require("users:manage"))]) -> dict:
    pw_hash = hash_password(body.password)
    with session_scope(ctx.sessions) as s:
        if s.scalar(select(UserRow).where(UserRow.username == body.username)):
            raise HTTPException(409, "User already exists")
        u = UserRow(username=body.username, password_hash=pw_hash, role=body.role)
        s.add(u)
        s.flush()
        out = user_out(u)
    audit(ctx, request, admin.username, "user.create", body.username, details={"role": body.role})
    return out


def _admins(s) -> int:
    return s.scalar(select(func.count()).select_from(UserRow).where(UserRow.role == "admin", UserRow.enabled.is_(True))) or 0


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserUpdate, request: Request, ctx: Ctx,
                admin: Annotated[CurrentUser, Depends(require("users:manage"))]) -> dict:
    with session_scope(ctx.sessions) as s:
        u = s.get(UserRow, user_id)
        if u is None:
            raise HTTPException(404, "Not found")
        demoting = u.role == "admin" and u.enabled and (body.role not in (None, "admin") or body.enabled is False)
        if demoting and _admins(s) <= 1:
            raise HTTPException(409, "Cannot remove the last active admin")
        if u.id == admin.id and body.enabled is False:
            raise HTTPException(409, "Cannot disable yourself")
        changed = []
        if body.role is not None and body.role != u.role:
            u.role, changed = body.role, [*changed, "role"]
        if body.enabled is not None and body.enabled != u.enabled:
            u.enabled, changed = body.enabled, [*changed, "enabled"]
        if body.password is not None:
            try:
                u.password_hash = hash_password(body.password)
            except ValidationFailed as exc:
                raise HTTPException(422, exc.detail) from exc
            changed.append("password")
        if changed:
            u.token_version += 1  # revokes existing sessions on any privilege/credential change
        out = user_out(u)
    audit(ctx, request, admin.username, "user.update", out["username"], details={"changed": changed})
    return out


@router.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: int, request: Request, ctx: Ctx,
                admin: Annotated[CurrentUser, Depends(require("users:manage"))]) -> None:
    with session_scope(ctx.sessions) as s:
        u = s.get(UserRow, user_id)
        if u is None:
            raise HTTPException(404, "Not found")
        if u.id == admin.id:
            raise HTTPException(409, "Cannot delete yourself")
        if u.role == "admin" and u.enabled and _admins(s) <= 1:
            raise HTTPException(409, "Cannot remove the last active admin")
        name = u.username
        s.delete(u)
    audit(ctx, request, admin.username, "user.delete", name)
