"""API dependencies: app context, authentication, authorisation, rate limiting, audit helper."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.api.ratelimit import RateLimiter
from app.audit.service import record_audit
from app.auth.rbac import has_permission
from app.auth.security import decode_token
from app.core.config import Settings
from app.database.base import session_scope
from app.database.models import RevokedToken, UserRow
from app.ids.engine import IDSEngine

log = logging.getLogger(__name__)
_bearer = HTTPBearer(auto_error=False)


@dataclass
class AppContext:
    settings: Settings
    sessions: sessionmaker[Session]
    facade: Any  # LocalFacade or ExecutorClient (same method names)
    ids: IDSEngine
    limiter: RateLimiter
    secret: str


@dataclass
class CurrentUser:
    id: int
    username: str
    role: str
    jti: str


def ctx_of(request: Request) -> AppContext:
    return request.app.state.ctx


Ctx = Annotated[AppContext, Depends(ctx_of)]


def client_ip(request: Request) -> str:
    # X-Forwarded-For is deliberately ignored: it is attacker-controlled unless a trusted proxy sets it.
    return request.client.host if request.client else "unknown"


def audit(ctx: AppContext, request: Request, actor: str, action: str, target: str = "", outcome: str = "success",
          details: dict | None = None) -> None:
    with session_scope(ctx.sessions) as s:
        record_audit(s, actor=actor, action=action, target=target[:256], outcome=outcome,
                     source_ip=client_ip(request), details=details or {})


def rate_limit(ctx: AppContext, bucket: str, key: str, limit: int) -> None:
    ok, retry = ctx.limiter.hit(bucket, key, limit)
    if not ok:
        raise HTTPException(429, "Too many requests", headers={"Retry-After": str(retry)})


def global_limit(request: Request, ctx: Ctx) -> None:
    rate_limit(ctx, "global", client_ip(request), ctx.settings.api.rate_limit_per_minute)


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def current_user(request: Request, ctx: Ctx,
                 creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]) -> CurrentUser:
    unauthorized = HTTPException(401, "Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    if creds is None:
        raise unauthorized
    try:
        claims = decode_token(ctx.secret, creds.credentials)
    except jwt.PyJWTError:
        raise unauthorized from None
    with session_scope(ctx.sessions) as s:
        if s.get(RevokedToken, claims["jti"]) is not None:
            raise unauthorized
        user = s.scalar(select(UserRow).where(UserRow.username == claims["sub"]))
        if user is None or not user.enabled or user.token_version != claims.get("ver"):
            raise unauthorized
        if user.locked_until and _utc(user.locked_until) > datetime.now(UTC):
            raise unauthorized
        cu = CurrentUser(user.id, user.username, user.role, claims["jti"])  # role comes from DB, not the token
    request.state.user = cu
    return cu


def require(permission: str):
    """Dependency factory: authenticate, rate-limit writes, then authorise by permission."""

    def dep(request: Request, ctx: Ctx, user: Annotated[CurrentUser, Depends(current_user)]) -> CurrentUser:
        if not has_permission(user.role, permission):
            audit(ctx, request, user.username, "auth.denied", target=permission, outcome="denied")
            raise HTTPException(403, "Forbidden")
        if permission.endswith((":write", ":manage", ":apply")) or permission == "settings:write":
            rate_limit(ctx, "write", user.username, ctx.settings.api.write_rate_per_minute)
        return user

    return dep


def page_params(limit: int = 50, offset: int = 0) -> tuple[int, int]:
    if not 1 <= limit <= 200 or offset < 0 or offset > 10_000_000:
        raise HTTPException(422, "limit must be 1-200 and offset >= 0")
    return limit, offset


Paging = Annotated[tuple[int, int], Depends(page_params)]
