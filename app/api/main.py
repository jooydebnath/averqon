"""FastAPI application factory."""

from __future__ import annotations

import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.api.deps import AppContext, global_limit
from app.api.ratelimit import RateLimiter
from app.api.routes import auth, firewall, system
from app.core.config import Settings
from app.core.errors import (
    AverqonError,
    BackendError,
    ConfigError,
    PermissionDenied,
    ValidationFailed,
)
from app.database.base import Base, make_engine, make_session_factory
from app.executor.protocol import ExecutorClient
from app.ids.engine import IDSEngine
from app.services.facade import LocalFacade
from app.services.firewall_manager import NotFound

log = logging.getLogger(__name__)
_STATUS = {ValidationFailed: 422, NotFound: 404, PermissionDenied: 403, BackendError: 502, ConfigError: 500}
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def _err(status: int, code: str, message: str, request: Request, extra: dict | None = None) -> JSONResponse:
    rid = getattr(request.state, "request_id", "")
    body = {"error": {"code": code, "message": message, "request_id": rid, **(extra or {})}}
    return JSONResponse(body, status_code=status)


def build_context(settings: Settings, facade=None, sessions=None) -> AppContext:
    if sessions is None:
        engine = make_engine(settings.database.url, echo=settings.database.echo)
        if engine.dialect.name == "sqlite":
            Base.metadata.create_all(engine)
        sessions = make_session_factory(engine)
    if facade is None:
        if settings.api.executor_socket:
            facade = ExecutorClient(settings.api.executor_socket)
        elif settings.environment == "production":
            raise ConfigError("production requires api.executor_socket (privileged executor)")
        else:
            from app.core.container import build_manager
            facade = LocalFacade(build_manager(settings))
    return AppContext(settings, sessions, facade, IDSEngine(sessions, None, settings.ids),  # type: ignore[arg-type]
                      RateLimiter(), settings.require_secret())


def create_app(settings: Settings, ctx: AppContext | None = None) -> FastAPI:
    app = FastAPI(title="Averqon", version=__version__, docs_url=None if settings.environment == "production" else "/docs",
                  redoc_url=None, openapi_url=None if settings.environment == "production" else "/openapi.json")
    app.state.ctx = ctx or build_context(settings)
    if settings.api.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=settings.api.cors_origins, allow_credentials=False,
                           allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                           allow_headers=["Authorization", "Content-Type"], max_age=600)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        request.state.request_id = uuid.uuid4().hex[:12]
        length = request.headers.get("content-length")
        if length and (not length.isdigit() or int(length) > settings.api.max_body_bytes):
            return _err(413, "payload_too_large", "Request body too large", request)
        resp = await call_next(request)
        for k, val in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, val)
        resp.headers["X-Request-ID"] = request.state.request_id
        return resp

    @app.exception_handler(AverqonError)
    async def _domain(request: Request, exc: AverqonError) -> JSONResponse:
        status = next((s for c, s in _STATUS.items() if isinstance(exc, c)), 500)
        msg = exc.detail if status < 500 or isinstance(exc, BackendError) else "Internal error"
        if status >= 500:
            log.error("domain error %s: %s", exc.code, exc.detail)
        return _err(status, exc.code, msg if status != 502 else "Firewall operation failed: " + exc.detail[:200], request)

    @app.exception_handler(RequestValidationError)
    async def _val(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Never echo submitted values back: report only where and why.
        errs = [{"loc": [str(x) for x in e["loc"]], "msg": e["msg"]} for e in exc.errors()]
        return _err(422, "validation_error", "Invalid request", request, {"fields": errs})

    @app.exception_handler(ValidationError)
    async def _pyd(request: Request, exc: ValidationError) -> JSONResponse:
        errs = [{"loc": [str(x) for x in e["loc"]], "msg": e["msg"]} for e in exc.errors()]
        return _err(422, "validation_error", "Invalid request", request, {"fields": errs})

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        resp = _err(exc.status_code, {401: "unauthorized", 403: "forbidden", 404: "not_found", 429: "rate_limited"}
                    .get(exc.status_code, "error"), str(exc.detail), request)
        for k, val in (exc.headers or {}).items():
            resp.headers[k] = val
        return resp

    @app.exception_handler(Exception)
    async def _any(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error on %s %s", request.method, request.url.path)
        return _err(500, "internal_error", "Internal error", request)

    from fastapi import Depends
    for r in (auth.router, firewall.router, system.router):
        app.include_router(r, dependencies=[Depends(global_limit)])
    return app
