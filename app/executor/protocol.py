"""Executor wire protocol: one JSON request line -> one JSON response line over a unix socket."""

from __future__ import annotations

import json
import socket
from typing import Any

from app.core.errors import AverqonError, BackendError, ValidationFailed
from app.services.firewall_manager import NotFound

MAX_MESSAGE = 1_048_576
_BY_CODE: dict[str, type[AverqonError]] = {
    "validation_error": ValidationFailed, "not_found": NotFound, "backend_error": BackendError,
    "rolled_back": BackendError,
}


def encode(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), default=str).encode() + b"\n"


def error_payload(exc: Exception) -> dict:
    if isinstance(exc, AverqonError):
        return {"ok": False, "error": {"code": exc.code, "message": exc.detail}}
    if isinstance(exc, ValueError):  # pydantic ValidationError and friends
        return {"ok": False, "error": {"code": "validation_error", "message": str(exc).splitlines()[0][:300]}}
    return {"ok": False, "error": {"code": "internal_error", "message": "internal error"}}


def raise_for(payload: dict) -> Any:
    if payload.get("ok"):
        return payload.get("result")
    err = payload.get("error", {})
    cls = _BY_CODE.get(err.get("code", ""), BackendError)
    raise cls(str(err.get("message", "executor error"))[:300])


class ExecutorClient:
    """Blocking client implementing the LocalFacade method names (via __getattr__)."""

    def __init__(self, path: str, timeout: float = 90.0) -> None:
        self.path, self.timeout = path, timeout

    def call(self, method: str, **params: Any) -> Any:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect(self.path)
                s.sendall(encode({"method": method, "params": params}))
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > MAX_MESSAGE:
                        raise BackendError("executor response too large")
        except OSError as exc:
            raise BackendError("privileged executor unavailable") from exc
        try:
            return raise_for(json.loads(buf))
        except json.JSONDecodeError as exc:
            raise BackendError("malformed executor response") from exc

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        return lambda **kw: self.call(name, **kw)
