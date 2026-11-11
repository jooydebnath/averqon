"""Privileged executor: the only process that touches the kernel firewall.

PRIVILEGED: runs as root (or with CAP_NET_ADMIN). Exposes ONLY the allow-listed facade methods
on a unix socket that is mode 0660 and additionally verifies the peer's uid via SO_PEERCRED.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import socket
import struct
from pathlib import Path
from typing import Any

from app.executor.protocol import MAX_MESSAGE, encode, error_payload
from app.services.facade import LocalFacade

log = logging.getLogger(__name__)


def peer_uid(sock: socket.socket) -> int:
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", creds)[1]


class ExecutorServer:
    def __init__(self, facade: LocalFacade, socket_path: Path, allowed_uids: set[int], socket_group: str | None = None) -> None:
        self.facade, self.path, self.allowed = facade, socket_path, allowed_uids
        self.group = socket_group
        self._server: asyncio.Server | None = None

    def dispatch(self, request: Any) -> dict:
        try:
            if not isinstance(request, dict):
                raise ValueError("request must be an object")  # noqa: TRY004
            method, params = request.get("method"), request.get("params", {})
            if method not in LocalFacade.EXPORTED or not isinstance(params, dict):
                raise ValueError("unknown method")
            fn = getattr(self.facade, method)
            bound = inspect.signature(fn).bind(**params)  # rejects unexpected / missing params
            log.info("executor call: %s", method)
            return {"ok": True, "result": fn(*bound.args, **bound.kwargs)}
        except TypeError as exc:
            return {"ok": False, "error": {"code": "validation_error", "message": f"bad parameters: {exc}"[:200]}}
        except Exception as exc:
            if not isinstance(exc, ValueError):
                log.exception("executor method failed")
            return error_payload(exc)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            sock = writer.get_extra_info("socket")
            uid = peer_uid(sock)
            if uid not in self.allowed:
                log.warning("rejected executor connection from uid %s", uid)
                return
            line = await asyncio.wait_for(reader.readline(), 10)
            if len(line) > MAX_MESSAGE or not line:
                return
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                writer.write(encode({"ok": False, "error": {"code": "validation_error", "message": "invalid json"}}))
            else:
                # Firewall changes are blocking subprocess work: run off the event loop.
                writer.write(encode(await asyncio.to_thread(self.dispatch, req)))
            await writer.drain()
        except (TimeoutError, ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        if self.path.exists() or self.path.is_symlink():
            self.path.unlink()
        old = os.umask(0o117)  # socket created 0660
        try:
            self._server = await asyncio.start_unix_server(self._handle, path=str(self.path), limit=MAX_MESSAGE)
        finally:
            os.umask(old)
        if self.group:
            import grp
            os.chown(self.path, -1, grp.getgrnam(self.group).gr_gid)
        log.info("executor listening on %s", self.path)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self.path.unlink(missing_ok=True)
