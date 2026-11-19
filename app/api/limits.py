"""Request body size enforcement that does not trust the Content-Length header."""

from __future__ import annotations

from fastapi import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodyTooLarge(HTTPException):
    """Raised while reading a request body that exceeds the configured limit.

    An ``HTTPException`` so FastAPI's body parser re-raises it (any other exception becomes a 400).
    """

    def __init__(self) -> None:
        super().__init__(413, "Request body too large")


class BodyLimitMiddleware:
    """Count body bytes as they are read, so chunked uploads (no Content-Length) are limited too.

    Raises ``BodyTooLarge`` from ``receive``; the app's HTTP exception handler renders the 413.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise BodyTooLarge
            return message

        await self.app(scope, limited_receive, send)
