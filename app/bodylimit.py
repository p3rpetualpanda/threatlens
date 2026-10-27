"""Cap request bodies by the bytes actually read, not by the Content-Length header.

A chunked body has no length header and FastAPI reads a JSON body whole, so the count has to
happen on the stream. Over the cap this sends the 413 itself (with the security headers from
`headers`) and tells the app the client went away; whatever the app then tries to send is dropped.
(Raising from `receive` does not work: FastAPI turns any error while reading a body into a 400.)
shortcut: counts the bytes ASGI delivers, so a gzip body is limited at its compressed size.
"""

from __future__ import annotations

from collections.abc import Callable

from starlette.requests import ClientDisconnect
from starlette.types import ASGIApp, Message, Receive, Scope, Send

DEFAULT_LIMIT = 64 * 1024  # the biggest form (comment, split) is 32 KB
INGEST_LIMIT = 10 * 1024 * 1024
LIMITS = {"/api/v1/login": 4096, "/login": 4096, "/api/v1/findings": INGEST_LIMIT}


class BodyLimit:
    def __init__(self, app: ASGIApp, headers: Callable[[Scope], dict[str, str]]) -> None:
        self.app = app
        self.headers = headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = LIMITS.get(scope["path"], DEFAULT_LIMIT)
        declared = dict(scope["headers"]).get(b"content-length", b"")
        too_big = declared.isdigit() and int(declared) > limit
        seen = 0
        started = refused = False

        async def refuse() -> None:
            nonlocal refused
            refused = True
            if started:  # a response is already on the wire; all that is left is to stop reading
                return
            body = b'{"detail":"request body too large"}'
            fields = {"content-type": "application/json", "content-length": str(len(body))}
            fields.update(self.headers(scope))
            raw = [(k.encode(), v.encode()) for k, v in fields.items()]
            await send({"type": "http.response.start", "status": 413, "headers": raw})
            await send({"type": "http.response.body", "body": body})

        async def counted() -> Message:
            nonlocal seen
            if refused:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if too_big or seen > limit:
                    await refuse()
                    return {"type": "http.disconnect"}
            return message

        async def watching(message: Message) -> None:
            nonlocal started
            if refused:
                return
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self.app(scope, counted, watching)
        except ClientDisconnect:  # the app noticed the disconnect we reported
            if not refused:
                raise
