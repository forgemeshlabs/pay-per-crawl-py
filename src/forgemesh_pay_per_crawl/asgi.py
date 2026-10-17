"""ASGI middleware for FastAPI, Starlette and any ASGI app.

    app.add_middleware(PayPerCrawlMiddleware, config=Config(pay_to="0x...", mode="gate"))
"""
from __future__ import annotations

import asyncio
from typing import Optional

from .core import Config, Gate, Request, Response


def _request(scope) -> Request:
    headers: dict[str, str] = {}
    for k, v in scope.get("headers", []):
        name = k.decode("latin-1").lower()
        val = v.decode("latin-1")
        headers[name] = f"{headers[name]}, {val}" if name in headers else val
    client = scope.get("client") or ("", 0)
    host = headers.get("host") or ""
    if not host:
        server = scope.get("server") or ("", None)
        host = server[0] + (f":{server[1]}" if server[1] else "")
    return Request(
        method=scope.get("method", "GET"),
        path=(scope.get("raw_path") or scope.get("path", "/").encode()).decode("latin-1").split("?")[0] or "/",
        query=scope.get("query_string", b"").decode("latin-1"),
        scheme=scope.get("scheme", "http"),
        host=host,
        headers=headers,
        ip=client[0] or "",
    )


class PayPerCrawlMiddleware:
    def __init__(self, app, config: Optional[Config] = None, gate: Optional[Gate] = None, **settings):
        self.app = app
        self.gate = gate or Gate(config or Config(**settings))

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        decision = await asyncio.to_thread(self.gate.handle, _request(scope))
        if decision.response is not None:
            r: Response = decision.response
            await send({"type": "http.response.start", "status": r.status,
                        "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in r.headers]})
            await send({"type": "http.response.body", "body": r.body})
            return
        if not decision.headers:
            await self.app(scope, receive, send)
            return
        extra = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in decision.headers]
        names = {k for k, _ in extra}

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                # Ours win over same-named headers from the app (receipts, no-store).
                kept = [(k, v) for k, v in message.get("headers", []) if k.lower() not in names or k.lower() == b"link"]
                message = {**message, "headers": kept + extra}
            await send(message)

        await self.app(scope, receive, send_with_headers)
