"""WSGI middleware for Flask and any WSGI app.

    app.wsgi_app = PayPerCrawlWSGI(app.wsgi_app, Config(pay_to="0x...", mode="gate"))
"""
from __future__ import annotations

from typing import Optional

from .core import Config, Gate, Request

_STATUS = {200: "200 OK", 402: "402 Payment Required", 403: "403 Forbidden"}


def _request(environ) -> Request:
    headers = {}
    for k, v in environ.items():
        if k.startswith("HTTP_"):
            headers[k[5:].replace("_", "-").lower()] = str(v)
    if environ.get("CONTENT_TYPE"):
        headers["content-type"] = environ["CONTENT_TYPE"]
    host = environ.get("HTTP_HOST") or environ.get("SERVER_NAME", "")
    if not environ.get("HTTP_HOST") and environ.get("SERVER_PORT") not in (None, "80", "443"):
        host += ":" + environ["SERVER_PORT"]
    return Request(
        method=environ.get("REQUEST_METHOD", "GET"),
        path=environ.get("PATH_INFO", "/") or "/",
        query=environ.get("QUERY_STRING", ""),
        scheme=environ.get("wsgi.url_scheme", "http"),
        host=host,
        headers=headers,
        ip=environ.get("REMOTE_ADDR", ""),
    )


class PayPerCrawlWSGI:
    def __init__(self, app, config: Optional[Config] = None, gate: Optional[Gate] = None, **settings):
        self.app = app
        self.gate = gate or Gate(config or Config(**settings))

    def __call__(self, environ, start_response):
        # SCRIPT_NAME mounts: gate on the full path the client used.
        req = _request(environ)
        script = environ.get("SCRIPT_NAME", "")
        if script:
            req.path = script.rstrip("/") + req.path
        decision = self.gate.handle(req)
        if decision.response is not None:
            r = decision.response
            start_response(_STATUS.get(r.status, f"{r.status} Status"), list(r.headers))
            return [r.body]
        if not decision.headers:
            return self.app(environ, start_response)
        names = {k.lower() for k, _ in decision.headers}

        def start(status, headers, exc_info=None):
            kept = [(k, v) for k, v in headers if k.lower() not in names or k.lower() == "link"]
            return start_response(status, kept + list(decision.headers), exc_info)

        return self.app(environ, start)
