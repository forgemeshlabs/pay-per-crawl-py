"""Django middleware.

settings.py:

    MIDDLEWARE = ["forgemesh_pay_per_crawl.django.PayPerCrawlMiddleware", ...]  # near the top
    PAY_PER_CRAWL = {"pay_to": "0x...", "mode": "gate", "price_usd": 0.01}
"""
from __future__ import annotations

from typing import Optional

from .core import Config, Gate, Request

_gate: Optional[Gate] = None


def _get_gate() -> Gate:
    global _gate
    if _gate is None:
        from django.conf import settings  # imported late so the module loads without Django configured
        _gate = Gate(Config.from_dict(dict(getattr(settings, "PAY_PER_CRAWL", {}))))
    return _gate


class PayPerCrawlMiddleware:
    sync_capable = True
    async_capable = False

    def __init__(self, get_response, gate: Optional[Gate] = None):
        self.get_response = get_response
        self.gate = gate or _get_gate()

    @staticmethod
    def _host(request) -> str:
        try:
            return request.get_host()
        except Exception:  # DisallowedHost: Django will answer 400 itself; do not fail the gate
            return request.META.get("HTTP_HOST") or request.META.get("SERVER_NAME", "")

    @classmethod
    def _request(cls, request) -> Request:
        headers = {}
        for k, v in request.META.items():
            if k.startswith("HTTP_"):
                headers[k[5:].replace("_", "-").lower()] = str(v)
        if request.META.get("CONTENT_TYPE"):
            headers["content-type"] = request.META["CONTENT_TYPE"]
        return Request(
            method=request.method or "GET",
            path=request.path,
            query=request.META.get("QUERY_STRING", ""),
            scheme=request.scheme,
            host=cls._host(request),
            headers=headers,
            ip=request.META.get("REMOTE_ADDR", ""),
        )

    def __call__(self, request):
        from django.http import HttpResponse
        decision = self.gate.handle(self._request(request))
        if decision.response is not None:
            r = decision.response
            resp = HttpResponse(r.body, status=r.status)
            for k, v in r.headers:
                if k.lower() == "content-type":
                    resp["Content-Type"] = v
                elif k.lower() != "content-length":
                    resp[k] = v
            return resp
        response = self.get_response(request)
        for k, v in decision.headers:
            response[k] = v
        return response
