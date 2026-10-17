"""Each adapter against the mock facilitator, in-process."""
import base64
import json

import pytest

from forgemesh_pay_per_crawl import Config
from tests.conftest import PAY_TO, UA_GPT, UA_HUMAN
from tests.helpers import make_auth, v2_header


def cfg(mock, **kw):
    return Config(pay_to=PAY_TO, mode="gate", facilitator_url=mock.url, mpp_secret="s", site_name="Ex", **kw)


def check_flow(get, head, mock):
    r = get("/paid-test/", UA_GPT)
    assert r.status_code == 402 and json.loads(base64.b64decode(r.headers["payment-required"]))["accepts"][0]["amount"] == "10000"
    assert head("/paid-test/", UA_GPT).status_code == 402
    assert get("/paid-test/", UA_HUMAN, {"accept": "text/html"}).status_code == 200
    ok = get("/paid-test/", UA_GPT, {"payment-signature": v2_header(make_auth(), "http://testserver/paid-test/")})
    assert ok.status_code == 200 and "ZZPAIDZZ" in ok.text
    assert json.loads(base64.b64decode(ok.headers["payment-response"]))["transaction"].startswith("0xabab")
    assert ok.headers["x-payment-response"] and "no-store" in ok.headers["cache-control"]
    assert get("/.well-known/x402.json", UA_GPT).status_code == 200
    assert "ZZPAIDZZ" not in get("/paid-test/", UA_GPT).text


def test_asgi_fastapi(mock):
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse
    from fastapi.testclient import TestClient
    from forgemesh_pay_per_crawl.asgi import PayPerCrawlMiddleware

    app = FastAPI()
    app.add_middleware(PayPerCrawlMiddleware, config=cfg(mock))

    @app.get("/paid-test/", response_class=HTMLResponse)
    def p():
        return "<p>ZZPAIDZZ</p>"

    c = TestClient(app)
    check_flow(lambda path, ua, h=None: c.get(path, headers={"user-agent": ua, **(h or {})}),
               lambda path, ua: c.head(path, headers={"user-agent": ua}), mock)


def test_asgi_kwargs_and_non_http_scope(mock):
    import asyncio
    from forgemesh_pay_per_crawl.asgi import PayPerCrawlMiddleware

    seen = []

    async def app(scope, receive, send):
        seen.append(scope["type"])

    mw = PayPerCrawlMiddleware(app, pay_to=PAY_TO, mode="gate", facilitator_url=mock.url)
    asyncio.run(mw({"type": "lifespan"}, None, None))
    assert seen == ["lifespan"]


def test_wsgi_flask(mock):
    from flask import Flask
    from forgemesh_pay_per_crawl.wsgi import PayPerCrawlWSGI

    app = Flask(__name__)
    app.wsgi_app = PayPerCrawlWSGI(app.wsgi_app, cfg(mock))

    @app.get("/paid-test/")
    def p():
        return "<p>ZZPAIDZZ</p>"

    c = app.test_client()
    check_flow(lambda path, ua, h=None: c.get(path, headers={"User-Agent": ua, **(h or {})}),
               lambda path, ua: c.head(path, headers={"User-Agent": ua}), mock)


def test_django(mock):
    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(
            DEBUG=True, SECRET_KEY="x", ROOT_URLCONF=__name__, ALLOWED_HOSTS=["*"],
            MIDDLEWARE=["forgemesh_pay_per_crawl.django.PayPerCrawlMiddleware"],
            PAY_PER_CRAWL={"pay_to": PAY_TO, "mode": "gate", "facilitator_url": mock.url, "mpp_secret": "s", "site_name": "Ex"},
        )
        django.setup()
    from django.test import Client
    c = Client()
    check_flow(lambda path, ua, h=None: _wrap(c.get(path, HTTP_USER_AGENT=ua, **{("HTTP_" + k.upper().replace("-", "_")): v for k, v in (h or {}).items()})),
               lambda path, ua: _wrap(c.head(path, HTTP_USER_AGENT=ua)), mock)


class _wrap:
    def __init__(self, r):
        self.status_code, self.text, self.headers = r.status_code, r.content.decode(), {k.lower(): v for k, v in r.items()}


def p(request):
    from django.http import HttpResponse
    return HttpResponse("<p>ZZPAIDZZ</p>")


def urlpatterns_():
    from django.urls import path
    return [path("paid-test/", p)]


urlpatterns = urlpatterns_()
