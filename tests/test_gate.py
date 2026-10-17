"""Gate behaviour with the real default transport against the mock facilitator."""
import base64
import json
import re

import pytest

from forgemesh_pay_per_crawl.core import Config, FileNonceLock, Gate, Request
from tests.conftest import PAY_TO, UA_GPT, UA_HUMAN
from tests.helpers import make_auth, mpp_header, v1_header, v2_header


class NoDNS:
    def reverse(self, ip):
        return None

    def forward(self, host):
        return []


def gate(mock, **kw):
    cfg = Config(pay_to=PAY_TO, mode=kw.pop("mode", "gate"), facilitator_url=mock.url, mpp_secret="s", site_name="Example", **kw)
    return Gate(cfg, resolver=NoDNS())


def req(ua=UA_GPT, path="/paid-test/", method="GET", headers=None, ip="198.51.100.7", query=""):
    h = {"user-agent": ua, "host": "example.test"}
    h.update(headers or {})
    return Request(method=method, path=path, query=query, scheme="https", host="example.test", headers=h, ip=ip)


def hdr(resp, name):
    return next((v for k, v in resp.headers if k.lower() == name.lower()), None)


def test_human_passes_gptbot_gets_402(mock):
    g = gate(mock)
    assert g.handle(req(UA_HUMAN, headers={"accept": "text/html"})).response is None
    r = g.handle(req()).response
    assert r.status == 402
    assert hdr(r, "content-type") == "application/json; charset=utf-8" and "no-store" in hdr(r, "cache-control")
    env = json.loads(base64.b64decode(hdr(r, "payment-required")))
    assert (env["x402Version"], env["accepts"][0]["network"], env["accepts"][0]["amount"], env["accepts"][0]["payTo"]) == (2, "eip155:8453", "10000", PAY_TO)
    assert env["resource"]["url"] == "https://example.test/paid-test/"
    body = json.loads(r.body)
    assert body["x402Version"] == 1 and body["accepts"][0]["network"] == "base" and body["accepts"][0]["resource"] == "https://example.test/paid-test/"
    assert re.search(r'Payment id=".*realm="example.test".*method="evm".*intent="charge".*request="', hdr(r, "www-authenticate"))
    assert "x402.json" in hdr(r, "link") and "describedby" in hdr(r, "link")
    assert g.handle(req(query="p=1")).response.status == 402
    assert json.loads(g.handle(req(query="p=1")).response.body)["accepts"][0]["resource"].endswith("/paid-test/?p=1")


def test_head_is_gated_like_get_with_no_body(mock):
    g = gate(mock)
    r = g.handle(req(method="HEAD")).response
    assert r.status == 402 and r.body == b"" and hdr(r, "payment-required")
    assert g.handle(req(method="POST")).response is None  # unsafe methods are not gated


def test_social_monitor_free_search_fake_demoted(mock):
    g = gate(mock)
    assert g.handle(req("facebookexternalhit/1.1")).response is None
    assert g.handle(req("UptimeRobot/2.0")).response is None
    fake = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    assert g.handle(req(fake)).response.status == 402


def test_monitor_mode_never_blocks_but_records(mock):
    events = []
    g = gate(mock, mode="monitor", on_event=events.append)
    assert g.handle(req()).response is None
    assert events[-1]["status"] == "monitor" and events[-1]["amount_units"] == 10000
    assert g.stats.totals()["hits"] == 1


def test_overrides_class_policy_allow_paths_exempt(mock):
    g = gate(mock, bot_overrides={"GPTBot": "block", "curl": "free"}, class_policy={"ai": "paid"}, allow_paths=["/open"])
    assert g.handle(req()).response.status == 403
    assert g.handle(req("curl/8.5")).response is None
    g2 = gate(mock, class_policy={"ai": "free", "automation": "block"}, allow_paths=["/open"])
    assert g2.handle(req()).response is None
    assert g2.handle(req("curl/8.5")).response.status == 403
    assert g2.handle(req("curl/8.5", path="/open/x")).response is None
    for p in ("/robots.txt", "/sitemap.xml", "/favicon.ico", "/.well-known/security.txt"):
        assert gate(mock).handle(req("curl/8.5", path=p)).response is None


def test_discovery_served_free_to_bots(mock):
    g = gate(mock, pages=[("Paid test post", "/paid-test/")])
    m = g.handle(req(path="/.well-known/x402.json")).response
    j = json.loads(m.body)
    assert m.status == 200 and j["x402Version"] == 2 and j["resources"][0]["accepts"][0]["payTo"] == PAY_TO and j["resources"][0]["metadata"]["paid"] is True
    assert j["provider"]["contact"] is None
    llms = g.handle(req(path="/llms.txt")).response
    assert llms.status == 200 and b"Paid test post" in llms.body
    ag = g.handle(req(path="/agents.txt")).response
    assert b"Payments: required" in ag.body
    assert g.handle(req(path="/.well-known/x402.json", method="HEAD")).response.body == b""
    off = gate(mock, discovery=False)
    assert off.handle(req(path="/llms.txt")).response is None
    assert "x402.json" in gate(mock).discovery(req()).robots_lines()
    assert json.loads(gate(mock, mode="monitor").handle(req(path="/.well-known/x402.json")).response.body)["resources"][0]["metadata"]["paid"] is False


def test_v2_paid_then_replay_rejected(mock):
    g = gate(mock)
    a = make_auth()
    h = {"payment-signature": v2_header(a, "https://example.test/paid-test/")}
    d = g.handle(req(headers=h))
    assert d.response is None
    names = [k for k, _ in d.headers]
    assert "PAYMENT-RESPONSE" in names and "X-PAYMENT-RESPONSE" in names and "Payment-Receipt" not in names
    settle = json.loads(base64.b64decode(dict(d.headers)["PAYMENT-RESPONSE"]))
    assert settle["success"] and settle["transaction"].startswith("0xabab")
    assert dict(d.headers)["Cache-Control"] == "private, no-store"
    assert len(mock.calls("/verify")) == 1 and len(mock.calls("/settle")) == 1
    r = g.handle(req(headers=h)).response
    assert r.status == 402 and json.loads(r.body)["invalidReason"] == "payment_in_flight"
    assert len(mock.calls("/settle")) == 1
    assert g.stats.totals()["revenue_units"] == 10000


def test_v1_forwarded_in_v1_shape_and_underpay_rejected(mock):
    g = gate(mock)
    d = g.handle(req("x402-fetch/1.2.0", headers={"x-payment": v1_header(make_auth())}))
    assert d.response is None
    assert mock.calls("/settle")[-1]["body"]["x402Version"] == 1 and mock.calls("/settle")[-1]["body"]["paymentRequirements"]["network"] == "base"
    r = g.handle(req("x402-fetch/1.2.0", headers={"x-payment": v1_header(make_auth("5000"))})).response
    assert r.status == 402 and json.loads(r.body)["invalidReason"] == "wrong_amount"


def test_mpp_paid_receipt_replay_and_problem_json(mock):
    g = gate(mock)
    www = hdr(g.handle(req()).response, "www-authenticate")
    cred = mpp_header(www, "example.test")
    d = g.handle(req("mpp-client/1", headers={"authorization": cred}))
    assert d.response is None and "Payment-Receipt" in dict(d.headers)
    rc = json.loads(base64.urlsafe_b64decode(dict(d.headers)["Payment-Receipt"] + "=="))
    assert rc["status"] == "success" and rc["reference"].startswith("0xabab")
    r = g.handle(req("mpp-client/1", headers={"authorization": cred})).response
    assert r.status == 402 and hdr(r, "content-type") == "application/problem+json; charset=utf-8"
    assert json.loads(r.body)["type"].endswith("/payment_in_flight")


def test_facilitator_reject_notx_and_down(mock):
    g = gate(mock)
    mock.mode = "reject"
    r = g.handle(req(headers={"payment-signature": v2_header(make_auth(), "u")})).response
    assert r.status == 402 and json.loads(r.body)["invalidReason"] == "insufficient_funds"
    mock.mode = "notx"
    r = g.handle(req(headers={"payment-signature": v2_header(make_auth(), "u")})).response
    assert r.status == 402 and json.loads(r.body)["invalidReason"] == "settlement_failed"  # never served without a tx


def test_facilitator_down_releases_nonce_for_retry(mock):
    g = gate(mock)
    h = {"payment-signature": v2_header(make_auth(), "u")}
    mock.mode = "down"
    r = g.handle(req(headers=h)).response
    assert r.status == 402 and json.loads(r.body)["invalidReason"] == "facilitator_unreachable"
    mock.mode = "ok"
    assert g.handle(req(headers=h)).response is None  # same authorization retried


def test_payment_on_free_class_is_honoured(mock):
    g = gate(mock)
    d = g.handle(req("facebookexternalhit/1.1", headers={"payment-signature": v2_header(make_auth(), "u")}))
    assert d.response is None and any(k == "PAYMENT-RESPONSE" for k, _ in d.headers)


def test_file_lock_shared_between_gates(mock, tmp_path):
    g1 = Gate(Config(pay_to=PAY_TO, mode="gate", facilitator_url=mock.url, mpp_secret="s"), lock=FileNonceLock(tmp_path), resolver=NoDNS())
    g2 = Gate(Config(pay_to=PAY_TO, mode="gate", facilitator_url=mock.url, mpp_secret="s"), lock=FileNonceLock(tmp_path), resolver=NoDNS())
    h = {"payment-signature": v2_header(make_auth(), "u")}
    assert g1.handle(req(headers=h)).response is None
    assert g2.handle(req(headers=h)).response.status == 402


def test_proxy_ip_header_used_for_classification(mock):
    seen = []

    class R:
        def reverse(self, ip):
            seen.append(ip)

        def forward(self, h):
            return []

    g = Gate(Config(pay_to=PAY_TO, mode="gate", facilitator_url=mock.url, trust_proxy_header="CF-Connecting-IP"), resolver=R())
    # Right-most hop wins: a client-prepended "66.249.66.1" must not be the address we verify.
    g.handle(req("Mozilla/5.0 (compatible; Googlebot/2.1)", headers={"cf-connecting-ip": "66.249.66.1, 203.0.113.50"}, ip="10.0.0.1"))
    assert seen == ["203.0.113.50"]


def test_base_url_pins_realm_and_resource(mock):
    g = gate(mock, base_url="https://real.example")
    r = g.handle(req()).response
    assert json.loads(r.body)["accepts"][0]["resource"] == "https://real.example/paid-test/"
    assert 'realm="real.example"' in hdr(r, "www-authenticate")


def test_config_validation():
    with pytest.raises(ValueError):
        Config(mode="gate")
    with pytest.raises(ValueError):
        Config(pay_to="0x123")
    with pytest.raises(ValueError):
        Config(class_policy={"ai": "maybe"})
    with pytest.raises(ValueError):
        Config.from_dict({"nope": 1})
    assert Config(mode="monitor").mode == "monitor"


def test_forwarded_for_uses_right_most_hop():
    """A client cannot prepend a Googlebot IP to X-Forwarded-For to get the free lane."""
    from forgemesh_pay_per_crawl.core.config import Config
    from forgemesh_pay_per_crawl.core.gate import Gate
    cfg = Config(pay_to="0x" + "ab" * 20, price_usd=0.01, mode="gate", trust_proxy_header="x-forwarded-for")
    gate = Gate(cfg)
    class R:
        ip = "203.0.113.9"
        headers = {"x-forwarded-for": "66.249.66.1, 203.0.113.9", "user-agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"}
    assert gate.client_ip(R()) == "203.0.113.9"


@pytest.mark.parametrize("path,allowed", [
    ("/robots.txt", True), ("/robots.txt.html", False), ("/robots.txt.anything", False),
    ("/llms.txt", True), ("/llms.txtx", False), ("/agents.txt", True), ("/favicon.ico", True),
    ("/sitemap.xml", True), ("/wp-sitemap-posts-post-1.xml", True), ("/sitemap_index.xml", True),
    ("/sitemapfoo", False), ("/sitemap.xml/x", False), ("/a/sitemap.xml", False),
    ("/.well-known/x402.json", True), ("/.well-known/../post", False),
    ("/.well-known/%2e%2e/post", False), ("/.well-known/%2E%2E/post", False), ("/foo%2fbar", False),
    ("/pricing", True), ("/pricing/", True), ("/pricing/plans", True), ("/pricing-secret", False),
    ("//robots.txt", False), ("/post", False), ("/", False),
])
def test_exempt_anchored(mock, path, allowed):
    assert gate(mock, allow_paths=["/pricing"]).exempt(path) is allowed


def test_exempt_allow_path_trailing_slash(mock):
    g = gate(mock, allow_paths=["/docs/"])
    assert g.exempt("/docs/a") and not g.exempt("/docs") and not g.exempt("/docsx")
