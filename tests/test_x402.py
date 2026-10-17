import base64
import json
import time

import pytest

from forgemesh_pay_per_crawl.core import Config, X402, TransportError, build_challenge, keccak256_hex
from forgemesh_pay_per_crawl.core.x402 import b64url, b64url_json, jcs, usd_to_units
from tests.conftest import PAY_TO
from tests.helpers import make_auth, mpp_header, v1_header, v2_header

URL = "https://example.test/post/"


def make(transport=None, **kw):
    cfg = Config(pay_to=PAY_TO, mode="gate", price_usd=0.01, mpp_secret="unit-secret", **kw)
    return X402(cfg, realm="example.test", site_name="Example", manifest_url="https://example.test/.well-known/x402.json", transport=transport)


def test_units_and_default_facilitator():
    assert usd_to_units(0.005) == "5000" and usd_to_units("0.01") == "10000" and usd_to_units(1) == "1000000"
    assert make().facilitator_url() == "https://facilitator.payai.network"
    assert make(facilitator_url="http://x.test/").facilitator_url() == "http://x.test"


def test_402_shapes():
    x = make()
    env = x.envelope_v2(URL, "Example: page")
    a = env["accepts"][0]
    assert env["x402Version"] == 2 and a["amount"] == "10000" and a["network"] == "eip155:8453" and a["payTo"] == PAY_TO
    assert a["extra"] == {"name": "USD Coin", "version": "2"} and env["resource"]["url"] == URL
    b = x.body_v1(URL, "Example: page")
    a = b["accepts"][0]
    assert b["x402Version"] == 1 and a["network"] == "base" and a["maxAmountRequired"] == "10000" and a["resource"] == URL
    assert "invalidReason" not in b and x.body_v1(URL, "d", "Payment rejected", "wrong_amount")["invalidReason"] == "wrong_amount"
    hdr, body, www = build_challenge(x, URL, "d")
    assert json.loads(base64.b64decode(hdr))["x402Version"] == 2 and body["x402Version"] == 1 and www.startswith("Payment id=")


def test_jcs_sorts_keys_and_keeps_slashes():
    assert jcs({"b": 1, "a": ["x/y", {"z": 1, "y": 2}]}) == '{"a":["x/y",{"y":2,"z":1}],"b":1}'


def test_mpp_challenge_round_trip():
    x = make()
    hdr = x.mpp_challenge("Example: page")
    import re
    m = re.match(r'^Payment id="([^"]+)", realm="example.test", method="evm", intent="charge", expires="([^"]+)", request="([^"]+)"$', hdr)
    assert m
    req = b64url_json(m.group(3))
    assert req["amount"] == "10000" and req["methodDetails"]["chainId"] == 8453 and req["recipient"] == PAY_TO
    p = x.extract_payment({"authorization": mpp_header(hdr, "example.test")}, URL)
    assert p["rail"] == "mpp" and "error" not in p and p["payload"]["x402Version"] == 2
    assert p["payload"]["payload"]["authorization"]["nonce"] == keccak256_hex(m.group(1) + "example.test")
    assert x.precheck(p, URL) is None


def test_mpp_rejections():
    x = make()
    hdr = x.mpp_challenge("d")
    import re
    cid, exp, req = re.search(r'id="([^"]+)".*expires="([^"]+)".*request="([^"]+)"', hdr).groups()

    def cred(**ch_over):
        c = {"challenge": {"id": cid, "realm": "example.test", "method": "evm", "intent": "charge", "expires": exp, "request": req},
             "payload": {"type": "authorization", "from": "0x" + "a" * 40, "to": PAY_TO, "value": "10000", "validAfter": "0",
                         "validBefore": "9999999999", "nonce": keccak256_hex(cid + "example.test"), "signature": "0xs"}}
        c["challenge"].update(ch_over)
        return c

    def run(c):
        return x.extract_payment({"authorization": "Payment " + b64url(json.dumps(c).encode())}, URL)

    bad_nonce = cred(); bad_nonce["payload"]["nonce"] = "0x" + "1" * 64
    assert run(bad_nonce)["error"] == "verification-failed"
    assert run(cred(id="tampered"))["error"] == "invalid-challenge"
    assert run(cred(realm="other.test"))["error"] == "invalid-challenge"
    assert run(cred(expires="2020-01-01T00:00:00Z"))["error"] == "payment-expired"
    assert x.extract_payment({"authorization": "Payment !!!"}, URL) is None  # not matching the token grammar
    assert x.extract_payment({"authorization": "Payment " + b64url(b"nope")}, URL)["error"] == "malformed-credential"
    other = make(); other.cfg.mpp_secret = "different"
    assert other.extract_payment({"authorization": "Payment " + b64url(json.dumps(cred()).encode())}, URL)["error"] == "invalid-challenge"
    assert x.extract_payment({"authorization": "Bearer abc"}, URL) is None


def test_extract_and_precheck_v1_v2():
    x = make()
    a = make_auth()
    p = x.extract_payment({"payment-signature": v2_header(a, URL)}, URL)
    assert p["rail"] == "x402v2" and x.precheck(p, URL) is None
    p = x.extract_payment({"x-payment": v1_header(a)}, URL)
    assert p["rail"] == "x402v1" and x.precheck(p, URL) is None
    assert x.extract_payment({}, URL) is None
    assert x.extract_payment({"payment-signature": "zzz"}, URL)["error"] == "malformed_payment_signature"
    assert x.extract_payment({"x-payment": base64.b64encode(b'{"x402Version":2,"payload":{"a":1}}').decode()}, URL)["error"] == "malformed_x_payment"

    def pre(header, hv, **auth_over):
        au = {**make_auth(), **auth_over}
        h = v2_header(au, URL) if header == "payment-signature" else v1_header(au)
        return x.precheck(x.extract_payment({header: h}, URL), URL)

    assert pre("payment-signature", 0, to="0x" + "c" * 40) == "wrong_pay_to"
    assert pre("payment-signature", 0, value="9999") == "wrong_amount"
    assert pre("payment-signature", 0, value="20000") == "wrong_amount"  # v2 is exact
    assert pre("x-payment", 0, value="20000") is None  # v1 may overpay
    assert pre("payment-signature", 0, validBefore="1") == "authorization_expired"
    assert pre("payment-signature", 0, nonce="") == "malformed_authorization"
    bad = x.extract_payment({"payment-signature": v2_header(make_auth(), URL, network="eip155:1")}, URL)
    assert x.precheck(bad, URL) == "wrong_network_or_asset"


class Recorder:
    def __init__(self, fn):
        self.fn, self.calls = fn, []

    def __call__(self, url, body, headers):
        self.calls.append((url, body, headers))
        return self.fn(url, body)


def ok_fn(url, body):
    if url.endswith("/verify"):
        return {"isValid": True, "payer": "0xpayer"}
    return {"success": True, "transaction": "0xtx", "network": "eip155:8453", "payer": "0xpayer"}


def test_facilitator_flow_v2_and_v1():
    t = Recorder(ok_fn)
    x = make(t)
    p = x.extract_payment({"payment-signature": v2_header(make_auth(), URL)}, URL)
    r = x.verify_and_settle(p, URL)
    assert r["ok"] and r["tx"] == "0xtx" and r["payer"] == "0xpayer"
    assert [c[0] for c in t.calls] == ["https://facilitator.payai.network/verify", "https://facilitator.payai.network/settle"]
    body = t.calls[0][1]
    assert body["x402Version"] == 2 and body["paymentRequirements"]["network"] == "eip155:8453" and body["paymentPayload"]["accepted"] == body["paymentRequirements"]
    t.calls.clear()
    p = x.extract_payment({"x-payment": v1_header(make_auth())}, URL)
    assert x.verify_and_settle(p, URL)["ok"]
    body = t.calls[1][1]  # settle
    assert body["x402Version"] == 1 and body["paymentRequirements"]["network"] == "base" and body["paymentRequirements"]["maxAmountRequired"] == "10000"
    assert body["paymentPayload"]["network"] == "base"  # v1 forwarded in v1 shape


def test_facilitator_failures():
    p = make().extract_payment({"x-payment": v1_header(make_auth())}, URL)
    r = make(Recorder(lambda u, b: {"isValid": True} if u.endswith("/verify") else {"success": True, "transaction": ""})).verify_and_settle(p, URL)
    assert not r["ok"] and r["reason"] == "settlement_failed"  # empty tx is not a sale
    r = make(Recorder(lambda u, b: {"isValid": False, "invalidReason": "insufficient_funds"})).verify_and_settle(p, URL)
    assert not r["ok"] and r["reason"] == "insufficient_funds"

    def boom(u, b):
        raise TransportError("timeout")

    r = make(Recorder(boom)).verify_and_settle(p, URL)
    assert r["reason"] == "facilitator_unreachable" and "timeout" in r["detail"]


def test_auth_header_forwarded_to_facilitator():
    t = Recorder(ok_fn)
    x = make(t, facilitator_auth="Bearer k")
    x.verify_and_settle(x.extract_payment({"x-payment": v1_header(make_auth())}, URL), URL)
    assert t.calls[0][2]["Authorization"] == "Bearer k"


def test_default_transport_against_mock(mock):
    x = make(None, facilitator_url=mock.url)
    r = x.verify_and_settle(x.extract_payment({"payment-signature": v2_header(make_auth(), URL)}, URL), URL)
    assert r["ok"] and r["tx"].startswith("0xabab")
    mock.mode = "down"
    r = x.verify_and_settle(x.extract_payment({"payment-signature": v2_header(make_auth(), URL)}, URL), URL)
    assert r["reason"] == "facilitator_unreachable"
