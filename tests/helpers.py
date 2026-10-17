import base64
import json
import os
import time

from forgemesh_pay_per_crawl.core import keccak256_hex
from forgemesh_pay_per_crawl.core.x402 import b64url
from tests.conftest import PAY_TO


def make_auth(value="10000", to=PAY_TO, valid_before=None):
    return {"from": "0x" + "b" * 40, "to": to, "value": value, "validAfter": "0",
            "validBefore": str(valid_before or int(time.time()) + 300), "nonce": "0x" + os.urandom(32).hex()}


def v2_header(auth, url, network="eip155:8453"):
    p = {"x402Version": 2, "resource": {"url": url},
         "accepted": {"scheme": "exact", "network": network, "amount": "10000", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                      "payTo": PAY_TO, "maxTimeoutSeconds": 300, "extra": {"name": "USD Coin", "version": "2"}},
         "payload": {"signature": "0xsig", "authorization": auth}}
    return base64.b64encode(json.dumps(p).encode()).decode()


def v1_header(auth):
    p = {"x402Version": 1, "scheme": "exact", "network": "base", "payload": {"signature": "0xsig", "authorization": auth}}
    return base64.b64encode(json.dumps(p).encode()).decode()


def mpp_header(www_authenticate, realm, value="10000"):
    import re
    m = re.search(r'id="([^"]+)".*expires="([^"]+)".*request="([^"]+)"', www_authenticate)
    cid, exp, req = m.groups()
    cred = {"challenge": {"id": cid, "realm": realm, "method": "evm", "intent": "charge", "expires": exp, "request": req},
            "payload": {"type": "authorization", "from": "0x" + "d" * 40, "to": PAY_TO, "value": value, "validAfter": "0",
                        "validBefore": str(int(time.time()) + 300), "nonce": keccak256_hex(cid + realm), "signature": "0xsig"}}
    return "Payment " + b64url(json.dumps(cred).encode())
