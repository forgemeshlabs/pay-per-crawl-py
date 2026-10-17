"""Integration matrix: real HTTP servers (uvicorn+FastAPI, Flask dev server) with the mock facilitator.

Mirrors the WordPress plugin's integration.sh: same checks, same expectations.
"""
import base64
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.conftest import PAY_TO, UA_GPT, UA_HUMAN
from tests.helpers import make_auth, mpp_header, v1_header, v2_header

ROOT = Path(__file__).resolve().parent.parent


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module", params=["fastapi", "flask"])
def server(request, mock):
    port = free_port()
    env = {**os.environ, "PPC_PAY_TO": PAY_TO, "PPC_MODE": "gate", "PPC_FACILITATOR": mock.url, "PPC_MPP_SECRET": "integration-secret",
           "PYTHONPATH": f"{ROOT}/src:{ROOT}"}
    if request.param == "fastapi":
        cmd = [sys.executable, "-m", "uvicorn", "examples.fastapi_app:app", "--port", str(port), "--log-level", "warning"]
    else:
        cmd = [sys.executable, "-m", "flask", "--app", "examples.flask_app", "run", "--port", str(port)]
    proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("server did not start")
    yield request.param, port
    proc.terminate()
    proc.wait(5)


class Resp:
    def __init__(self, r, body):
        self.status, self.body, self.h = r.status, body.decode("utf-8", "replace"), {k.lower(): v for k, v in r.getheaders()}


def get(port, path, ua=UA_HUMAN, method="GET", headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, headers={"User-Agent": ua, **(headers or {})})
    r = c.getresponse()
    out = Resp(r, r.read())
    c.close()
    return out


def test_matrix(server, mock):
    name, port = server
    B = f"http://127.0.0.1:{port}"
    mock.reset()

    r = get(port, "/paid-test/", headers={"Accept": "text/html"})
    assert r.status == 200 and "ZZPAIDZZ" in r.body                       # human gets the page
    r = get(port, "/paid-test/", UA_GPT)
    assert r.status == 402 and "ZZPAIDZZ" not in r.body                   # gptbot gets 402 with no content
    assert r.h["content-type"] == "application/json; charset=utf-8" and "no-store" in r.h["cache-control"]
    env = json.loads(base64.b64decode(r.h["payment-required"]))
    a = env["accepts"][0]
    assert (env["x402Version"], a["network"], a["amount"], a["payTo"], env["resource"]["url"]) == (2, "eip155:8453", "10000", PAY_TO, f"{B}/paid-test/")
    body = json.loads(r.body)
    assert (body["x402Version"], body["accepts"][0]["network"], body["accepts"][0]["maxAmountRequired"], body["accepts"][0]["resource"]) == (1, "base", "10000", f"{B}/paid-test/")
    assert re.search(r'Payment id=".*realm="127.0.0.1".*method="evm".*intent="charge".*request="', r.h["www-authenticate"])
    assert "x402.json" in r.h["link"] and "describedby" in r.h["link"]

    assert get(port, "/paid-test/", UA_GPT, "HEAD").status == 402          # HEAD like GET
    assert get(port, "/", "curl/8.5").status == 402                        # curl on home
    assert get(port, "/paid-test/?p=1", "curl/8.5").status == 402          # query URL
    assert get(port, "/paid-test/", "facebookexternalhit/1.1").status == 200   # social preview free
    fake = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    assert get(port, "/paid-test/", fake).status == 402                    # fake googlebot demoted and charged
    r = get(port, "/open/page", UA_GPT)
    assert r.status == 200 and "ZZOPENZZ" in r.body                        # allow-path

    r = get(port, "/.well-known/x402.json", UA_GPT)
    j = json.loads(r.body)
    assert r.status == 200 and j["x402Version"] == 2 and j["resources"][0]["accepts"][0]["payTo"] == PAY_TO and j["resources"][0]["metadata"]["paid"] is True
    r = get(port, "/llms.txt", UA_GPT)
    assert r.status == 200 and "Paid test post" in r.body
    r = get(port, "/agents.txt", UA_GPT)
    assert r.status == 200 and "Payments: required" in r.body

    # v2 paid
    mock.reset()
    h = {"PAYMENT-SIGNATURE": v2_header(make_auth(), f"{B}/paid-test/")}
    r = get(port, "/paid-test/", UA_GPT, headers=h)
    assert r.status == 200 and "ZZPAIDZZ" in r.body
    rec = json.loads(base64.b64decode(r.h["payment-response"]))
    assert rec["success"] and rec["transaction"].startswith("0xabab") and r.h["x-payment-response"]
    assert len(mock.calls("/verify")) == 1 and len(mock.calls("/settle")) == 1
    r = get(port, "/paid-test/", UA_GPT, headers=h)                        # replay
    assert r.status == 402 and "payment_in_flight" in r.body

    # v1 paid, forwarded as v1
    r = get(port, "/paid-test/", "x402-fetch/1.2.0", headers={"X-PAYMENT": v1_header(make_auth())})
    assert r.status == 200
    last = mock.calls("/settle")[-1]["body"]
    assert (last["x402Version"], last["paymentRequirements"]["network"]) == (1, "base")
    r = get(port, "/paid-test/", "x402-fetch/1.2.0", headers={"X-PAYMENT": v1_header(make_auth("5000"))})
    assert r.status == 402 and "wrong_amount" in r.body                    # underpayment

    # MPP from a fresh challenge
    www = get(port, "/paid-test/", UA_GPT).h["www-authenticate"]
    cred = mpp_header(www, "127.0.0.1")
    r = get(port, "/paid-test/", "mpp-client/1", headers={"Authorization": cred})
    assert r.status == 200 and len(r.h["payment-receipt"]) > 10
    r = get(port, "/paid-test/", "mpp-client/1", headers={"Authorization": cred})
    assert r.status == 402 and r.h["content-type"] == "application/problem+json; charset=utf-8"

    # facilitator failure modes
    mock.mode = "reject"
    r = get(port, "/paid-test/", UA_GPT, headers={"PAYMENT-SIGNATURE": v2_header(make_auth(), f"{B}/paid-test/")})
    assert r.status == 402 and "insufficient_funds" in r.body
    mock.mode = "notx"
    r = get(port, "/paid-test/", UA_GPT, headers={"PAYMENT-SIGNATURE": v2_header(make_auth(), f"{B}/paid-test/")})
    assert r.status == 402 and "ZZPAIDZZ" not in r.body                    # no tx, no content
