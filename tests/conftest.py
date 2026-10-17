import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

PAY_TO = "0x13C3C28c64cc9d60eEb8a675F3fe27eBC6a4Cd09"
UA_HUMAN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"
UA_GPT = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"


class MockFacilitator:
    """Records every request; answers per .mode: ok | reject | notx | down."""

    def __init__(self):
        self.mode = "ok"
        self.log = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                outer.log.append({"path": self.path, "body": body, "headers": dict(self.headers)})
                auth = (body.get("paymentPayload", {}).get("payload") or {}).get("authorization", {})
                if outer.mode == "down":
                    self.send_response(502)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"bad gateway")
                    return
                if self.path == "/verify":
                    out = {"isValid": False, "invalidReason": "insufficient_funds"} if outer.mode == "reject" else {"isValid": True, "payer": auth.get("from", "0x0")}
                elif self.path == "/settle":
                    out = ({"success": True, "transaction": ""} if outer.mode == "notx" else
                           {"success": True, "transaction": "0x" + "ab" * 32, "network": body["paymentRequirements"]["network"], "payer": auth.get("from", "0x0")})
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                data = json.dumps(out).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def calls(self, path):
        return [c for c in self.log if c["path"] == path]

    def reset(self, mode="ok"):
        self.mode = mode
        self.log.clear()

    def close(self):
        self.server.shutdown()


@pytest.fixture(scope="session")
def mock():
    m = MockFacilitator()
    yield m
    m.close()


@pytest.fixture(autouse=True)
def _reset_mock(request):
    if "mock" in request.fixturenames:
        request.getfixturevalue("mock").reset()
