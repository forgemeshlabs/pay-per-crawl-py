"""x402 (v1 + v2) and MPP wire formats: challenge envelopes, payment parsing,
facilitator verify/settle. No web-framework dependencies."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable, Mapping, Optional

from .config import Config
from .keccak import keccak256_hex

NETWORK_V2 = "eip155:8453"
NETWORK_V1 = "base"
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
USDC_NAME = "USD Coin"
USDC_VERSION = "2"
USDC_DECIMALS = 6
TIMEOUT_SECS = 300
MPP_PROBLEMS = "https://paymentauth.org/problems/"
DEFAULT_FACILITATOR = "https://facilitator.payai.network"
VERSION = "0.1.0"
USER_AGENT = f"forgemesh-pay-per-crawl-py/{VERSION}"

# Transport: (url, json body, headers) -> parsed JSON dict. Raise TransportError on failure.
Transport = Callable[[str, dict, dict], dict]


class TransportError(Exception):
    pass


def usd_to_units(usd: Any) -> str:
    return str(int((Decimal(str(usd)) * 1000000).to_integral_value()))


def units_to_usd(units: Any) -> float:
    return float(units) / 1000000


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64url_decode(s: str) -> bytes:
    s = str(s)
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64_json(s: str) -> Any:
    try:
        raw = base64.b64decode(str(s), validate=True)
        return json.loads(raw) if raw else None
    except (binascii.Error, ValueError):
        return None


def b64url_json(s: str) -> Any:
    try:
        raw = b64url_decode(s)
        return json.loads(raw) if raw else None
    except (binascii.Error, ValueError):
        return None


def dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def b64_encode_json(obj: Any) -> str:
    return base64.b64encode(dumps(obj).encode()).decode()


def jcs(value: Any) -> str:
    """RFC 8785 canonical JSON for the value shapes MPP requests use."""
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(str(k), ensure_ascii=False) + ":" + jcs(value[k]) for k in sorted(value, key=str)) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> float:
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError):
        return 0.0


def default_transport(timeout: float = 45.0) -> Transport:
    """httpx when installed, stdlib urllib otherwise."""
    try:
        import httpx  # type: ignore
    except Exception:  # pragma: no cover
        httpx = None

    def call(url: str, body: dict, headers: dict) -> dict:
        data = json.dumps(body).encode()
        try:
            if httpx is not None:
                r = httpx.post(url, content=data, headers=headers, timeout=timeout, follow_redirects=False)
                text, code = r.text, r.status_code
            else:
                req = urllib.request.Request(url, data=data, headers=headers, method="POST")
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        text, code = resp.read().decode("utf-8", "replace"), resp.status
                except urllib.error.HTTPError as e:  # body still carries the facilitator's reason
                    text, code = e.read().decode("utf-8", "replace"), e.code
        except Exception as e:  # network, DNS, timeout
            raise TransportError(str(e)) from e
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        if not isinstance(parsed, dict):
            raise TransportError(f"HTTP {code}: {text[:200]}")
        return parsed

    return call


class X402:
    def __init__(self, cfg: Config, *, realm: str, site_name: str, manifest_url: str,
                 transport: Optional[Transport] = None, clock: Callable[[], float] = time.time):
        self.cfg = cfg
        self.realm = realm
        self.site_name = site_name
        self.manifest_url = manifest_url
        self.transport = transport or default_transport()
        self._clock = clock

    # ── Requirements ───────────────────────────────────────────────────────

    def requirements_v2(self, resource_url: str = "", description: str = "") -> dict:
        return {
            "scheme": "exact",
            "network": NETWORK_V2,
            "amount": usd_to_units(self.cfg.price_usd),
            "asset": USDC,
            "payTo": self.cfg.pay_to,
            "maxTimeoutSeconds": TIMEOUT_SECS,
            "extra": {"name": USDC_NAME, "version": USDC_VERSION},
        }

    def requirements_v1(self, resource_url: str, description: str = "") -> dict:
        return {
            "scheme": "exact",
            "network": NETWORK_V1,
            "maxAmountRequired": usd_to_units(self.cfg.price_usd),
            "asset": USDC,
            "payTo": self.cfg.pay_to,
            "maxTimeoutSeconds": TIMEOUT_SECS,
            "resource": resource_url,
            "description": description,
            "mimeType": "text/html",
            "extra": {"name": USDC_NAME, "version": USDC_VERSION},
        }

    def envelope_v2(self, resource_url: str, description: str, error: str = "Payment required") -> dict:
        return {
            "x402Version": 2,
            "error": error,
            "resource": {"url": resource_url, "description": description, "mimeType": "text/html"},
            "accepts": [self.requirements_v2(resource_url, description)],
        }

    def body_v1(self, resource_url: str, description: str, error: str = "Payment required", invalid_reason: Optional[str] = None) -> dict:
        body = {
            "x402Version": 1,
            "error": error,
            "accepts": [self.requirements_v1(resource_url, description)],
            "provider": {"name": self.site_name, "plugin": "forgemesh-pay-per-crawl"},
            "docs": {"x402": "https://x402.org", "manifest": self.manifest_url},
        }
        if invalid_reason:
            body["invalidReason"] = invalid_reason
        return body

    # ── Inbound payment headers ────────────────────────────────────────────

    def extract_payment(self, h: Mapping[str, str], resource_url: str) -> Optional[dict]:
        """Find a payment on the request: None, or {rail, payload, error, mpp}.

        h is a lowercased header map.
        """
        if h.get("payment-signature"):
            p = b64_json(h["payment-signature"])
            if not isinstance(p, dict) or p.get("x402Version") != 2 or not p.get("payload"):
                return {"rail": "x402v2", "error": "malformed_payment_signature"}
            return {"rail": "x402v2", "payload": p}
        if h.get("x-payment"):
            p = b64_json(h["x-payment"])
            if not isinstance(p, dict) or p.get("x402Version") != 1 or not p.get("payload"):
                return {"rail": "x402v1", "error": "malformed_x_payment"}
            return {"rail": "x402v1", "payload": p}
        m = re.match(r"^Payment\s+([A-Za-z0-9_\-]+)$", (h.get("authorization") or "").strip(), re.I)
        if m:
            cred = b64url_json(m.group(1))
            err = self.validate_mpp(cred)
            if err:
                return {"rail": "mpp", "error": err[0], "detail": err[1]}
            pl = cred["payload"]
            v2 = {
                "x402Version": 2,
                "resource": {"url": resource_url},
                "accepted": self.requirements_v2(resource_url),
                "payload": {
                    "signature": pl["signature"],
                    "authorization": {k: pl[k] for k in ("from", "to", "value", "validAfter", "validBefore", "nonce")},
                },
            }
            return {"rail": "mpp", "payload": v2, "mpp": cred}
        return None

    @staticmethod
    def authorization_of(payment: dict) -> Optional[dict]:
        try:
            a = payment["payload"]["payload"]["authorization"]
        except (KeyError, TypeError):
            return None
        return a if isinstance(a, dict) else None

    def precheck(self, payment: dict, resource_url: str = "") -> Optional[str]:
        """Cheap local checks before the facilitator: recipient, amount, asset/network, expiry."""
        auth = self.authorization_of(payment)
        if not auth or not auth.get("to") or "value" not in auth or not auth.get("nonce"):
            return "malformed_authorization"
        if str(auth["to"]).lower() != self.cfg.pay_to.lower():
            return "wrong_pay_to"
        want = usd_to_units(self.cfg.price_usd)
        val = str(auth["value"])
        if val != want and not (val.isdigit() and int(val) >= int(want) and payment["rail"] == "x402v1"):
            return "wrong_amount"
        p = payment["payload"]
        if payment["rail"] == "x402v2":
            acc = p.get("accepted") or {}
            if acc.get("network") != NETWORK_V2 or str(acc.get("asset", "")).lower() != USDC.lower():
                return "wrong_network_or_asset"
        elif payment["rail"] == "x402v1":
            if p.get("network") != NETWORK_V1 or p.get("scheme") != "exact":
                return "wrong_network_or_scheme"
        vb = str(auth.get("validBefore", ""))
        if vb.isdigit() and int(vb) < self._clock():
            return "authorization_expired"
        return None

    # ── Facilitator ────────────────────────────────────────────────────────

    def facilitator_url(self) -> str:
        return (self.cfg.facilitator_url.strip() or DEFAULT_FACILITATOR).rstrip("/")

    def verify_and_settle(self, payment: dict, resource_url: str) -> dict:
        """POST /verify then /settle. Serve only on a non-empty transaction hash.

        Returns {ok, reason, settle, tx, payer, detail}.
        """
        rail = payment["rail"]
        p = dict(payment["payload"])
        if rail == "x402v1":
            req, version = self.requirements_v1(resource_url, self.site_name), 1
        else:
            req, version = self.requirements_v2(resource_url), 2
            p["accepted"] = req  # the facilitator deep-compares `accepted` with requirements
            if not p.get("resource"):
                p["resource"] = {"url": resource_url}
        body = {"x402Version": version, "paymentPayload": p, "paymentRequirements": req}

        try:
            v = self._post("/verify", body)
        except TransportError as e:
            return {"ok": False, "reason": "facilitator_unreachable", "detail": str(e)}
        if not v.get("isValid"):
            return {"ok": False, "reason": str(v.get("invalidReason") or "verification_failed"), "payer": v.get("payer")}
        try:
            s = self._post("/settle", body)
        except TransportError as e:
            return {"ok": False, "reason": "facilitator_unreachable", "detail": str(e)}
        tx = str(s.get("transaction") or "")
        if not s.get("success") or tx == "":
            return {"ok": False, "reason": str(s.get("errorReason") or "settlement_failed"), "settle": s}
        return {"ok": True, "settle": s, "tx": tx, "payer": s.get("payer") or v.get("payer")}

    def _post(self, path: str, body: dict) -> dict:
        headers = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": USER_AGENT}
        if self.cfg.facilitator_auth:
            headers["Authorization"] = self.cfg.facilitator_auth
        return self.transport(self.facilitator_url() + path, body, headers)

    # ── MPP ────────────────────────────────────────────────────────────────

    def challenge_id(self, realm: str, request_b64: str, expires: str, digest: str = "", opaque: str = "") -> str:
        data = "|".join([realm, "evm", "charge", request_b64, expires, digest, opaque]).encode()
        return b64url(hmac.new(self.cfg.mpp_secret.encode(), data, hashlib.sha256).digest())

    def mpp_challenge(self, description: str = "") -> str:
        """WWW-Authenticate: Payment ... header value."""
        request = {
            "amount": usd_to_units(self.cfg.price_usd),
            "currency": USDC,
            "recipient": self.cfg.pay_to,
            "methodDetails": {"chainId": 8453, "credentialTypes": ["authorization"], "decimals": USDC_DECIMALS},
        }
        if description:
            request["description"] = description
        request_b64 = b64url(jcs(request).encode())
        expires = _iso(self._clock() + TIMEOUT_SECS)
        cid = self.challenge_id(self.realm, request_b64, expires)
        return f'Payment id="{cid}", realm="{self.realm}", method="evm", intent="charge", expires="{expires}", request="{request_b64}"'

    def validate_mpp(self, cred: Any) -> Optional[tuple[str, str]]:
        """(problem, detail) on failure, None when valid."""
        if not isinstance(cred, dict) or not isinstance(cred.get("challenge"), dict) or not isinstance(cred.get("payload"), dict) or not cred["challenge"] or not cred["payload"]:
            return ("malformed-credential", "Credential must contain challenge and payload objects.")
        ch = cred["challenge"]
        if ch.get("realm") != self.realm or ch.get("method") != "evm" or ch.get("intent") != "charge" or not ch.get("id") or not ch.get("request") or not ch.get("expires"):
            return ("invalid-challenge", "Challenge fields missing or not issued by this realm.")
        if _parse_iso(str(ch["expires"])) < self._clock():
            return ("payment-expired", "Challenge has expired; retry with a fresh challenge.")
        expected = self.challenge_id(ch["realm"], str(ch["request"]), str(ch["expires"]), str(ch.get("digest", "")), str(ch.get("opaque", "")))
        if not hmac.compare_digest(expected, str(ch["id"])):
            return ("invalid-challenge", "Challenge id does not match its parameters.")
        request = b64url_json(str(ch["request"]))
        if (not isinstance(request, dict) or request.get("amount") != usd_to_units(self.cfg.price_usd)
                or str(request.get("recipient", "")).lower() != self.cfg.pay_to.lower()
                or str(request.get("currency", "")).lower() != USDC.lower()):
            return ("invalid-challenge", "Challenge request does not match this resource's payment terms.")
        pl = cred["payload"]
        if pl.get("type") != "authorization":
            return ("verification-failed", 'Only credentialTypes ["authorization"] (EIP-3009) is accepted.')
        for f in ("from", "to", "value", "validAfter", "validBefore", "nonce", "signature"):
            if not isinstance(pl.get(f), str) or pl[f] == "":
                return ("verification-failed", f"Payload field {f} is required.")
        if pl["nonce"].lower() != keccak256_hex(str(ch["id"]) + str(ch["realm"])):
            return ("verification-failed", "Payload nonce must equal keccak256(challenge.id || challenge.realm).")
        return None

    def mpp_receipt(self, tx: str) -> str:
        return b64url(dumps({"status": "success", "method": "evm", "timestamp": _iso(self._clock()), "reference": tx}).encode())
