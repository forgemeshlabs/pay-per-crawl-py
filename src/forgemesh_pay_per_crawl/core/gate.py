"""The gate: classify the request, apply policy, answer 402 or let it through."""
from __future__ import annotations

import posixpath
import re
import time
from typing import Callable, Optional

from . import x402
from .classifier import Classifier
from .config import Config
from .discovery import PATHS, Discovery
from .http import Decision, Request, Response, host_of
from .locks import MemoryNonceLock
from .pro import ProReporter, Stats
from .x402 import X402, Transport, b64_encode_json, dumps

EXEMPT_FILES = frozenset(("/robots.txt", "/llms.txt", "/agents.txt", "/favicon.ico"))
_SITEMAP_RE = re.compile(r"^/[a-z0-9_-]*sitemap[a-z0-9_-]*\.xml$")
_PAID_HEADERS = ("PAYMENT-RESPONSE", "X-PAYMENT-RESPONSE")


def _under(norm: str, allow: str) -> bool:
    """norm equals allow or sits beneath it ("/pricing" never matches "/pricing-secret")."""
    if allow.endswith("/"):
        return norm.startswith(allow)
    return norm == allow or norm.startswith(allow + "/")


class Gate:
    def __init__(self, config: Config, *, transport: Optional[Transport] = None, lock=None, resolver=None,
                 stats: Optional[Stats] = None, clock: Callable[[], float] = time.time, start_pro: bool = True):
        self.cfg = config
        self._transport = transport
        self.lock = lock or MemoryNonceLock()
        self.classifier = Classifier(resolver=resolver)
        self.stats = stats or Stats(salt=config.mpp_secret)
        self._clock = clock
        self.pro: Optional[ProReporter] = None
        if ProReporter.enabled(config):
            home = config.base_url or ""
            self.pro = ProReporter(config, self.stats, home, config.site_name or host_of(home), self.classifier)
            if start_pro:
                self.pro.start()

    # ── Request helpers ──────────────────────────────────────────────────

    def home(self, req: Request) -> str:
        return self.cfg.base_url or f"{req.scheme}://{req.host}"

    def site_name(self, req: Request) -> str:
        return self.cfg.site_name or host_of(self.home(req)) or "site"

    def client_ip(self, req: Request) -> str:
        ip = req.ip
        hdr = self.cfg.trust_proxy_header.lower()
        if hdr and req.headers.get(hdr):
            # Multi-value forwarding headers grow on the LEFT with client-supplied
            # values; the right-most entry is the one the proxy in front of us
            # appended. Single-value edge headers (CF-Connecting-IP, X-Real-IP,
            # True-Client-IP) have one entry, so this is a no-op for them.
            parts = [p.strip() for p in req.headers[hdr].split(",") if p.strip()]
            if parts:
                ip = parts[-1]
        return ip

    def url(self, req: Request) -> str:
        return self.home(req) + req.path + (("?" + req.query) if req.query else "")

    def x402(self, req: Request) -> X402:
        home = self.home(req)
        return X402(self.cfg, realm=host_of(home), site_name=self.site_name(req),
                    manifest_url=home + "/.well-known/x402.json", transport=self._transport, clock=self._clock)

    def discovery(self, req: Request) -> Discovery:
        return Discovery(self.cfg, self.home(req), self.site_name(req))

    def link_header(self, req: Request) -> list:
        if not self.cfg.discovery:
            return []
        home = self.home(req)
        return [("Link", f'<{home}/.well-known/x402.json>; rel="describedby"; type="application/json", '
                         f'<{home}/llms.txt>; rel="llms-txt"; type="text/plain"')]

    # ── Entry point ──────────────────────────────────────────────────────

    def handle(self, req: Request) -> Decision:
        """Blocking (it may call the facilitator): run it in a thread from async code."""
        method = req.method.upper()
        if method not in self.cfg.gated_methods:
            return Decision()
        d = self.discovery(req).serve(req.path) if method in ("GET", "HEAD") else None
        if d is not None:
            return Decision(self._for_method(req, d))
        if self.exempt(req.path):
            return Decision(headers=self.link_header(req))
        return self._gate(req)

    def exempt(self, path: str) -> bool:
        """True only for an exact exempt file, a root sitemap .xml, /.well-known/ or an allow path.

        Matching is on the normalised path at a path-segment boundary; dot segments, doubled slashes
        and %2e / %2f in the raw path are never exempt.
        """
        low = path.lower()
        if "%2f" in low or "%2e" in low:
            return False
        norm = posixpath.normpath(path) if path.startswith("/") else ""
        if norm.startswith("//"):
            norm = "/" + norm.lstrip("/")
        if not norm or norm.rstrip("/") != path.rstrip("/"):
            return False
        if norm in EXEMPT_FILES or _SITEMAP_RE.match(norm) or _under(norm, "/.well-known/") or norm == "/.well-known":
            return True
        return any(p.strip() and _under(norm, p.strip()) for p in self.cfg.allow_paths)

    # ── Core ─────────────────────────────────────────────────────────────

    def _event(self, row: dict, **extra) -> None:
        ev = {**row, **extra}
        self.stats.record(ev)
        if self.cfg.on_event:
            try:
                self.cfg.on_event(ev)
            except Exception:
                pass

    def _gate(self, req: Request) -> Decision:
        h = req.headers
        ua = h.get("user-agent", "")
        ip = self.client_ip(req)
        c = self.classifier.classify(ua, h, ip)
        row = {"ua_class": c.cls, "bot_name": c.name, "verified": c.verified, "method": req.method.upper(),
               "path": req.path, "ip_hash": self.stats.ip_hash(ip), "ua": ua}
        url = self.url(req)
        x = self.x402(req)
        link = self.link_header(req)
        payment = x.extract_payment(h, url)

        if c.cls == "human" and not payment:
            if self.cfg.log_humans:
                self._event(row, status="passed")
            return Decision(headers=link)

        policy = self.policy_for(c.name, c.cls)
        if policy == "free" and not payment:  # a payment on a free class is still honoured
            self._event(row, status="passed")
            return Decision(headers=link)
        if policy == "block":
            self._event(row, status="blocked")
            return Decision(self._blocked(req))
        if not payment:
            if self.cfg.mode == "monitor" or policy == "free":
                self._event(row, status="monitor", amount_units=int(x402.usd_to_units(self.cfg.price_usd)))
                return Decision(headers=link)
            self._event(row, status="unpaid")
            return Decision(self._respond_402(req, x, url, None))

        row["rail"] = payment["rail"]
        if payment.get("error"):
            self._event(row, status="rejected", reason=payment["error"])
            return Decision(self._respond_402(req, x, url, payment["error"], payment.get("detail"), payment["rail"]))
        pre = x.precheck(payment, url)
        if pre:
            self._event(row, status="rejected", reason=pre)
            return Decision(self._respond_402(req, x, url, pre, None, payment["rail"]))

        auth = x.authorization_of(payment)
        nonce_key = str(auth["nonce"]).lower()
        if not self.lock.acquire(nonce_key):
            self._event(row, status="rejected", reason="payment_in_flight")
            return Decision(self._respond_402(req, x, url, "payment_in_flight", "This authorization was already presented.", payment["rail"]))

        try:
            r = x.verify_and_settle(payment, url)
        except Exception as e:  # never leave a nonce locked on an unexpected failure
            r = {"ok": False, "reason": "facilitator_unreachable", "detail": str(e)}
        if not r.get("ok"):
            if r["reason"] == "facilitator_unreachable":
                self.lock.release(nonce_key)  # let the client retry the same authorization
            self._event(row, status="settle_failed", reason=r["reason"], payer=str(r.get("payer") or auth.get("from") or ""))
            return Decision(self._respond_402(req, x, url, r["reason"], r.get("detail"), payment["rail"]))

        self._event(row, status="paid", amount_units=int(auth["value"]), tx_hash=r["tx"], payer=str(r.get("payer") or auth.get("from") or ""))
        settle_b64 = b64_encode_json(r["settle"])
        hdrs = [("PAYMENT-RESPONSE", settle_b64), ("X-PAYMENT-RESPONSE", settle_b64)]
        if payment["rail"] == "mpp":
            hdrs.append(("Payment-Receipt", x.mpp_receipt(r["tx"])))
        hdrs.append(("Cache-Control", "private, no-store"))
        return Decision(headers=hdrs + link)

    def policy_for(self, name: str, cls: str) -> str:
        ov = self.cfg.bot_overrides.get(name) if name else None
        if ov in ("free", "paid", "block"):
            return ov
        return self.cfg.class_policy.get(cls, "paid")

    # ── Responses ────────────────────────────────────────────────────────

    def _for_method(self, req: Request, resp: Response) -> Response:
        if req.method.upper() == "HEAD":
            return Response(resp.status, resp.headers, b"")
        return resp

    def _respond_402(self, req: Request, x: X402, url: str, reason: Optional[str], detail: Optional[str] = None,
                     rail: Optional[str] = None) -> Response:
        desc = f"{x.site_name}: one page fetch (HTML)"
        headers = [
            ("Cache-Control", "no-store"),
            ("PAYMENT-REQUIRED", b64_encode_json(x.envelope_v2(url, desc, reason or "Payment required"))),
            ("WWW-Authenticate", x.mpp_challenge(desc)),
            ("Link", f'<{self.home(req)}/.well-known/x402.json>; rel="describedby"; type="application/json"'),
            ("X-Robots-Tag", "noindex"),
        ]
        if rail == "mpp" and reason:
            ctype = "application/problem+json; charset=utf-8"
            body = dumps({"type": x402.MPP_PROBLEMS + reason, "title": "Payment Required", "status": 402, "detail": detail or reason})
        else:
            ctype = "application/json; charset=utf-8"
            body = dumps(x.body_v1(url, desc, "Payment rejected" if reason else "Payment required", reason))
        data = body.encode()
        headers.append(("Content-Type", ctype))
        if req.method.upper() == "HEAD":
            return Response(402, headers, b"")
        headers.append(("Content-Length", str(len(data))))
        return Response(402, headers, data)

    def _blocked(self, req: Request) -> Response:
        data = dumps({"error": "forbidden", "detail": "This crawler is not permitted on this site."}).encode()
        headers = [("Cache-Control", "no-store"), ("Content-Type", "application/json; charset=utf-8")]
        if req.method.upper() == "HEAD":
            return Response(403, headers, b"")
        return Response(403, headers + [("Content-Length", str(len(data)))], data)
