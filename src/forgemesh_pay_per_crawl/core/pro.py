"""Stats collector and the optional Pro reporter.

Stats is a small in-memory rollup of hits (per day, bot, class) and settlements.
ProReporter pushes those rollups to the hosted dashboard with a Pro license key
and pulls the crawler-intel feed. Without a key nothing here ever calls out.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Callable, Optional

from . import x402
from .classifier import CLASSES, Classifier
from .config import Config
from .http import host_of

BASE = "https://proxy.forgemesh.io"
_KEY = re.compile(r"^fmppc_[A-Za-z0-9_\-]{20,}$")


def _day(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")


class Stats:
    def __init__(self, salt: str = "", clock: Callable[[], float] = time.time, keep_days: int = 3):
        self._salt = salt or "fmppc"
        self._clock = clock
        self._keep = keep_days
        self._mu = threading.Lock()
        self._daily: dict[tuple, dict] = {}
        self._settlements: list[dict] = []
        self._seq = 0

    def ip_hash(self, ip: str) -> str:
        return hashlib.sha256((self._salt + "|" + ip).encode()).hexdigest()[:16]

    def record(self, ev: dict) -> None:
        now = self._clock()
        day = _day(now)
        key = (day, ev.get("bot_name") or "", ev.get("ua_class") or "")
        status = ev.get("status", "")
        with self._mu:
            row = self._daily.setdefault(key, {"hits": 0, "paid": 0, "unpaid": 0, "rejected": 0, "monitor": 0,
                                               "revenue_units": 0, "would_units": 0, "_src": set()})
            row["hits"] += 1
            if status in ("paid", "unpaid", "monitor"):
                row[status] += 1
            elif status in ("rejected", "settle_failed"):
                row["rejected"] += 1
            if status == "paid":
                row["revenue_units"] += int(ev.get("amount_units") or 0)
            elif status == "monitor":
                row["would_units"] += int(ev.get("amount_units") or 0)
            if ev.get("ip_hash"):
                row["_src"].add(ev["ip_hash"])
            if status == "paid":
                self._seq += 1
                self._settlements.append({
                    "id": self._seq,
                    "ts": datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                    "bot_name": ev.get("bot_name") or "", "ua_class": ev.get("ua_class") or "",
                    "path": ev.get("path") or "", "rail": ev.get("rail") or "",
                    "amount_units": int(ev.get("amount_units") or 0),
                    "tx_hash": ev.get("tx_hash") or "", "payer": ev.get("payer") or "",
                })
                del self._settlements[:-5000]
            cutoff = _day(now - self._keep * 86400)
            for k in [k for k in self._daily if k[0] < cutoff]:
                del self._daily[k]

    def rollup(self, day: str) -> list[dict]:
        with self._mu:
            rows = []
            for (d, name, cls), r in self._daily.items():
                if d == day:
                    out = {k: v for k, v in r.items() if k != "_src"}
                    out.update(bot_name=name, ua_class=cls, sources=len(r["_src"]))
                    rows.append(out)
        return sorted(rows, key=lambda r: -r["hits"])[:500]

    def settlements_after(self, last_id: int, limit: int = 1000) -> list[dict]:
        with self._mu:
            return [dict(s) for s in self._settlements if s["id"] > last_id][:limit]

    def totals(self) -> dict:
        with self._mu:
            t = {"hits": 0, "paid": 0, "revenue_units": 0}
            for r in self._daily.values():
                t["hits"] += r["hits"]
                t["paid"] += r["paid"]
                t["revenue_units"] += r["revenue_units"]
            return t


HttpFn = Callable[[str, str, Optional[dict], dict], tuple]  # (method, url, body, headers) -> (code, json|None)


def _http(method: str, url: str, body: Optional[dict], headers: dict) -> tuple:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            code, text = r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        code, text = e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, {"ok": False, "error": str(e)}
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    return code, parsed


class ProReporter:
    def __init__(self, cfg: Config, stats: Stats, home: str, site_name: str, classifier: Optional[Classifier] = None,
                 http: Optional[HttpFn] = None, base: str = BASE, clock: Callable[[], float] = time.time):
        self.cfg = cfg
        self.stats = stats
        self.home = home
        self.site_name = site_name
        self.classifier = classifier
        self._http = http or _http
        self.base = base
        self._clock = clock
        self.state: dict = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def enabled(cfg: Config) -> bool:
        return bool(cfg.pro_key) and bool(_KEY.match(cfg.pro_key))

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        headers = {"Authorization": f"Bearer {self.cfg.pro_key}", "Content-Type": "application/json", "Accept": "application/json",
                   "User-Agent": f"{x402.USER_AGENT} ({host_of(self.home)})"}
        code, js = self._http(method, self.base + path, body, headers)
        if not isinstance(js, dict):
            return {"ok": False, "error": f"HTTP {code}", "code": code}
        js["code"] = code
        if code >= 400:
            js["ok"] = False
        return js

    def verify(self) -> dict:
        r = self._request("POST", "/api/wp/license/verify")
        self.state.update(verified_at=self._clock(), ok=bool(r.get("ok")), status=str(r.get("status") or r.get("error") or "error"),
                          sites_used=int(r.get("sites_used") or 0), site_limit=int(r.get("site_limit") or 0),
                          dashboard=str(r.get("dashboard_url") or self.base + "/wp/dashboard"))
        return r

    def sync(self) -> dict:
        """One sync: verify daily, push rollups for yesterday and today plus new settlements, pull intel daily."""
        if not self.enabled(self.cfg):
            return {"ok": False, "error": "no_license_key"}
        now = self._clock()
        if not self.state.get("verified_at") or now - self.state["verified_at"] > 86400:
            self.verify()
        if not self.state.get("ok"):
            return {"ok": False, "error": self.state.get("status", "not_verified")}
        daily = [{"day": d, "rows": self.stats.rollup(d)} for d in (_day(now - 86400), _day(now))]
        last = int(self.state.get("last_settlement_id", 0))
        settlements = self.stats.settlements_after(last)
        payload = {
            "site": {"host": host_of(self.home), "url": self.home, "name": self.site_name, "plugin_version": x402.VERSION,
                     "mode": self.cfg.mode, "price_usd": float(self.cfg.price_usd), "pay_to": self.cfg.pay_to,
                     "listed": bool(self.cfg.pro_listed)},
            "daily": daily,
            "settlements": [{k: v for k, v in s.items() if k != "id"} for s in settlements],
        }
        r = self._request("POST", "/api/wp/ingest", payload)
        self.state.update(synced_at=now, sync_ok=bool(r.get("ok")), sync_error="" if r.get("ok") else str(r.get("error") or f"HTTP {r.get('code')}"))
        if r.get("ok") and settlements:
            self.state["last_settlement_id"] = settlements[-1]["id"]
        if not self.state.get("intel_at") or now - self.state["intel_at"] > 86400:
            self.pull_intel()
        return r

    def pull_intel(self) -> int:
        intel = self._request("GET", "/api/wp/intel")
        agents = intel.get("agents")
        if not isinstance(agents, list) or self.classifier is None:
            return 0
        clean = []
        for a in agents[:500]:
            if not isinstance(a, dict) or not a.get("name") or not isinstance(a.get("match"), list) or a.get("class") not in CLASSES:
                continue
            clean.append({
                "name": str(a["name"])[:64], "class": a["class"],
                "match": [str(m).lower()[:64] for m in a["match"][:8] if m],
                "verify": [str(v) for v in (a.get("verify") or []) if v],
            })
        self.classifier.merge_intel(clean)
        self.state.update(intel_at=self._clock(), intel_version=str(intel.get("version") or ""), intel_count=len(clean))
        return len(clean)

    def start(self, interval: float = 3600.0) -> None:
        """Background thread: first sync after 5 minutes, then every `interval` seconds."""
        if not self.enabled(self.cfg) or self._thread:
            return

        def loop() -> None:
            wait = 300.0
            while not self._stop.wait(wait):
                try:
                    self.sync()
                except Exception:
                    pass
                wait = interval

        self._thread = threading.Thread(target=loop, name="fmppc-pro", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
