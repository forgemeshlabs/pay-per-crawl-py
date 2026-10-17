"""Request classifier: who is asking, and is it who it says it is.

Classes: human, search, social, monitor, seo, ai, automation, bot.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Optional

from .catalog import CATALOG

CLASSES = ("human", "search", "social", "monitor", "seo", "ai", "automation", "bot")

_BOT_WORDS = re.compile(r"\b(bot|crawler|spider|scraper|fetcher|crawl|agent|archiver|indexer)\b", re.I)
_BROWSER = re.compile(r"(chrome|safari|firefox|edg|opera|opr|msie|trident|samsungbrowser|ucbrowser)")
_SHORT = re.compile(r"^([A-Za-z0-9_.\-]+)")
_DAY = 86400


@dataclass
class Classification:
    cls: str
    name: str = ""
    verified: Optional[bool] = None
    impersonation: bool = False

    # Dict-style access keeps call sites close to the PHP reference.
    def __getitem__(self, key: str):
        return {"class": self.cls, "name": self.name, "verified": self.verified, "impersonation": self.impersonation}[key]


class SystemResolver:
    """Reverse and forward DNS through the OS resolver."""

    def reverse(self, ip: str) -> Optional[str]:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return None

    def forward(self, host: str) -> list[str]:
        try:
            return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
        except (socket.gaierror, OSError):
            return []


def _same_ip(a: str, b: str) -> bool:
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return False


class Classifier:
    def __init__(self, resolver=None, extra: Optional[list[dict]] = None, clock: Callable[[], float] = time.time):
        self.resolver = resolver or SystemResolver()
        self._catalog = [dict(e) for e in CATALOG]
        self._cache: dict[tuple, tuple[float, Optional[bool]]] = {}
        self._lock = threading.Lock()
        self._clock = clock
        if extra:
            self.merge_intel(extra)

    @property
    def catalog(self) -> list[dict]:
        return self._catalog

    def merge_intel(self, agents: list[dict]) -> None:
        """Merge an intel feed: new names appended, known names get extra needles."""
        by = {e["name"]: e for e in self._catalog}
        for a in agents:
            if a["name"] in by:
                e = by[a["name"]]
                e["match"] = list(dict.fromkeys(list(e["match"]) + list(a["match"])))
                if a.get("verify"):
                    e["verify"] = list(a["verify"])
            else:
                e = {"name": a["name"], "class": a["class"], "match": list(a["match"]), "verify": list(a.get("verify", []))}
                self._catalog.append(e)
                by[e["name"]] = e

    def classify(self, ua: str, headers: Optional[Mapping[str, str]] = None, ip: str = "") -> Classification:
        headers = headers or {}
        ua_l = (ua or "").strip().lower()
        for entry in self._catalog:
            for needle in entry["match"]:
                if needle in ua_l:
                    cls, verified, imp = entry["class"], None, False
                    if entry.get("verify") and ip:
                        verified = self.verify_rdns(ip, entry["verify"])
                        if verified is False:
                            cls, imp = "automation", True  # claimed a search engine, failed rDNS
                    return Classification(cls, entry["name"], verified, imp)
        if ua_l == "":
            return Classification("automation", "Empty User-Agent")
        if _BOT_WORDS.search(ua_l):
            return Classification("bot", short_name(ua))
        if "mozilla/" in ua_l and _BROWSER.search(ua_l):
            accept = (headers.get("accept") or "").lower()
            # A real navigation sends text/html; an API-ish Accept with a browser UA is a tool.
            if accept and "text/html" not in accept and "*/*" not in accept and "image/" not in accept:
                return Classification("automation", "Browser-UA tool")
            return Classification("human")
        return Classification("bot", short_name(ua))

    def verify_rdns(self, ip: str, suffixes: list[str]) -> Optional[bool]:
        """Reverse + forward DNS, cached per IP for a day. None when the IP is unusable."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None
        key = (ip, tuple(suffixes))
        now = self._clock()
        with self._lock:
            hit = self._cache.get(key)
            if hit and now - hit[0] < _DAY:
                return hit[1]
        host = self.resolver.reverse(ip)
        if not host or host == ip:
            result: Optional[bool] = False  # no PTR at all: not a search engine
        else:
            host_l = host.lower().rstrip(".")
            ok = any(host_l.endswith(s.lower()) for s in suffixes)
            if ok:
                ok = any(_same_ip(ip, f) for f in self.resolver.forward(host_l))
            result = ok
        with self._lock:
            if len(self._cache) > 5000:
                self._cache.clear()
            self._cache[key] = (now, result)
        return result


def short_name(ua: str) -> str:
    ua = (ua or "").strip()
    m = _SHORT.match(ua)
    return (m.group(1) if m else ua)[:60]
