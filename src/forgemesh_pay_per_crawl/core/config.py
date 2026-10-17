"""Configuration, mirroring the WordPress plugin's settings."""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field, fields
from typing import Any, Callable, Iterable

POLICIES = ("free", "paid", "block")
DEFAULT_CLASS_POLICY = {
    "search": "free",
    "social": "free",
    "monitor": "free",
    "seo": "paid",
    "ai": "paid",
    "automation": "paid",
    "bot": "paid",
}
_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")


@dataclass
class Config:
    """Settings for the gate.

    mode: "monitor" records what bots would have paid and never blocks;
          "gate" answers 402 to paid classes. Start in monitor.
    pay_to: your wallet (0x address on Base). Payments go straight to it.
    price_usd: price per page fetch in USD (paid in USDC on Base).
    facilitator_url: defaults to PayAI (no key). facilitator_auth is an optional
          Authorization header value for facilitators that need one.
    mpp_secret: HMAC key for MPP challenge ids. Set a stable value when you run
          more than one worker process, otherwise a credential issued by one
          worker is rejected by another.
    base_url: your public origin (https://example.com). Set it behind a proxy;
          otherwise scheme and host come from the request.
    trust_proxy_header: header carrying the real client IP, e.g. "CF-Connecting-IP"
          or "X-Forwarded-For". Used for search-engine verification.
    pages: list of (title, url) or a callable returning one, listed in llms.txt.
    on_event: optional callback(dict) for every classified hit.
    """

    pay_to: str = ""
    price_usd: float = 0.01
    mode: str = "monitor"
    facilitator_url: str = ""
    facilitator_auth: str = ""
    mpp_secret: str = ""
    base_url: str = ""
    site_name: str = ""
    site_description: str = ""
    contact_email: str = ""
    publish_contact: bool = False
    class_policy: dict = field(default_factory=lambda: dict(DEFAULT_CLASS_POLICY))
    bot_overrides: dict = field(default_factory=dict)
    allow_paths: list = field(default_factory=list)
    gated_methods: tuple = ("GET", "HEAD")
    log_humans: bool = True
    discovery: bool = True
    trust_proxy_header: str = ""
    pages: Any = field(default_factory=list)
    pro_key: str = ""
    pro_listed: bool = True
    on_event: Callable[[dict], None] | None = None

    def __post_init__(self) -> None:
        if self.mode not in ("monitor", "gate"):
            raise ValueError("mode must be 'monitor' or 'gate'")
        if self.mode == "gate" and not _ADDR.match(self.pay_to or ""):
            raise ValueError("gate mode needs pay_to: a 0x wallet address on Base")
        if self.pay_to and not _ADDR.match(self.pay_to):
            raise ValueError("pay_to must be a 0x address (40 hex characters)")
        if float(self.price_usd) <= 0:
            raise ValueError("price_usd must be positive")
        policy = dict(DEFAULT_CLASS_POLICY)
        policy.update(self.class_policy or {})
        for k, v in list(policy.items()):
            if v not in POLICIES:
                raise ValueError(f"class_policy[{k!r}] must be one of {POLICIES}")
        self.class_policy = policy
        for k, v in (self.bot_overrides or {}).items():
            if v not in POLICIES:
                raise ValueError(f"bot_overrides[{k!r}] must be one of {POLICIES}")
        self.gated_methods = tuple(m.upper() for m in self.gated_methods)
        self.base_url = (self.base_url or "").rstrip("/")
        if not self.mpp_secret:
            # Per-process random: fine for one worker, set a stable value for several.
            self.mpp_secret = secrets.token_hex(32)

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"unknown settings: {sorted(unknown)}")
        return cls(**data)

    def page_list(self) -> Iterable[tuple[str, str]]:
        pages = self.pages() if callable(self.pages) else self.pages
        return list(pages or [])
