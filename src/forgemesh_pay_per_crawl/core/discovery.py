"""Discovery documents so paying agents and x402 indexes find the paid copy:
/.well-known/x402.json, /llms.txt, /agents.txt, and robots.txt lines."""
from __future__ import annotations

import json
from typing import Optional

from . import x402
from .config import Config
from .http import Response, host_of

PATHS = ("/.well-known/x402.json", "/llms.txt", "/agents.txt")


def _price(p: float) -> str:
    return f"{float(p):.6f}".rstrip("0").rstrip(".")


class Discovery:
    def __init__(self, cfg: Config, home: str, site_name: str):
        self.cfg = cfg
        self.home = home.rstrip("/") + "/"
        self.site_name = site_name

    def paid(self) -> bool:
        return self.cfg.mode == "gate" and bool(self.cfg.pay_to)

    def url(self, path: str) -> str:
        return self.home.rstrip("/") + path

    def manifest(self) -> dict:
        price = float(self.cfg.price_usd)
        host = host_of(self.home)
        res = {
            "resource": self.home + "{path}",
            "type": "http",
            "metadata": {
                "method": "GET",
                "name": f"{self.site_name}: page fetch",
                "description": f"Any page on {host}, served as HTML to automated clients after an x402 payment of ${_price(price)} USDC on Base. Humans and verified search engines read free.",
                "priceUsd": price,
                "mimeType": "text/html",
                "paid": self.paid(),
            },
            "accepts": [{
                "scheme": "exact",
                "network": x402.NETWORK_V2,
                "amount": x402.usd_to_units(price),
                "asset": x402.USDC,
                "payTo": self.cfg.pay_to,
                "maxTimeoutSeconds": x402.TIMEOUT_SECS,
                "extra": {"name": x402.USDC_NAME, "version": x402.USDC_VERSION},
            }],
        }
        return {
            "x402Version": 2,
            "provider": {
                "name": self.site_name,
                "url": self.home,
                "description": self.cfg.site_description,
                "contact": self.cfg.contact_email if (self.cfg.contact_email and self.cfg.publish_contact) else None,
            },
            "resources": [res],
            "protocols": ["x402", "mpp"],
            "generator": f"forgemesh-pay-per-crawl-py/{x402.VERSION}",
            "sitemap": self.url("/sitemap.xml"),
        }

    def llms(self) -> str:
        lines = [f"# {self.site_name}", "", f"> {self.cfg.site_description}", "", f"Site: {self.home}", f"Sitemap: {self.url('/sitemap.xml')}", "",
                 "## Access for automated clients", ""]
        if self.paid():
            lines.append(f"Pages on this site answer HTTP 402 to crawlers and agents. Pay ${_price(self.cfg.price_usd)} USDC on Base per page with x402 (PAYMENT-SIGNATURE or X-PAYMENT header) or MPP (Authorization: Payment) and retry the same URL.")
        else:
            lines.append("This site is instrumented for x402 pay-per-crawl; charging is not enabled yet. Terms will appear in the manifest below when it is.")
        lines += ["Verified search engines and humans are never charged.", "",
                  f"Manifest: {self.url('/.well-known/x402.json')}", f"Agents: {self.url('/agents.txt')}", "Protocol: https://x402.org", ""]
        pages = self.cfg.page_list()
        if pages:
            lines += ["## Pages", ""]
            lines += [f"- [{t}]({u})" for t, u in pages]
        return "\n".join(lines) + "\n"

    def agents(self) -> str:
        host = host_of(self.home)
        lines = [
            f"# agents.txt — {host}",
            "# Standard: https://agents-txt.com",
            "",
            f"Name: {self.site_name}",
            f"Provider: {self.site_name} ({self.home})",
            "Protocols: x402, mpp, http",
            f"Payments: {'required' if self.paid() else 'none'}",
            "",
            f"LLMs: {self.url('/llms.txt')}",
            f"x402: {self.url('/.well-known/x402.json')}",
            f"Sitemap: {self.url('/sitemap.xml')}",
            "",
            "## Payment",
            "Protocol: x402 (HTTP 402 challenge; pay and retry with PAYMENT-SIGNATURE) and MPP (WWW-Authenticate: Payment)",
            f"Network: {x402.NETWORK_V2}",
            f"Asset: {x402.USDC} (USDC)",
            f"Price: ${_price(self.cfg.price_usd)} per page",
            f"PayTo: {self.cfg.pay_to}",
            "",
        ]
        return "\n".join(lines)

    def robots_lines(self) -> str:
        """Lines to append to your robots.txt."""
        return ("\n# x402 pay-per-crawl (forgemesh-pay-per-crawl)\n"
                f"# Manifest: {self.url('/.well-known/x402.json')}\n"
                f"# LLMs: {self.url('/llms.txt')}\n"
                f"# Agents: {self.url('/agents.txt')}\n")

    def serve(self, path: str) -> Optional[Response]:
        """Response for a discovery path, else None."""
        if not self.cfg.discovery:
            return None
        path = path.rstrip("/")
        if path == "/.well-known/x402.json":
            body, ctype = json.dumps(self.manifest(), indent=2, ensure_ascii=False), "application/json; charset=utf-8"
        elif path == "/llms.txt":
            body, ctype = self.llms(), "text/plain; charset=utf-8"
        elif path == "/agents.txt":
            body, ctype = self.agents(), "text/plain; charset=utf-8"
        else:
            return None
        data = body.encode()
        return Response(200, [("Content-Type", ctype), ("Cache-Control", "public, max-age=3600"),
                              ("Access-Control-Allow-Origin", "*"), ("Content-Length", str(len(data)))], data)
