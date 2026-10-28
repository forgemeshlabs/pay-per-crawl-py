# ForgeMesh Pay-per-Crawl for Python

**Know who crawls your site. Charge the ones that can pay.**

Pay-per-Crawl shows you every AI crawler, SEO crawler and script that fetches your pages, verifies the real search engines by reverse DNS so SEO is untouched, and lets you answer everything else with a standard HTTP 402 price in USDC on Base, paid to your own wallet. Be clear about what pays today: x402-capable agents do; the big AI labs' crawlers (GPTBot, ClaudeBot, PerplexityBot and friends) do not yet pay anyone per page, and they simply get no content from a charging site. Until they do, this is an honest bot ledger with the price already on the door. You see who takes what, you can block or charge any of it, and when a crawler does pay, it goes straight to you. Nobody in between holds the money. Humans and verified search engines read free.

Middleware for **FastAPI / Starlette (ASGI)**, **Flask and any WSGI app**, and **Django**, on one framework-free core.

This is the Python edition of the [WordPress plugin](https://github.com/forgemeshlabs/forgemesh-pay-per-crawl); behaviour is identical.

- **Humans see nothing different.** Browsers get the page as always.
- **Verified search engines stay free.** Googlebot, Bingbot, DuckDuckBot, Applebot and others are checked by reverse DNS, so SEO is untouched. A crawler that only *claims* to be Googlebot is treated as a script.
- **AI crawlers, SEO crawlers and scripts get `402 Payment Required`** with an x402 challenge (v2 `PAYMENT-REQUIRED` header + v1 JSON body) and an MPP `WWW-Authenticate: Payment` challenge. An x402-capable client pays USDC on Base and retries; the page is served only after the payment settles on-chain. A crawler that cannot pay gets no content.
- **You keep 100%.** The payer's USDC goes directly to your wallet. No custody, no account, no API key, no revenue share.
- **Discovery built in.** Serves `/.well-known/x402.json`, `/llms.txt` and `/agents.txt`.

## Install

```
pip install forgemesh-pay-per-crawl
```

Python 3.10+. One dependency (`pycryptodome`, for keccak256). `httpx` is used for facilitator calls if installed, otherwise the standard library. Start with `mode="monitor"` (records what bots would have paid, never blocks), then switch to `mode="gate"`.

## FastAPI / Starlette

```python
from forgemesh_pay_per_crawl import Config
from forgemesh_pay_per_crawl.asgi import PayPerCrawlMiddleware

app.add_middleware(PayPerCrawlMiddleware,
    config=Config(pay_to="0xYourWalletOnBase", mode="gate", price_usd=0.01, base_url="https://example.com"))
```

## Flask (and any WSGI app)

```python
from forgemesh_pay_per_crawl import Config
from forgemesh_pay_per_crawl.wsgi import PayPerCrawlWSGI

app.wsgi_app = PayPerCrawlWSGI(app.wsgi_app,
    Config(pay_to="0xYourWalletOnBase", mode="gate", price_usd=0.01, base_url="https://example.com"))
```

## Django

```python
# settings.py
MIDDLEWARE = ["forgemesh_pay_per_crawl.django.PayPerCrawlMiddleware", *MIDDLEWARE]  # near the top
PAY_PER_CRAWL = {"pay_to": "0xYourWalletOnBase", "mode": "gate", "price_usd": 0.01, "base_url": "https://example.com"}
```

## Settings

All are `Config(...)` keyword arguments (or keys of `PAY_PER_CRAWL`).

| Setting | Default | Meaning |
|---|---|---|
| `pay_to` | required in gate mode | Your `0x` wallet on Base. |
| `mode` | `"monitor"` | `"monitor"` records only; `"gate"` answers 402. |
| `price_usd` | `0.01` | Price per page fetch, paid in USDC. |
| `facilitator_url` | PayAI (`https://facilitator.payai.network`, no key) | Any x402 facilitator that supports Base. `facilitator_auth` sets an `Authorization` header if yours needs one. |
| `class_policy` | search/social/monitor free; seo/ai/automation/bot paid | Per class: `"free"`, `"paid"` or `"block"`. |
| `bot_overrides` | `{}` | Per bot name, e.g. `{"GPTBot": "free", "Bytespider": "block"}`. |
| `allow_paths` | `[]` | Path prefixes that are never gated. `/robots.txt`, `/sitemap*`, `/llms.txt`, `/agents.txt`, `/.well-known/`, `/favicon.ico` always are. |
| `base_url` | from the request | Your public origin. Set it behind a proxy or load balancer. |
| `trust_proxy_header` | `""` | Header with the real client IP (`"CF-Connecting-IP"`, `"X-Forwarded-For"`) so search-engine verification sees the right address. |
| `mpp_secret` | random per process | HMAC key for MPP challenge ids. Set a stable value if you run more than one worker. |
| `gated_methods` | `("GET", "HEAD")` | HEAD is gated like GET (402 with no body). |
| `site_name`, `site_description`, `pages` | | Used in the discovery files; `pages` is a list (or callable returning one) of `(title, url)` for `llms.txt`. |
| `on_event` | `None` | Callback receiving a dict for every classified request (status, bot, class, rail, tx hash, payer). |

Bot classes: `human`, `search`, `social`, `monitor`, `seo`, `ai`, `automation`, `bot`. The catalog covers 85 crawlers and tools; see `core/catalog.py`.

Multiple worker processes: pass `lock=FileNonceLock("/var/tmp/fmppc")` to `Gate(...)` (and use `PayPerCrawlMiddleware(app, gate=gate)`) so a payment authorization cannot be replayed on another worker, and set a stable `mpp_secret`. The default lock is in-process memory.

### Behind Cloudflare

If your site is proxied by Cloudflare, set **AI Crawl Control** (and any Bot Fight Mode / AI Labyrinth / "Block AI bots" rule) to **Allow** for the crawlers you want to charge. Cloudflare answers those requests at the edge before they ever reach your app, so the gate would never see them. Set `trust_proxy_header="CF-Connecting-IP"` and `base_url` to your public origin.

## How a payment works

This is what happens when an x402-capable client fetches a page.

1. A bot requests a page and gets `402` with the price, asset (USDC on Base) and your wallet, in the `PAYMENT-REQUIRED` header (x402 v2), the JSON body (x402 v1, with `invalidReason` when a payment was rejected) and `WWW-Authenticate: Payment` (MPP).
2. The bot signs a USDC transfer authorization (EIP-3009) and retries with it in `PAYMENT-SIGNATURE` (v2), `X-PAYMENT` (v1) or `Authorization: Payment` (MPP).
3. The middleware checks recipient, amount and expiry locally, locks the authorization nonce against replay, then posts it to the **facilitator** (`/verify`, then `/settle`). The facilitator verifies and submits it on-chain; it never holds funds. v1 payments are forwarded in v1 shape.
4. The page is served only when a transaction hash comes back, with the receipt in `PAYMENT-RESPONSE`, `X-PAYMENT-RESPONSE` and (MPP) `Payment-Receipt`.

Without a Pro key the package never contacts ForgeMesh. Its only outbound requests are to the facilitator you chose, and only when a payment is presented. (The optional Pro reporter below is the one exception, and is off without a key.)

## Money flow

The payer's USDC moves wallet to wallet on Base, from the payer to the `pay_to` address you configured. There is no ForgeMesh account, no custody, no settlement service and no revenue share: the site owner keeps 100%. The facilitator (PayAI by default) charges the seller no fee at the time of writing; check your facilitator's terms.

## Using the pieces directly

```python
from forgemesh_pay_per_crawl import Classifier, Config, Gate, Request, X402, build_challenge

Classifier().classify("Mozilla/5.0 (compatible; GPTBot/1.2)").cls        # "ai"
gate = Gate(Config(pay_to="0x...", mode="gate"))
decision = gate.handle(Request(method="GET", path="/x", headers={"user-agent": "curl/8"}, host="example.com"))
decision.response   # a Response (status, headers, body) to send, or None to serve the page
decision.headers    # headers to add to the page you serve (payment receipt, Link)
```

`Gate.handle` is blocking (it can call the facilitator); in async code run it in a thread, as the ASGI middleware does. The facilitator transport is injectable (`Gate(config, transport=fn)` with `fn(url, body, headers) -> dict`).

## Pro (optional)

With a ForgeMesh Pay-per-Crawl Pro license (`pro_key="fmppc_..."`) the package reports daily bot rollups and settlements to the hosted dashboard at proxy.forgemesh.io and pulls the crawler-intel feed into the classifier. Nothing is sent without a key. The rollups are held in memory per process, so with several workers each reports its own counts.

## Verified

- Unit and integration tests: `pytest` (keccak vectors incl. block-boundary cases, classifier with rDNS, 402 shapes, MPP challenge/credential round trip, facilitator flow, replay, HEAD, file lock, Pro sync, all three adapters, and an integration matrix against live uvicorn/FastAPI and Flask servers with a mock facilitator).
- Real settlements on Base mainnet through PayAI, October 2026, from the FastAPI example gated at $0.01: x402 v1 ([tx](https://basescan.org/tx/0x49f0f05b3509545e5134aa6cf091ff7eab4e4f1e1b9aef9bf28280c231e2a945)) and x402 v2 ([tx](https://basescan.org/tx/0x15d95ad90c9530e4816016f65681ddd4a79730373634c991c57afa2b88a8b44b)).

## Development

```
python -m venv .venv && .venv/bin/pip install -e ".[test]"
.venv/bin/pytest
python -m build
```

MIT. Made by [ForgeMesh Labs](https://forgemesh.io) (hello@forgemesh.io).
