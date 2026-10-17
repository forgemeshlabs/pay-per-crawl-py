"""FastAPI example. Run: PPC_PAY_TO=0x... uvicorn examples.fastapi_app:app --port 8412"""
import os

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from forgemesh_pay_per_crawl import Config
from forgemesh_pay_per_crawl.asgi import PayPerCrawlMiddleware

app = FastAPI()
app.add_middleware(
    PayPerCrawlMiddleware,
    config=Config(
        pay_to=os.environ.get("PPC_PAY_TO", ""),
        mode=os.environ.get("PPC_MODE", "monitor"),
        price_usd=float(os.environ.get("PPC_PRICE", "0.01")),
        facilitator_url=os.environ.get("PPC_FACILITATOR", ""),  # empty = PayAI
        mpp_secret=os.environ.get("PPC_MPP_SECRET", ""),
        site_name="Example Site",
        site_description="A FastAPI example behind pay-per-crawl.",
        allow_paths=["/open"],
        pages=[("Paid test post", "/paid-test/")],
    ),
)


@app.get("/paid-test/", response_class=HTMLResponse)
def paid_test():
    return "<html><body><h1>Paid test post</h1><p>ZZPAIDZZ</p></body></html>"


@app.get("/", response_class=HTMLResponse)
def home():
    return "<html><body>home ZZPAIDZZ</body></html>"


@app.get("/open/page", response_class=HTMLResponse)
def open_page():
    return "<html><body>open ZZOPENZZ</body></html>"
