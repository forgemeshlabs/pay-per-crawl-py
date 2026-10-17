"""Flask example. Run: PPC_PAY_TO=0x... flask --app examples.flask_app run --port 8413"""
import os

from flask import Flask

from forgemesh_pay_per_crawl import Config
from forgemesh_pay_per_crawl.wsgi import PayPerCrawlWSGI

app = Flask(__name__)
app.wsgi_app = PayPerCrawlWSGI(
    app.wsgi_app,
    Config(
        pay_to=os.environ.get("PPC_PAY_TO", ""),
        mode=os.environ.get("PPC_MODE", "monitor"),
        price_usd=float(os.environ.get("PPC_PRICE", "0.01")),
        facilitator_url=os.environ.get("PPC_FACILITATOR", ""),
        mpp_secret=os.environ.get("PPC_MPP_SECRET", ""),
        site_name="Example Site",
        site_description="A Flask example behind pay-per-crawl.",
        allow_paths=["/open"],
        pages=[("Paid test post", "/paid-test/")],
    ),
)


@app.get("/paid-test/")
def paid_test():
    return "<html><body><h1>Paid test post</h1><p>ZZPAIDZZ</p></body></html>"


@app.get("/")
def home():
    return "<html><body>home ZZPAIDZZ</body></html>"


@app.get("/open/page")
def open_page():
    return "<html><body>open ZZOPENZZ</body></html>"
