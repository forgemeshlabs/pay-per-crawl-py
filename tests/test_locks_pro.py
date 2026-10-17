import json

from forgemesh_pay_per_crawl.core import Classifier, Config, FileNonceLock, MemoryNonceLock, ProReporter, Stats
from tests.conftest import PAY_TO

KEY = "fmppc_" + "a" * 30


def test_memory_lock_ttl_and_release():
    t = [1000.0]
    lock = MemoryNonceLock(ttl=10, clock=lambda: t[0])
    assert lock.acquire("n") and not lock.acquire("n")
    t[0] += 11
    assert lock.acquire("n")
    lock.release("n")
    assert lock.acquire("n")


def test_file_lock_atomic_ttl_release(tmp_path):
    t = [1000.0]
    import os
    lock = FileNonceLock(tmp_path, ttl=10, clock=lambda: t[0])
    assert lock.acquire("n") and not lock.acquire("n")
    os.utime(next(tmp_path.iterdir()), (1000.0, 1000.0))
    t[0] = 1020.0  # file is 20s old: expired
    assert lock.acquire("n")
    lock.release("n")
    assert list(tmp_path.iterdir()) == [] and lock.acquire("n")


def test_stats_rollup_and_settlements():
    t = [1_800_000_000.0]
    s = Stats(clock=lambda: t[0])
    s.record({"bot_name": "GPTBot", "ua_class": "ai", "status": "unpaid", "ip_hash": "a"})
    s.record({"bot_name": "GPTBot", "ua_class": "ai", "status": "paid", "amount_units": 10000, "tx_hash": "0xtx", "payer": "0xp", "path": "/x", "rail": "x402v2", "ip_hash": "b"})
    s.record({"bot_name": "GPTBot", "ua_class": "ai", "status": "rejected", "ip_hash": "b"})
    s.record({"bot_name": "curl", "ua_class": "automation", "status": "monitor", "amount_units": 10000})
    day = "2027-01-15"
    rows = {r["bot_name"]: r for r in s.rollup(day)}
    g = rows["GPTBot"]
    assert (g["hits"], g["paid"], g["unpaid"], g["rejected"], g["revenue_units"], g["sources"]) == (3, 1, 1, 1, 10000, 2)
    assert rows["curl"]["would_units"] == 10000
    assert [x["tx_hash"] for x in s.settlements_after(0)] == ["0xtx"] and s.settlements_after(1) == []


def test_pro_disabled_without_key_and_never_calls():
    calls = []
    cfg = Config(pay_to=PAY_TO, mode="gate")
    pro = ProReporter(cfg, Stats(), "https://e.test", "E", http=lambda *a: calls.append(a) or (200, {"ok": True}))
    assert not ProReporter.enabled(cfg) and not ProReporter.enabled(Config(pro_key="nope"))
    assert pro.sync()["error"] == "no_license_key" and calls == []


def test_pro_sync_pushes_rollups_and_settlements_and_pulls_intel():
    calls = []

    def http(method, url, body, headers):
        calls.append((method, url, body, headers))
        if url.endswith("/license/verify"):
            return 200, {"ok": True, "status": "active", "sites_used": 1, "site_limit": 5}
        if url.endswith("/ingest"):
            return 200, {"ok": True}
        if url.endswith("/intel"):
            return 200, {"ok": True, "version": "v1", "agents": [
                {"name": "NewCrawler", "class": "ai", "match": ["newcrawler/"]},
                {"name": "Bad", "class": "nonsense", "match": ["x"]},
                {"name": "NoMatch", "class": "ai"}]}
        return 404, None

    t = [1_800_000_000.0]
    stats = Stats(clock=lambda: t[0])
    stats.record({"bot_name": "GPTBot", "ua_class": "ai", "status": "paid", "amount_units": 10000, "tx_hash": "0xtx", "payer": "0xp", "path": "/x", "rail": "x402v1"})
    cl = Classifier()
    cfg = Config(pay_to=PAY_TO, mode="gate", pro_key=KEY)
    pro = ProReporter(cfg, stats, "https://e.test", "E", classifier=cl, http=http, clock=lambda: t[0])
    assert pro.sync()["ok"]
    methods = [(m, u.split("proxy.forgemesh.io")[1]) for m, u, _, _ in calls]
    assert methods == [("POST", "/api/wp/license/verify"), ("POST", "/api/wp/ingest"), ("GET", "/api/wp/intel")]
    assert calls[0][3]["Authorization"] == f"Bearer {KEY}"
    ingest = calls[1][2]
    assert ingest["site"]["host"] == "e.test" and ingest["site"]["mode"] == "gate" and ingest["site"]["pay_to"] == PAY_TO
    assert ingest["settlements"][0]["tx_hash"] == "0xtx" and "id" not in ingest["settlements"][0]
    today = [d for d in ingest["daily"] if d["day"] == "2027-01-15"][0]
    assert today["rows"][0]["revenue_units"] == 10000
    assert cl.classify("NewCrawler/1.0").name == "NewCrawler" and pro.state["intel_count"] == 1
    calls.clear()
    pro.sync()  # settlements already acknowledged, intel not due, license fresh
    assert [u.split("forgemesh.io")[1] for _, u, _, _ in calls] == ["/api/wp/ingest"] and calls[0][2]["settlements"] == []


def test_pro_inactive_license_stops_sync():
    calls = []

    def http(method, url, body, headers):
        calls.append(url)
        return 403, {"ok": False, "status": "lapsed"}

    pro = ProReporter(Config(pro_key=KEY), Stats(), "https://e.test", "E", http=http)
    assert pro.sync()["ok"] is False and len(calls) == 1 and pro.state["status"] == "lapsed"
