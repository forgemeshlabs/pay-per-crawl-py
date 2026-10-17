from forgemesh_pay_per_crawl.core import CLASSES, Classifier
from forgemesh_pay_per_crawl.core.catalog import CATALOG
from tests.conftest import UA_GPT, UA_HUMAN


class FakeDNS:
    def __init__(self, ptr=None, fwd=None):
        self.ptr, self.fwd, self.calls = ptr or {}, fwd or {}, 0

    def reverse(self, ip):
        self.calls += 1
        return self.ptr.get(ip)

    def forward(self, host):
        return self.fwd.get(host, [])


GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


def c(ua, headers=None, ip="", dns=None):
    return Classifier(resolver=dns or FakeDNS()).classify(ua, headers, ip)


def test_catalog_size_matches_php_reference():
    assert len(CATALOG) == 85
    assert {e["class"] for e in CATALOG} <= set(CLASSES)


def test_human_gptbot_claudebot_curl():
    assert c(UA_HUMAN, {"accept": "text/html,application/xhtml+xml"}).cls == "human"
    r = c(UA_GPT)
    assert (r.cls, r.name) == ("ai", "GPTBot")
    r = c("Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)")
    assert (r.cls, r.name) == ("ai", "ClaudeBot")
    assert (c("curl/8.5.0").cls, c("curl/8.5.0").name) == ("automation", "curl")


def test_empty_ua_social_seo_unknown_bot():
    assert c("").cls == "automation"
    assert c("facebookexternalhit/1.1").cls == "social"
    assert c("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)").cls == "seo"
    r = c("SomethingNewCrawler/2.0 (+https://example.com/bot)")
    assert (r.cls, r.name) == ("bot", "SomethingNewCrawler")
    assert c("UptimeRobot/2.0").cls == "monitor"


def test_browser_ua_with_json_accept_is_a_tool():
    assert c("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36", {"accept": "application/json"}).cls == "automation"


def test_googlebot_verified_by_rdns():
    dns = FakeDNS({"66.249.66.1": "crawl-66-249-66-1.googlebot.com"}, {"crawl-66-249-66-1.googlebot.com": ["66.249.66.1"]})
    r = c(GOOGLEBOT, ip="66.249.66.1", dns=dns)
    assert r.cls == "search" and r.verified is True and not r.impersonation


def test_fake_googlebot_is_demoted():
    r = c(GOOGLEBOT, ip="203.0.113.9")  # no PTR
    assert r.cls == "automation" and r.impersonation and r.verified is False
    dns = FakeDNS({"203.0.113.9": "evil.example.com"})
    assert c(GOOGLEBOT, ip="203.0.113.9", dns=dns).impersonation
    # right suffix but forward lookup does not return the IP (spoofed PTR)
    dns = FakeDNS({"203.0.113.9": "crawl.googlebot.com"}, {"crawl.googlebot.com": ["66.249.66.1"]})
    assert c(GOOGLEBOT, ip="203.0.113.9", dns=dns).impersonation


def test_no_ip_keeps_claim_unverified_and_rdns_is_cached():
    r = c(GOOGLEBOT)
    assert r.cls == "search" and r.verified is None
    dns = FakeDNS({"66.249.66.1": "x.googlebot.com"}, {"x.googlebot.com": ["66.249.66.1"]})
    cl = Classifier(resolver=dns)
    cl.classify(GOOGLEBOT, ip="66.249.66.1")
    cl.classify(GOOGLEBOT, ip="66.249.66.1")
    assert dns.calls == 1
    assert cl.verify_rdns("not-an-ip", [".googlebot.com"]) is None


def test_intel_merge_appends_and_extends_without_duplicating():
    cl = Classifier()
    cl.merge_intel([{"name": "GPTBot", "class": "ai", "match": ["gptbot", "gptbot-next"]},
                    {"name": "Brand New Crawler", "class": "seo", "match": ["brandnewcrawler/"]}])
    names = [e["name"] for e in cl.catalog]
    assert names.count("GPTBot") == 1 and "Brand New Crawler" in names
    assert cl.classify("gptbot-next/9").name == "GPTBot"
    assert cl.classify("BrandNewCrawler/1.0").cls == "seo"
