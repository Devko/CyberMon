"""Machine-Readable Advisories: the CSAF crawl (fetch_csaf), the builder
(csaf_metrics) and the contract (csaf_contracts). No network: the crawl
runs against the fixture tree through FixtureSession, or a tiny in-test
session."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from pipeline import contracts, csaf_metrics, fetch_csaf
from pipeline.fetch_csaf import (CARRY_DAYS, DocRef, Fetcher, FixtureSession,
                                 crawl, load_state, parse_changes_csv,
                                 parse_distributions, parse_lister,
                                 parse_robots, parse_rolie, sample_key,
                                 summarize_document)

FIX = Path(__file__).resolve().parent / "fixtures" / "csaf"
GEN = "2026-11-05T07:00:00Z"
TODAY = GEN[:10]


def _crawl(state_dir=None, session=None, **kw):
    return crawl(session or FixtureSession(FIX), state_dir, TODAY, k=2,
                 row_builder=csaf_metrics.build_row, sleep=lambda s: None,
                 log=lambda m: None, **kw)


# ---------------------------------------------------------------- robots

def test_robots_wildcards_longest_match_and_delay():
    r = parse_robots("User-agent: *\nCrawl-delay: 4\nDisallow: /*.txt$\n"
                     "Disallow: /private/\nAllow: /private/open/\n")
    assert r.delay == 4.0
    assert not r.allows("https://h.test/csaf/index.txt")
    assert r.allows("https://h.test/csaf/changes.csv")
    assert r.allows("https://h.test/csaf/index.txt.asc")
    assert not r.allows("https://h.test/private/x.json")
    assert r.allows("https://h.test/private/open/x.json")


def test_robots_prefers_our_own_group():
    r = parse_robots("User-agent: *\nDisallow: /\n\n"
                     "User-agent: CyberMon\nDisallow: /nope/\n")
    assert r.allows("https://h.test/csaf/x.json")
    assert not r.allows("https://h.test/nope/x.json")


def test_robots_empty_disallow_allows_everything():
    assert parse_robots("User-agent: *\nDisallow:\n").allows("https://h.test/a")


class _Resp:
    def __init__(self, status, body=b""):
        self.status_code = status
        self.content = body
        self.headers = {}

    @property
    def text(self):
        return self.content.decode()

    def iter_content(self, n):
        yield self.content

    def raise_for_status(self):
        if self.status_code >= 400:
            raise OSError(self.status_code)


class _Session:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, **kw):
        self.calls.append(url)
        r = self.routes.get(url, 404)
        if isinstance(r, Exception):
            raise r
        return _Resp(r) if isinstance(r, int) else _Resp(200, r)


@pytest.mark.parametrize("robots,allowed", [
    (404, True),          # RFC 9309: unavailable -> allow
    (403, True),
    (503, False),         # unreachable -> disallow all
    (OSError("down"), False),
])
def test_robots_status_rules(robots, allowed):
    fx = Fetcher(_Session({"https://h.test/robots.txt": robots}),
                 sleep=lambda s: None, log=lambda m: None)
    assert fx.allowed("https://h.test/a.json") is allowed


def test_fetcher_refuses_disallowed_urls_and_keeps_crawl_delay():
    waits = []
    s = _Session({"https://h.test/robots.txt": b"User-agent: *\nCrawl-delay: 3\n"
                                               b"Disallow: /no/\n",
                  "https://h.test/a.json": b"{}", "https://h.test/b.json": b"{}"})
    fx = Fetcher(s, sleep=waits.append, log=lambda m: None)
    with pytest.raises(PermissionError):
        fx.get("https://h.test/no/x.json", max_bytes=100)
    assert fx.get("https://h.test/a.json", max_bytes=100) == (200, b"{}")
    fx.get("https://h.test/b.json", max_bytes=100)
    assert waits and 0 < waits[-1] <= 3
    assert "https://h.test/no/x.json" not in s.calls
    assert fx.requests == len(s.calls)


def test_fetcher_caps_body_size():
    s = _Session({"https://h.test/big.json": b"x" * 50})
    fx = Fetcher(s, sleep=lambda s: None, log=lambda m: None)
    with pytest.raises(ValueError):
        fx.get("https://h.test/big.json", max_bytes=10)


# ---------------------------------------------------------------- parsing

def test_parse_lister_reads_providers_and_publishers():
    info, sources = parse_lister(json.loads((FIX / "lister.json").read_text()))
    assert info["url"] == fetch_csaf.LISTER_URL
    assert [s.kind for s in sources].count("publisher") == 1
    assert len(sources) == 5


@pytest.mark.parametrize("bad", [
    [], {"aggregator": {}}, {"aggregator": {"name": "x"}, "csaf_providers": []},
    {"aggregator": {"name": "x"},
     "csaf_providers": [{"metadata": {"url": "http://insecure.test/pm.json",
                                      "publisher": {"name": "x"}}}]},
])
def test_parse_lister_rejects_malformed(bad):
    with pytest.raises(ValueError):
        parse_lister(bad)


def test_distributions_keep_public_feeds_and_drop_closed_folders():
    pm = json.loads((FIX / "dir_pm.json").read_text())
    dists = parse_distributions(pm)
    urls = [d.url for d in dists]
    assert "https://dir.example.test/.well-known/csaf/white/" in urls
    assert not any("amber" in u for u in urls)
    assert [d.kind for d in dists] == ["directory", "rolie"]


def test_changes_csv_years_and_malformed_rows():
    docs = parse_changes_csv('"2025/a.json","2025-01-01T00:00:00Z"\n'
                             'b.json,2024-01-01T00:00:00Z\n', "https://h.test/")
    assert [(d.url, d.year) for d in docs] == [
        ("https://h.test/2025/a.json", 2025), ("https://h.test/b.json", None)]
    with pytest.raises(ValueError):
        parse_changes_csv("<html>\n" * 20, "https://h.test/")


def test_rolie_uses_content_src_then_self_link():
    docs = parse_rolie(json.loads((FIX / "feed_white.json").read_text()))
    assert [d.year for d in docs] == [2023, 2026, 2026]
    assert docs[1].url.endswith("fv-2.json")


def test_summary_requires_every_vulnerability():
    doc = json.loads((FIX / "docs" / "dv-2026-0002.json").read_text())
    assert summarize_document(doc) == {
        "c": "csaf_security_advisory", "cvss": True, "cwe": True,
        "product_tree": True, "remediation": True}
    two = copy.deepcopy(doc)
    two["vulnerabilities"].append({"cve": "CVE-2026-0002"})
    s = summarize_document(two)
    assert not s["cvss"] and not s["cwe"] and not s["remediation"]
    empty = copy.deepcopy(doc)
    empty["vulnerabilities"] = []
    s = summarize_document(empty)
    assert not s["cvss"] and s["product_tree"]
    with pytest.raises(ValueError):
        summarize_document({"no": "document"})


def test_sample_key_is_the_file_name_hash():
    assert sample_key("https://a.test/x/2026/Doc.json") == \
        sample_key("https://b.test/2024/doc.json")


# ---------------------------------------------------------------- crawl

def test_fixture_crawl_statuses_counts_and_dedup():
    res = {r.source.name: r for r in _crawl().results}
    assert res["Robots Vendor PSIRT"].status == "robots"
    assert res["Denied Coordinator"].status == "denied"
    assert res["Denied Coordinator"].detail == "HTTP 403"
    assert res["Empty Publisher"].status == "empty"
    directory = res["Directory Vendor PSIRT"]
    assert directory.status == "measured"
    # five changes.csv rows, one path twice; the white feed repeats a
    # listed document and the amber folder is never read
    assert [len(d.docs) for d in directory.dists] == [4]
    assert len(directory.dists[0].sample) == 2
    assert [len(d.docs) for d in res["Feed Vendor CERT"].dists] == [3]


def test_sample_is_the_lowest_hashes():
    res = {r.source.name: r for r in _crawl().results}
    d = res["Directory Vendor PSIRT"].dists[0]
    want = sorted(d.docs, key=lambda r: sample_key(r.url))[:2]
    assert [s["url"] for s in d.sample] == [r.url for r in want]


def test_state_caches_samples_and_refreshes_changed_documents(tmp_path):
    first = _crawl(tmp_path)
    assert first.docs_fetched == 4
    second = _crawl(tmp_path)
    assert second.docs_fetched == 0 and second.docs_cached == 4
    state = load_state(tmp_path)
    url = next(iter(state["docs"]))
    state["docs"][url]["ts"] = "an older change time"
    fetch_csaf.save_state(tmp_path, state)
    third = _crawl(tmp_path, refresh_cap=0)
    assert third.docs_fetched == 0      # over the refresh cap: kept as is
    fourth = _crawl(tmp_path)
    assert fourth.docs_fetched == 1


def test_new_document_cap_bounds_a_cold_start(tmp_path):
    out = _crawl(tmp_path, new_cap=1)
    assert out.docs_fetched == 1


def test_failed_provider_is_carried_then_dropped(tmp_path):
    _crawl(tmp_path)
    routes = json.loads((FIX / "urls.json").read_text())
    down = {u: (500 if "feed.example.test" in u and not u.endswith("robots.txt")
                else (FIX / t).read_bytes() if isinstance(t, str) else t)
            for u, t in routes.items()}
    out = _crawl(tmp_path, session=_Session(down))
    feed = next(r for r in out.results if r.source.name == "Feed Vendor CERT")
    assert feed.status == "carried" and feed.measured_on == TODAY
    row = csaf_metrics.build_row(feed)
    assert row["status"] == "carried" and row["documents"] == 3
    # beyond CARRY_DAYS the cached row expires
    state = load_state(tmp_path)
    for p in state["providers"].values():
        p["last_ok"] = "2026-01-01"
    fetch_csaf.save_state(tmp_path, state)
    out = _crawl(tmp_path, session=_Session(down))
    feed = next(r for r in out.results if r.source.name == "Feed Vendor CERT")
    assert feed.status == "error"
    assert CARRY_DAYS == 14  # the methodology copy says 14 days


def test_lister_failure_raises():
    with pytest.raises(OSError):
        _crawl(session=_Session({}))


# ---------------------------------------------------------------- builder

def test_build_and_validate_fixture_edition():
    obj = csaf_metrics.build_csaf_adoption(_crawl(), GEN)
    contracts.validate("csaf_adoption.json", obj)
    t = obj["totals"]
    assert (t["listed"], t["measured"], t["documents"]) == (5, 2, 7)
    assert t["top_name"] == "Directory Vendor PSIRT"
    assert sum(t["mix"].values()) == 7
    assert [(y["year"], y["n"], y["providers"]) for y in obj["years"]] == [
        (2023, 1, 1), (2024, 1, 1), (2025, 1, 1), (2026, 4, 2)]
    assert obj["sources"][0]["name"] == "Directory Vendor PSIRT"
    assert obj["sources"][-1]["status"] in ("robots", "denied", "empty")


def test_largest_remainder_sums_exactly():
    out = csaf_metrics._largest_remainder(7, {"vex": 1, "other": 2}, 3)
    assert sum(out.values()) == 7


@pytest.mark.parametrize("mutate", [
    lambda o: o["sources"][0]["mix"].__setitem__("vex", 99),
    lambda o: o["sources"][-1].__setitem__("documents", 3),
    lambda o: o["years"].pop(),
    lambda o: o["totals"].__setitem__("documents", 1),
    lambda o: o["sources"].reverse(),
    lambda o: o["lister"].__setitem__("listed", 99),
    lambda o: o.__setitem__("current_year", 1999),
])
def test_contract_rejects_broken_editions(mutate):
    obj = csaf_metrics.build_csaf_adoption(_crawl(), GEN)
    mutate(obj)
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("csaf_adoption.json", obj)


def test_meta_source_block_is_checked():
    meta = {"generated_at": GEN, "sample": False, "sources": {
        "cvelist": {"release": "r", "cve_count": 1},
        "epss": {"model_version": "v", "score_date": "2026-11-04",
                 "row_count": 1},
        "kev": {"catalog_version": "v", "count": 1},
        "csaf": {"fetched_at": GEN, "listed": 3, "measured": 2,
                 "documents": 1, "requests": 1, "docs_fetched": 0}}}
    contracts.validate("meta.json", meta)
    meta["sources"]["csaf"]["measured"] = 4
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("meta.json", meta)


def test_doc_ref_is_plain_data():
    assert DocRef("https://a.test/x.json", None, "t").year is None


def test_carried_edition_survives_new_year():
    obj = csaf_metrics.build_csaf_adoption(_crawl(), GEN)
    obj["generated_at"] = "2027-01-01T02:00:00Z"
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("csaf_adoption.json", obj)
    obj["stale"] = True
    contracts.validate("csaf_adoption.json", obj)


def test_time_budget_skips_remaining_providers():
    ticks = iter(range(0, 10 ** 7, 2000))   # every clock read: +2000 s
    out = _crawl(clock=lambda: next(ticks))
    assert {r.status for r in out.results} == {"error"}
    assert {r.detail for r in out.results} == {"time budget"}
    assert out.docs_fetched == 0


def _routes(fail):
    """The fixture routes as an in-test session, with ``fail(url)`` URLs
    answering 500."""
    routes = json.loads((FIX / "urls.json").read_text())
    served = {}
    for url, target in routes.items():
        if fail(url, target):
            served[url] = 500
        elif isinstance(target, str):
            served[url] = (FIX / target).read_bytes()
        else:
            served[url] = target
    return _Session(served)


def test_failing_document_host_is_cut_off():
    session = _routes(lambda u, t: isinstance(t, str) and t.startswith("docs/"))
    out = _crawl(session=session)
    assert out.docs_fetched == 0
    doc_calls = [u for u in session.calls
                 if routes_target(u).startswith("docs/")]
    # two attempts per failed document; a host is cut off after
    # HOST_FAILURES failed documents in a row
    hosts = {u.split("/")[2] for u in doc_calls}
    assert len(doc_calls) <= 2 * fetch_csaf.HOST_FAILURES * len(hosts)


def routes_target(url):
    return str(json.loads((FIX / "urls.json").read_text()).get(url, ""))


def test_unexpected_provider_error_does_not_fail_the_crawl(monkeypatch):
    real = fetch_csaf.parse_distributions

    def boom(pm):
        if "feed-white.json" in json.dumps(pm):
            raise KeyError("surprise")
        return real(pm)

    monkeypatch.setattr(fetch_csaf, "parse_distributions", boom)
    out = _crawl()
    feed = next(r for r in out.results if r.source.name == "Feed Vendor CERT")
    assert feed.status == "error" and feed.detail == "KeyError"
    other = next(r for r in out.results
                 if r.source.name == "Directory Vendor PSIRT")
    assert other.status == "measured"


def test_malformed_lister_is_a_value_error():
    session = _Session({fetch_csaf.LISTER_URL: b'{"aggregator": "x"}'})
    with pytest.raises(ValueError):
        _crawl(session=session)


def test_failed_changes_probe_falls_back_to_the_feed():
    session = _routes(lambda u, t: False)
    session.routes["https://feed.example.test/csaf/changes.csv"] = \
        OSError("connection reset")
    out = _crawl(session=session)
    feed = next(r for r in out.results if r.source.name == "Feed Vendor CERT")
    assert feed.status == "measured"
    assert [len(d.docs) for d in feed.dists] == [3]
