"""Market fetchers: per-source request shapes, retry policies, the HN
backfill queue, window pruning, and state round-trips — no network."""
from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone

from pipeline import fetch_market
from pipeline.market_metrics import build_market_hype
from pipeline.market_terms import TermDef

NOW = datetime(2026, 7, 9, 6, 0, 0, tzinfo=timezone.utc)
# NOW's day ordinal (739806) is divisible by 2 and 3, so the per-day
# rotation offset is 0 for the group sizes used below: expected orders
# can be written out literally.
DAY = NOW.date()

TERM_A = TermDef("alpha", "Alpha", gdelt_query='"alpha" security',
                 hn_query='"alpha"', arxiv_query='"alpha"')
TERM_B = TermDef("beta", "Beta", gdelt_query='"beta" security',
                 hn_query='"beta"', arxiv_query='"beta"')
TERM_C = TermDef("gamma", "Gamma", gdelt_query='"gamma" security',
                 hn_query='"gamma"', arxiv_query='"gamma"')
# Like alpha, but mapped into the two v1.1 lanes (wiki + edgar). The
# plain terms above have wiki_article=None / edgar_query=None, so the
# original tests double as proof that unmapped terms are skipped.
TERM_M = TermDef("mapped", "Mapped", gdelt_query='"mapped" security',
                 hn_query='"mapped"', arxiv_query='"mapped"',
                 wiki_article="Mapped_(security)",
                 edgar_query='"mapped"')


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("response body is not JSON")
        return self._payload


def _gdelt(points):
    """GDELT timelinevolraw JSON from [(datestamp, value), ...]."""
    return FakeResponse(payload={"timeline": [{"data": [
        {"date": d, "value": v} for d, v in points]}]})


def _hn(nbhits):
    return FakeResponse(payload={"nbHits": nbhits})


def _atom(total, published):
    """arXiv Atom feed with namespaced totalResults and <entry> stubs."""
    entries = "".join(f"<entry><published>{p}</published></entry>"
                      for p in published)
    return FakeResponse(text=(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<feed xmlns="http://www.w3.org/2005/Atom" '
        'xmlns:opensearch="http://a9.com/-/spec/opensearch/1.1/">'
        f"<opensearch:totalResults>{total}</opensearch:totalResults>"
        f"{entries}</feed>"))


def _wiki(month_views):
    """Pageviews monthly payload from [("YYYY-MM", views), ...]."""
    return FakeResponse(payload={"items": [
        {"timestamp": m.replace("-", "") + "0100", "views": v}
        for m, v in month_views]})


def _edgar(total):
    return FakeResponse(payload={"hits": {"total": {"value": total,
                                                    "relation": "eq"}}})


class FakeSession:
    """Serves per-source response queues and records every request; an
    exhausted queue yields a benign empty success for that source."""

    def __init__(self, gdelt=(), hn=(), arxiv=(), wiki=(), edgar=()):
        self.queues = {"gdelt": list(gdelt), "hn": list(hn),
                       "arxiv": list(arxiv), "wiki": list(wiki),
                       "edgar": list(edgar)}
        self.requests = {"gdelt": [], "hn": [], "arxiv": [],
                         "wiki": [], "edgar": []}

    def get(self, url, params=None, headers=None, timeout=None):
        source = ("gdelt" if "gdelt" in url else
                  "hn" if "algolia" in url else
                  "wiki" if "wikimedia" in url else
                  "edgar" if "efts.sec.gov" in url else "arxiv")
        self.requests[source].append(
            {"url": url, "params": dict(params or {}),
             "headers": dict(headers or {}), "timeout": timeout})
        queue = self.queues[source]
        if queue:
            return queue.pop(0)
        return {"gdelt": _gdelt([]), "hn": _hn(0), "arxiv": _atom(0, []),
                "wiki": _wiki([]), "edgar": _edgar(0)}[source]


def _no_sleep(_):
    pass


def _sync(session, terms, state=None, months=3, batch=8, sleep=_no_sleep,
          log=lambda m: None):
    return fetch_market.sync_state(state, terms, window_months=months,
                                   backfill_batch=batch, now=NOW,
                                   session=session, sleep=sleep, log=log)


def _epoch(year, month):
    return int(datetime(year, month, 1, tzinfo=timezone.utc).timestamp())


# ------------------------------------------------------------- month window

def test_month_window_spans_years():
    jan = datetime(2026, 1, 15, tzinfo=timezone.utc)
    assert fetch_market.month_window(jan, 3) == \
        ["2025-11", "2025-12", "2026-01"]
    default = fetch_market.month_window(NOW)
    assert len(default) == 60
    assert default[0] == "2021-08"
    assert default[-1] == "2026-07"


# -------------------------------------------------------------------- GDELT

def test_gdelt_daily_to_monthly_bucketing_clips_to_window():
    session = FakeSession(gdelt=[_gdelt([
        ("20260410T000000Z", 9),   # outside the 3-month window: clipped
        ("20260501T000000Z", 3),
        ("20260515T000000Z", 4),
        ("20260601T000000Z", 5),
    ])])
    state = _sync(session, [TERM_A], months=3)
    assert state["series"]["alpha"]["gdelt"] == {"2026-05": 7, "2026-06": 5}
    req = session.requests["gdelt"][0]
    assert req["params"]["query"] == '"alpha" security'
    assert req["params"]["mode"] == "timelinevolraw"
    assert req["params"]["format"] == "json"
    assert req["params"]["timespan"] == "5y"
    assert req["timeout"] == 90.0
    assert req["headers"]["User-Agent"] == \
        "CyberMon/1.0 (+https://github.com/Devko/CyberMon)"


def test_gdelt_429_plaintext_retries_once_then_keeps_cached_months():
    prior = {"version": 1, "last_sync": "2026-07-08T00:00:00Z",
             "series": {"alpha": {"gdelt": {"2026-06": 7, "2020-01": 5}}},
             "pending": []}
    session = FakeSession(gdelt=[
        FakeResponse(429, text="Too many requests. Slow down."),
        FakeResponse(429, text="Too many requests. Slow down."),
    ])
    sleeps = []
    state = _sync(session, [TERM_A], state=prior, months=3,
                  sleep=sleeps.append)
    assert len(session.requests["gdelt"]) == 2      # exactly one retry
    assert 75.0 in sleeps                           # after the long penalty
    # cached (window-pruned) months survive the failure
    assert state["series"]["alpha"]["gdelt"] == {"2026-06": 7}


def test_gdelt_non_json_200_body_also_retries_then_keeps_cache():
    prior = {"version": 1, "last_sync": "2026-07-08T00:00:00Z",
             "series": {"alpha": {"gdelt": {"2026-06": 7}}}, "pending": []}
    session = FakeSession(gdelt=[
        FakeResponse(200, text="Timeout or throttle page, not JSON"),
        FakeResponse(200, text="Timeout or throttle page, not JSON"),
    ])
    state = _sync(session, [TERM_A], state=prior, months=3)
    assert len(session.requests["gdelt"]) == 2
    assert state["series"]["alpha"]["gdelt"] == {"2026-06": 7}


# -------------------------------------------------------- GDELT fetch order

def _ids(terms):
    return [t.id for t in terms]


def test_gdelt_order_puts_starved_terms_first():
    # alpha has an (edge-case) empty gdelt dict, gamma has no entry at
    # all: both are starved and precede beta, whose curve is cached.
    series = {"beta": {"gdelt": {"2026-06": 7}}, "alpha": {"gdelt": {}}}
    order = fetch_market.gdelt_term_order([TERM_A, TERM_B, TERM_C],
                                          series, DAY)
    assert _ids(order) == ["alpha", "gamma", "beta"]


def test_gdelt_order_rotates_daily_and_cycles():
    terms = [TERM_A, TERM_B, TERM_C]
    orders = [_ids(fetch_market.gdelt_term_order(
        terms, {}, DAY + timedelta(days=i))) for i in range(4)]
    assert orders[0] == ["alpha", "beta", "gamma"]
    assert orders[1] == ["beta", "gamma", "alpha"]
    assert orders[2] == ["gamma", "alpha", "beta"]
    assert orders[3] == orders[0]  # cycle length == group size


def test_gdelt_order_rotates_groups_independently():
    # starved group [alpha, beta] rotates on its own modulus; the cached
    # group [gamma] is a fixed point but still always comes after.
    series = {"gamma": {"gdelt": {"2026-06": 1}}}
    terms = [TERM_A, TERM_B, TERM_C]
    day1 = DAY + timedelta(days=1)  # ordinal % 2 == 1
    assert _ids(fetch_market.gdelt_term_order(terms, series, DAY)) == \
        ["alpha", "beta", "gamma"]
    assert _ids(fetch_market.gdelt_term_order(terms, series, day1)) == \
        ["beta", "alpha", "gamma"]


def test_gdelt_order_is_deterministic_and_pure_for_a_fixed_date():
    terms = [TERM_A, TERM_B, TERM_C]
    series = {"beta": {"gdelt": {"2026-06": 7}}}
    first = fetch_market.gdelt_term_order(terms, series, date(2031, 2, 17))
    assert fetch_market.gdelt_term_order(terms, series,
                                         date(2031, 2, 17)) == first
    assert sorted(_ids(first)) == ["alpha", "beta", "gamma"]  # permutation
    assert terms == [TERM_A, TERM_B, TERM_C]  # inputs never mutated


def test_gdelt_pass_fetches_starved_terms_first():
    prior = {"version": 1, "last_sync": "2026-07-08T00:00:00Z",
             "series": {"alpha": {"gdelt": {"2026-06": 7}}}, "pending": []}
    session = FakeSession(gdelt=[_gdelt([("20260601T000000Z", 2)]),
                                 _gdelt([("20260601T000000Z", 3)])])
    logs = []
    state = _sync(session, [TERM_A, TERM_B], state=prior, months=3,
                  log=logs.append)
    # beta (never fetched) jumps the watchlist order ahead of alpha
    queries = [r["params"]["query"] for r in session.requests["gdelt"]]
    assert queries == ['"beta" security', '"alpha" security']
    assert state["series"]["beta"]["gdelt"] == {"2026-06": 2}
    assert state["series"]["alpha"]["gdelt"] == {"2026-06": 3}
    assert any("1 term(s) with no cached months fetch first" in m
               for m in logs)


# ----------------------------------------------------------------------- HN

def test_hn_month_epoch_bounds_and_nbhits():
    session = FakeSession(hn=[_hn(42), _hn(7)])
    state = _sync(session, [TERM_A], months=2)  # window: 2026-06, 2026-07
    reqs = session.requests["hn"]
    assert len(reqs) == 2  # previous + current month, nothing pending
    assert reqs[0]["params"]["numericFilters"] == \
        f"created_at_i>={_epoch(2026, 6)},created_at_i<{_epoch(2026, 7)}"
    assert reqs[1]["params"]["numericFilters"] == \
        f"created_at_i>={_epoch(2026, 7)},created_at_i<{_epoch(2026, 8)}"
    assert reqs[0]["params"]["query"] == '"alpha"'
    assert reqs[0]["params"]["hitsPerPage"] == 0
    assert "tags" not in reqs[0]["params"]  # default stories+comments
    assert state["series"]["alpha"]["hn"] == {"2026-06": 42, "2026-07": 7}
    assert state["pending"] == []


def test_hn_pending_queue_enqueues_oldest_first_and_pops_fifo():
    # window 2026-04..07; refresh covers 06+07, so 04+05 need backfill
    session = FakeSession(hn=[
        _hn(1), _hn(2),               # alpha refresh: 2026-06, 2026-07
        _hn(3), _hn(4),               # beta refresh
        _hn(5),                       # pop 1: alpha 2026-04 -> ok
        FakeResponse(400, payload={"error": "bad"}),  # pop 2: beta 2026-04
    ])
    state = _sync(session, [TERM_A, TERM_B], months=4, batch=2)
    assert len(session.requests["hn"]) == 6
    assert state["series"]["alpha"]["hn"]["2026-04"] == 5
    # the failed pop stays queued, still ahead of the newer months
    assert state["pending"] == [["hn", "beta", "2026-04"],
                                ["hn", "alpha", "2026-05"],
                                ["hn", "beta", "2026-05"]]


def test_hn_backfill_batch_limits_pops():
    session = FakeSession()
    state = _sync(session, [TERM_A], months=6, batch=1)
    # refresh = 2 requests; only one queued month may be drained
    assert len(session.requests["hn"]) == 3
    # 2026-02..05 were missing; the oldest was drained
    assert state["pending"] == [["hn", "alpha", "2026-03"],
                                ["hn", "alpha", "2026-04"],
                                ["hn", "alpha", "2026-05"]]
    assert "2026-02" in state["series"]["alpha"]["hn"]


# -------------------------------------------------------------------- arXiv

def test_arxiv_atom_parsing_pagination_and_bucketing(monkeypatch):
    monkeypatch.setattr(fetch_market, "ARXIV_PAGE_SIZE", 2)
    session = FakeSession(arxiv=[
        _atom(3, ["2026-05-03T10:00:00Z", "2026-05-20T00:00:00Z"]),
        _atom(3, ["2026-06-01T09:30:00Z"]),
    ])
    state = _sync(session, [TERM_A], months=3)
    reqs = session.requests["arxiv"]
    assert len(reqs) == 2
    assert reqs[0]["url"].startswith("https://export.arxiv.org")
    assert reqs[0]["params"]["search_query"] == \
        ('cat:cs.CR AND all:"alpha" '
         'AND submittedDate:[202605010000 TO 202608010000]')
    assert reqs[0]["params"]["start"] == 0
    assert reqs[1]["params"]["start"] == 2  # offset past the first page
    assert reqs[0]["params"]["max_results"] == 2
    # 2026-07 had no papers: a successful pass records the real zero
    assert state["series"]["alpha"]["arxiv"] == \
        {"2026-05": 2, "2026-06": 1, "2026-07": 0}


def test_arxiv_page_cap_stops_at_three_pages(monkeypatch):
    monkeypatch.setattr(fetch_market, "ARXIV_PAGE_SIZE", 1)
    session = FakeSession(arxiv=[
        _atom(10, ["2026-05-01T00:00:00Z"]),
        _atom(10, ["2026-06-01T00:00:00Z"]),
        _atom(10, ["2026-06-02T00:00:00Z"]),
        _atom(10, ["2026-07-01T00:00:00Z"]),  # never requested
    ])
    logs = []
    state = _sync(session, [TERM_A], months=3, log=logs.append)
    assert len(session.requests["arxiv"]) == 3
    assert any("capped" in line for line in logs)
    assert state["series"]["alpha"]["arxiv"] == \
        {"2026-05": 1, "2026-06": 2, "2026-07": 0}


def test_arxiv_success_stores_zeros_for_paperless_window_months():
    # A successful pass queries the whole window at once, so months with
    # no papers are real observations: stored as zeros, never left as
    # gaps (a gap means the fetch failed). Without this, divergence()
    # would average the last 3 *nonzero* months and fabricate research
    # attention for terms whose recent months are genuinely quiet.
    session = FakeSession(arxiv=[_atom(1, ["2026-06-15T00:00:00Z"])])
    state = _sync(session, [TERM_A], months=3)
    assert state["series"]["alpha"]["arxiv"] == \
        {"2026-05": 0, "2026-06": 1, "2026-07": 0}


def test_arxiv_success_zero_fill_replaces_stale_cached_months():
    prior = {"version": 1, "last_sync": "2026-07-08T00:00:00Z",
             "series": {"alpha": {"arxiv": {"2026-05": 9}}}, "pending": []}
    session = FakeSession(arxiv=[_atom(1, ["2026-06-15T00:00:00Z"])])
    state = _sync(session, [TERM_A], state=prior, months=3)
    # the fresh curve replaces the cache wholesale, zeros included
    assert state["series"]["alpha"]["arxiv"] == \
        {"2026-05": 0, "2026-06": 1, "2026-07": 0}


def test_arxiv_failure_keeps_cached_months_without_zero_fill():
    prior = {"version": 1, "last_sync": "2026-07-08T00:00:00Z",
             "series": {"alpha": {"arxiv": {"2026-06": 4}}}, "pending": []}
    session = FakeSession(arxiv=[FakeResponse(503, text="unavailable")])
    state = _sync(session, [TERM_A], state=prior, months=3)
    assert len(session.requests["arxiv"]) == 1  # no retry loop for arXiv
    # exactly the cached months survive: a failed fetch never invents
    # zeros for months it did not observe
    assert state["series"]["alpha"]["arxiv"] == {"2026-06": 4}


# ---------------------------------------------------------------- Wikipedia

def test_wiki_request_shape_bucketing_and_window_clip():
    session = FakeSession(wiki=[_wiki([
        ("2026-04", 999),   # API can hand back months we no longer want
        ("2026-05", 1200),
        ("2026-06", 1300),
        ("2026-07", 40),    # in-progress month arrives partial; kept in
    ])])                    # state, trimmed later at build time
    state = _sync(session, [TERM_M], months=3)  # window 2026-05..07
    req = session.requests["wiki"][0]
    assert req["url"] == (
        "https://wikimedia.org/api/rest_v1/metrics/pageviews/per-article/"
        "en.wikipedia.org/all-access/user/Mapped_(security)/monthly/"
        "2026050100/2026070100")
    assert req["headers"]["User-Agent"] == \
        "CyberMon/1.0 (+https://github.com/Devko/CyberMon)"
    assert state["series"]["mapped"]["wiki"] == \
        {"2026-05": 1200, "2026-06": 1300, "2026-07": 40}


def test_wiki_unmapped_terms_make_no_request():
    session = FakeSession()
    state = _sync(session, [TERM_A], months=3)  # wiki_article=None
    assert session.requests["wiki"] == []
    assert "wiki" not in state["series"].get("alpha", {})


def test_wiki_404_and_errors_keep_cached_months():
    prior = {"version": 1, "last_sync": "2026-07-08T00:00:00Z",
             "series": {"mapped": {"wiki": {"2026-06": 500}}},
             "pending": []}
    logs = []
    session = FakeSession(wiki=[FakeResponse(404, text="not found")])
    state = _sync(session, [TERM_M], state=prior, months=3,
                  log=logs.append)
    assert state["series"]["mapped"]["wiki"] == {"2026-06": 500}
    assert any("fix market_terms.py" in m for m in logs)
    # a transient 5xx keeps the cache too, without the rename warning
    session = FakeSession(wiki=[FakeResponse(503, text="unavailable")])
    state = _sync(session, [TERM_M], state=prior, months=3)
    assert len(session.requests["wiki"]) == 1  # no retry loop
    assert state["series"]["mapped"]["wiki"] == {"2026-06": 500}


def test_wiki_success_replaces_cache_but_leaves_unfetched_months_as_gaps():
    prior = {"version": 1, "last_sync": "2026-07-08T00:00:00Z",
             "series": {"mapped": {"wiki": {"2026-05": 9}}}, "pending": []}
    # the article only has data from 2026-06 (created then): earlier
    # months are unknown, not zero — the fresh curve replaces the cache
    session = FakeSession(wiki=[_wiki([("2026-06", 70), ("2026-07", 5)])])
    state = _sync(session, [TERM_M], state=prior, months=3)
    assert state["series"]["mapped"]["wiki"] == {"2026-06": 70, "2026-07": 5}


# -------------------------------------------------------------------- EDGAR

def test_edgar_cell_request_shape_and_month_bounds():
    session = FakeSession(edgar=[_edgar(3), _edgar(4), _edgar(5)])
    state = _sync(session, [TERM_M], months=3)  # window 2026-05..07
    reqs = session.requests["edgar"]
    assert len(reqs) == 3  # one cell per window month
    assert reqs[0]["url"] == "https://efts.sec.gov/LATEST/search-index"
    assert reqs[0]["params"] == {"q": '"mapped"', "startdt": "2026-05-01",
                                 "enddt": "2026-05-31"}
    assert reqs[1]["params"]["enddt"] == "2026-06-30"
    assert reqs[2]["params"]["enddt"] == "2026-07-31"
    # SEC's fair-access policy: name/version + contact address, nothing
    # more — a UA carrying the project URL in parentheses gets blocked
    assert reqs[0]["headers"]["User-Agent"] == "CyberMon/1.0 claude@devko.de"
    assert state["series"]["mapped"]["edgar"] == \
        {"2026-05": 3, "2026-06": 4, "2026-07": 5}


def test_edgar_month_bounds_handle_february_and_december():
    assert fetch_market._month_bounds_iso("2024-02") == \
        ("2024-02-01", "2024-02-29")  # leap year
    assert fetch_market._month_bounds_iso("2026-02") == \
        ("2026-02-01", "2026-02-28")
    assert fetch_market._month_bounds_iso("2025-12") == \
        ("2025-12-01", "2025-12-31")


def test_edgar_unmapped_terms_make_no_request():
    session = FakeSession()
    state = _sync(session, [TERM_A], months=3)  # edgar_query=None
    assert session.requests["edgar"] == []
    assert "edgar" not in state["series"].get("alpha", {})


def test_edgar_failed_cell_keeps_cached_count_others_refresh():
    prior = {"version": 1, "last_sync": "2026-07-08T00:00:00Z",
             "series": {"mapped": {"edgar": {"2026-05": 8, "2026-06": 9}}},
             "pending": []}
    session = FakeSession(edgar=[
        _edgar(10),                                   # 2026-05 refreshed
        FakeResponse(429, text="slow down"),          # 2026-06 fails
        _edgar(2),                                    # 2026-07 refreshed
    ])
    state = _sync(session, [TERM_M], state=prior, months=3)
    assert len(session.requests["edgar"]) == 3  # no per-cell retry loop
    assert state["series"]["mapped"]["edgar"] == \
        {"2026-05": 10, "2026-06": 9, "2026-07": 2}


def test_edgar_consecutive_failures_abort_the_pass(monkeypatch):
    monkeypatch.setattr(fetch_market, "_EDGAR_ABORT_AFTER", 2)
    other = TermDef("omega", "Omega", gdelt_query="o", hn_query="o",
                    arxiv_query="o", edgar_query='"omega"')
    session = FakeSession(edgar=[
        _edgar(1),                            # mapped 2026-05 lands
        FakeResponse(403, text="<html>blocked</html>"),
        FakeResponse(403, text="<html>blocked</html>"),
        # queue exhausted -> benign successes WOULD follow, but the
        # abort must stop the pass before omega is ever attempted
    ])
    logs = []
    state = _sync(session, [TERM_M, other], months=3, log=logs.append)
    assert len(session.requests["edgar"]) == 3
    assert state["series"]["mapped"]["edgar"] == {"2026-05": 1}
    assert "omega" not in {r["params"].get("q") for r
                           in session.requests["edgar"]}
    assert any("aborting the pass" in m for m in logs)


# ----------------------------------------------- v1 state forward-compat

def test_three_source_state_gains_new_lanes_without_reset():
    # A pre-v1.1 state (gdelt/hn/arxiv only) must load as-is: same
    # version, nothing discarded, and the first sync simply adds the
    # wiki/edgar keys alongside the cached months.
    prior = {"version": 1, "last_sync": "2026-07-08T00:00:00Z",
             "series": {"mapped": {"gdelt": {"2026-06": 7},
                                   "hn": {"2026-06": 3},
                                   "arxiv": {"2026-06": 1}}},
             "pending": []}
    session = FakeSession(
        gdelt=[FakeResponse(429, text="x"), FakeResponse(429, text="x")],
        arxiv=[FakeResponse(503, text="x")],
        wiki=[_wiki([("2026-06", 40)])],
        edgar=[_edgar(2), _edgar(3), _edgar(4)])
    state = _sync(session, [TERM_M], state=prior, months=3)
    # v1.1 never bumps the version: that would discard cached months
    assert state["version"] == 1
    assert state["series"]["mapped"]["gdelt"] == {"2026-06": 7}
    assert state["series"]["mapped"]["arxiv"] == {"2026-06": 1}
    assert state["series"]["mapped"]["wiki"] == {"2026-06": 40}
    assert state["series"]["mapped"]["edgar"] == \
        {"2026-05": 2, "2026-06": 3, "2026-07": 4}

    def _sync_with_state(st):
        return _sync(FakeSession(
            gdelt=[FakeResponse(429, text="x"), FakeResponse(429, text="x")],
            arxiv=[FakeResponse(503, text="x")],
            wiki=[FakeResponse(503, text="x")],
            edgar=[FakeResponse(403, text="x")] * 5), [TERM_M],
            state=st, months=3)

    # ... and the enriched state round-trips through a night where every
    # source fails: all five lanes keep their cached months.
    again = _sync_with_state(state)
    assert again["series"] == state["series"]


def test_pruning_carries_unknown_source_keys_through():
    # _pruned_state must not hardcode a source list: a state written by a
    # NEWER pipeline (or a future lane) keeps its extra keys, window-pruned.
    prior = {"version": 1, "last_sync": "2026-07-08T00:00:00Z",
             "series": {"alpha": {"gdelt": {"2026-06": 7},
                                  "somefuture": {"2026-06": 5,
                                                 "2019-01": 1}}},
             "pending": []}
    session = FakeSession(gdelt=[FakeResponse(429, text="x"),
                                 FakeResponse(429, text="x")])
    state = _sync(session, [TERM_A], state=prior, months=3)
    assert state["series"]["alpha"]["somefuture"] == {"2026-06": 5}


# ------------------------------------------------------------------ pruning

def test_window_pruning_drops_old_months_and_stale_pending():
    prior = {
        "version": 1, "last_sync": "2026-07-08T00:00:00Z",
        "series": {
            "alpha": {"gdelt": {"2020-01": 5, "2026-06": 7},
                      "hn": {"2019-12": 3}},
            "ghost": {"gdelt": {"2026-06": 99}},  # term left the watchlist
        },
        "pending": [
            ["hn", "alpha", "2020-05"],    # month left the window
            ["hn", "ghost", "2026-06"],    # term left the watchlist
            ["gdelt", "alpha", "2026-06"],  # only hn cells may be pending
        ],
    }
    # GDELT fails twice so the (pruned) cached curve is what remains
    session = FakeSession(gdelt=[FakeResponse(429, text="slow down"),
                                 FakeResponse(429, text="slow down")])
    state = _sync(session, [TERM_A], state=prior, months=2)
    assert state["series"]["alpha"]["gdelt"] == {"2026-06": 7}
    assert "2019-12" not in state["series"]["alpha"]["hn"]
    assert "ghost" not in state["series"]
    assert state["pending"] == []


# ---------------------------------------------------------------- state I/O

def test_state_round_trip_leaves_no_tmp(tmp_path):
    state = {"version": 1, "last_sync": "2026-07-09T06:00:00Z",
             "series": {"alpha": {"hn": {"2026-06": 3}}},
             "pending": [["hn", "alpha", "2026-05"]]}
    fetch_market.save_state(tmp_path, state)
    assert fetch_market.load_state(tmp_path) == state
    assert list(tmp_path.glob("*.tmp")) == []


def test_load_state_none_on_missing_or_corrupt(tmp_path):
    assert fetch_market.load_state(tmp_path, log=lambda m: None) is None
    (tmp_path / "market_state.json").write_text("{corrupt", encoding="utf-8")
    warnings = []
    assert fetch_market.load_state(tmp_path, log=warnings.append) is None
    assert warnings and "unreadable" in warnings[0]


# ------------------------------------------------------ state reconstruction

def _publish(out_dir, state, terms, generated_at="2026-07-09T06:00:00Z"):
    """Write ``out_dir/market_hype.json`` as the pipeline would publish it."""
    obj = build_market_hype(state, terms, generated_at)
    (out_dir / "market_hype.json").write_text(json.dumps(obj),
                                              encoding="utf-8")
    return obj


def test_reconstruct_state_round_trips_published_counts(tmp_path):
    window = fetch_market.month_window(NOW, 60)
    state = {"version": 1, "last_sync": "2026-07-09T06:00:00Z",
             "series": {"alpha": {
                 "gdelt": {"2026-05": 40, "2026-06": 25},
                 "hn": {m: i for i, m in enumerate(window)},
                 "arxiv": {"2026-06": 3},
             }},
             "pending": []}
    obj = _publish(tmp_path, state, [TERM_A])
    logs = []
    rebuilt = fetch_market.reconstruct_state(tmp_path, log=logs.append)
    # Closed months round-trip losslessly. The in-progress month (2026-07)
    # is deliberately never published, so it cannot be reconstructed: it is
    # re-queued and re-fetched — which the nightly HN pass does anyway.
    expected = {**state, "series": {"alpha": {
        "gdelt": {"2026-05": 40, "2026-06": 25},
        "hn": {m: i for i, m in enumerate(window) if m != "2026-07"},
        "arxiv": {"2026-06": 3},
    }}, "pending": [["hn", "alpha", "2026-07"]]}
    assert rebuilt == expected
    assert any("reconstructed sync state" in m for m in logs)
    # ... and building again from the rebuilt state reproduces every
    # published number; only the backfill counter differs (the re-queued
    # current month), which is metadata, not data.
    rebuilt_obj = build_market_hype(rebuilt, [TERM_A],
                                    "2026-07-09T06:00:00Z")
    assert rebuilt_obj["terms"] == obj["terms"]
    assert rebuilt_obj["headline"] == obj["headline"]
    assert rebuilt_obj["backfill_remaining"] == 1


def test_reconstruct_state_round_trips_wiki_and_edgar_counts(tmp_path):
    # The reconstruction path iterates whatever sources the published
    # file carries — the v1.1 lanes must survive a lost cache too.
    state = {"version": 1, "last_sync": "2026-07-09T06:00:00Z",
             "series": {"mapped": {
                 "gdelt": {"2026-06": 25},
                 "wiki": {"2026-05": 1200, "2026-06": 1300},
                 "edgar": {"2026-05": 3, "2026-06": 4},
             }},
             "pending": []}
    _publish(tmp_path, state, [TERM_M])
    rebuilt = fetch_market.reconstruct_state(tmp_path, log=lambda m: None)
    assert rebuilt["series"]["mapped"]["wiki"] == \
        {"2026-05": 1200, "2026-06": 1300}
    assert rebuilt["series"]["mapped"]["edgar"] == \
        {"2026-05": 3, "2026-06": 4}


def test_reconstruct_state_queues_window_months_missing_from_hn(tmp_path):
    window = fetch_market.month_window(NOW, 60)
    state = {"version": 1, "last_sync": "2026-07-09T06:00:00Z",
             "series": {
                 "alpha": {"hn": {m: 1 for m in window[2:]}},
                 "beta": {"gdelt": {"2026-06": 9}},  # no hn cell at all
             },
             "pending": []}
    _publish(tmp_path, state, [TERM_A, TERM_B])
    rebuilt = fetch_market.reconstruct_state(tmp_path, log=lambda m: None)
    # The published file omits the in-progress month, so the rebuilt series
    # lacks alpha's current-month hn cell; everything closed is intact.
    assert rebuilt["series"] == {
        "alpha": {"hn": {m: 1 for m in window[2:] if m != window[-1]}},
        "beta": {"gdelt": {"2026-06": 9}},
    }
    # oldest months first (the order the nightly backfill drains), all
    # terms per month: alpha's two missing leading months plus the
    # unpublishable current month, beta's entire window
    expected = []
    for month in window:
        if month in window[:2] or month == window[-1]:
            expected.append(["hn", "alpha", month])
        expected.append(["hn", "beta", month])
    assert rebuilt["pending"] == expected


def test_reconstruct_state_none_on_missing_or_corrupt_output(tmp_path):
    assert fetch_market.reconstruct_state(tmp_path,
                                          log=lambda m: None) is None
    path = tmp_path / "market_hype.json"
    warnings = []
    path.write_text("{corrupt", encoding="utf-8")
    assert fetch_market.reconstruct_state(tmp_path,
                                          log=warnings.append) is None
    path.write_text(json.dumps({"generated_at": "2026-07-09T06:00:00Z"}),
                    encoding="utf-8")  # valid JSON, not the published shape
    assert fetch_market.reconstruct_state(tmp_path,
                                          log=warnings.append) is None
    assert len(warnings) == 2
    assert all("cannot reconstruct" in w for w in warnings)


# ------------------------------------------------------------ full sync run

def test_full_sync_pass_request_counts_for_two_terms():
    session = FakeSession()  # benign defaults for every source
    state = _sync(session, [TERM_A, TERM_B], months=3, batch=8)
    assert len(session.requests["gdelt"]) == 2   # one curve per term
    assert len(session.requests["arxiv"]) == 2   # one page per term
    # both terms are unmapped for the v1.1 lanes: not a single request
    assert session.requests["wiki"] == []
    assert session.requests["edgar"] == []
    # 2 terms x (prev+current refresh) + 2 backfilled cells for 2026-05
    assert len(session.requests["hn"]) == 6
    assert state["version"] == 1
    assert state["last_sync"] == "2026-07-09T06:00:00Z"
    assert state["pending"] == []
    for term_id in ("alpha", "beta"):
        assert set(state["series"][term_id]) == {"gdelt", "hn", "arxiv"}
        assert state["series"][term_id]["hn"] == \
            {"2026-05": 0, "2026-06": 0, "2026-07": 0}
        # the empty-feed arXiv success stores explicit zeros, not a gap
        assert state["series"][term_id]["arxiv"] == \
            {"2026-05": 0, "2026-06": 0, "2026-07": 0}
