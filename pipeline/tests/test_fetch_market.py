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


class FakeSession:
    """Serves per-source response queues and records every request; an
    exhausted queue yields a benign empty success for that source."""

    def __init__(self, gdelt=(), hn=(), arxiv=()):
        self.queues = {"gdelt": list(gdelt), "hn": list(hn),
                       "arxiv": list(arxiv)}
        self.requests = {"gdelt": [], "hn": [], "arxiv": []}

    def get(self, url, params=None, headers=None, timeout=None):
        source = ("gdelt" if "gdelt" in url else
                  "hn" if "algolia" in url else "arxiv")
        self.requests[source].append(
            {"url": url, "params": dict(params or {}),
             "headers": dict(headers or {}), "timeout": timeout})
        queue = self.queues[source]
        if queue:
            return queue.pop(0)
        return {"gdelt": _gdelt([]), "hn": _hn(0),
                "arxiv": _atom(0, [])}[source]


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
