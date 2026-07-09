"""Security Market math: index-to-peak, YoY, divergence, headline, stage."""
from __future__ import annotations

import json
from pathlib import Path

from pipeline import market_contracts
from pipeline.market_metrics import (build_market_hype, divergence,
                                     index_series, run_stage, yoy)
from pipeline.market_terms import TERMS, TermDef

from .conftest import GENERATED_AT

FIXTURES = Path(__file__).parent / "fixtures"


def _monthly(counts, start="2024-01"):
    """month->count dict for consecutive months beginning at ``start``."""
    year, month = int(start[:4]), int(start[5:7])
    out = {}
    for n in counts:
        out[f"{year:04d}-{month:02d}"] = n
        month += 1
        if month > 12:
            year, month = year + 1, 1
    return out


def _series(indexes, start_month=1):
    """A minimal index series with the given index values (recent last)."""
    return [{"month": f"2026-{start_month + i:02d}", "n": 1, "index": v}
            for i, v in enumerate(indexes)]


def _term(term_id):
    return TermDef(term_id, term_id.upper(), gdelt_query=term_id,
                   hn_query=term_id, arxiv_query=term_id)


def _state(series, pending=()):
    return {"version": 1, "last_sync": "2026-07-01T00:00:00Z",
            "series": series, "pending": [list(p) for p in pending]}


def _fixture_state():
    return json.loads((FIXTURES / "market" / "state.json")
                      .read_text(encoding="utf-8"))


# ----------------------------------------------------------- index-to-peak

def test_index_series_normalizes_to_peak_and_sorts():
    out = index_series({"2024-02": 5, "2024-01": 10, "2024-03": 0})
    assert out == [{"month": "2024-01", "n": 10, "index": 100.0},
                   {"month": "2024-02", "n": 5, "index": 50.0},
                   {"month": "2024-03", "n": 0, "index": 0.0}]


def test_index_series_rounds_to_one_decimal():
    out = index_series({"2024-01": 1, "2024-02": 3})
    assert out[0]["index"] == 33.3 and out[1]["index"] == 100.0


def test_index_series_zero_peak_yields_all_zero_indexes():
    out = index_series({"2024-01": 0, "2024-02": 0})
    assert [p["index"] for p in out] == [0.0, 0.0]
    assert index_series({}) == []


# ------------------------------------------------------------ year-over-year

def test_yoy_needs_24_populated_months():
    assert yoy(_monthly([10] * 23)) is None
    assert yoy({}) is None


def test_yoy_needs_nonzero_prior_baseline():
    assert yoy(_monthly([0] * 12 + [10] * 12)) is None


def test_yoy_needs_minimum_volume():
    # 11 prior hits shrinking to 4 is noise, not a -63.6% market move.
    assert yoy(_monthly([1] * 11 + [0] + [1] * 4 + [0] * 8)) is None
    # exactly at the floor (15 + 15 = 30) a percentage may post
    at_floor = yoy(_monthly([2] * 3 + [1] * 9 + [1] * 9 + [2] * 3))
    assert at_floor is not None and at_floor["pct_change"] == 0.0


def test_yoy_change_on_raw_counts():
    out = yoy(_monthly([10] * 12 + [15] * 12, start="2024-07"))
    assert out == {"latest_month": "2026-06", "pct_change": 50.0,
                   "n_latest_12m": 180, "n_prior_12m": 120}


def test_yoy_uses_only_the_latest_24_populated_months():
    # six huge early months must not leak into either window
    out = yoy(_monthly([100] * 6 + [10] * 12 + [15] * 12, start="2024-01"))
    assert out["pct_change"] == 50.0
    assert out["n_prior_12m"] == 120 and out["n_latest_12m"] == 180


# -------------------------------------------------------------- divergence

def test_divergence_needs_3_populated_months_in_each_source():
    assert divergence(_series([50.0, 60.0]), _series([10.0, 20.0, 30.0])) is None
    assert divergence(_series([50.0] * 3), _series([10.0, 20.0])) is None
    assert divergence([], []) is None


def test_divergence_averages_only_the_3_most_recent_months():
    out = divergence(_series([0.0, 90.0, 95.0, 100.0]),
                     _series([10.0, 20.0, 30.0]))
    assert out == {"gdelt_index_avg3m": 95.0, "arxiv_index_avg3m": 20.0,
                   "research_vs_media_index": -75.0,
                   "direction": "media_leads"}


def test_divergence_directions_and_dead_zone_edges():
    def rvm(gdelt_idx, arxiv_idx):
        return divergence(_series([gdelt_idx] * 3), _series([arxiv_idx] * 3))

    assert rvm(50.0, 80.0)["direction"] == "research_leads"
    assert rvm(80.0, 50.0)["direction"] == "media_leads"
    assert rvm(50.0, 55.0)["direction"] == "aligned"
    # dead zone is inclusive: exactly +/-10 is still "aligned"
    assert rvm(50.0, 60.0)["research_vs_media_index"] == 10.0
    assert rvm(50.0, 60.0)["direction"] == "aligned"
    assert rvm(60.0, 50.0)["research_vs_media_index"] == -10.0
    assert rvm(60.0, 50.0)["direction"] == "aligned"
    # ... and one tenth past it flips the call
    assert rvm(50.0, 60.1)["direction"] == "research_leads"
    assert rvm(60.1, 50.0)["direction"] == "media_leads"


# ---------------------------------------------------------------- headline

def test_headline_riser_faller_and_tiebreak_by_term_id():
    rising = _monthly([10] * 12 + [20] * 12, start="2024-07")   # +100%
    falling = _monthly([20] * 12 + [10] * 12, start="2024-07")  # -50%
    state = _state({"bbb": {"gdelt": dict(rising)},
                    "aaa": {"gdelt": dict(rising)},  # ties bbb at +100.0
                    "ccc": {"gdelt": falling}})
    obj = build_market_hype(state, [_term(t) for t in ("bbb", "aaa", "ccc")],
                            GENERATED_AT)
    assert obj["headline"]["top_riser"] == {
        "term_id": "aaa", "label": "AAA", "source": "gdelt",
        "pct_change": 100.0}
    assert obj["headline"]["top_faller"] == {
        "term_id": "ccc", "label": "CCC", "source": "gdelt",
        "pct_change": -50.0}


def test_headline_divergence_tiebreak_by_term_id():
    series = {"gdelt": _monthly([10, 10, 10], start="2026-04"),
              "arxiv": _monthly([1, 2, 4], start="2026-04")}
    state = _state({"bbb": series,
                    "aaa": {k: dict(v) for k, v in series.items()}})
    obj = build_market_hype(state, [_term(t) for t in ("bbb", "aaa")],
                            GENERATED_AT)
    top = obj["headline"]["top_divergence"]
    assert top["term_id"] == "aaa" and top["direction"] == "media_leads"


def test_headline_null_when_nothing_eligible():
    state = _state({"aaa": {"gdelt": _monthly([5] * 10)}})  # too sparse
    obj = build_market_hype(state, [_term("aaa")], GENERATED_AT)
    assert obj["headline"] == {"top_riser": None, "top_faller": None,
                               "top_divergence": None}


# ----------------------------------------------- end-to-end from the fixture

def test_build_market_hype_from_fixture_state():
    state = _fixture_state()
    terms = [t for t in TERMS if t.id in state["series"]]
    obj = build_market_hype(state, terms, GENERATED_AT)
    market_contracts.validate("market_hype.json", obj)

    assert obj["generated_at"] == GENERATED_AT
    assert obj["window_months"] == 60
    assert obj["sources"] == ["gdelt", "hn", "arxiv"]
    assert obj["backfill_remaining"] == 3
    assert [t["id"] for t in obj["terms"]] == [t.id for t in terms]

    by_id = {t["id"]: t for t in obj["terms"]}
    assert by_id["zero_trust"]["yoy"]["gdelt"] == {
        "latest_month": "2026-06", "pct_change": 75.0,
        "n_latest_12m": 980, "n_prior_12m": 560}
    assert by_id["zero_trust"]["yoy"]["arxiv"] is None  # only 4 months
    assert by_id["sase"]["yoy"]["gdelt"]["pct_change"] == -39.2
    assert by_id["cnapp"]["yoy"]["gdelt"] is None       # 23 months < 24
    assert by_id["cnapp"]["divergence"] is None         # 2 arxiv months < 3
    assert by_id["sase"]["divergence"] is None          # no arxiv at all
    assert by_id["sase"]["series"]["arxiv"] == []       # absent source = empty

    assert by_id["post_quantum"]["divergence"] == {
        "gdelt_index_avg3m": 42.0, "arxiv_index_avg3m": 90.9,
        "research_vs_media_index": 48.9, "direction": "research_leads"}
    assert by_id["deepfake"]["divergence"] == {
        "gdelt_index_avg3m": 90.0, "arxiv_index_avg3m": 31.7,
        "research_vs_media_index": -58.3, "direction": "media_leads"}
    assert by_id["ransomware"]["divergence"]["direction"] == "aligned"
    assert by_id["zero_trust"]["divergence"]["direction"] == "aligned"

    assert obj["headline"] == {
        "top_riser": {"term_id": "zero_trust", "label": "Zero Trust",
                      "source": "gdelt", "pct_change": 75.0},
        "top_faller": {"term_id": "sase", "label": "SASE",
                       "source": "gdelt", "pct_change": -39.2},
        "top_divergence": {"term_id": "deepfake", "label": "Deepfake",
                           "research_vs_media_index": -58.3,
                           "direction": "media_leads"},
    }


# -------------------------------------------------------------------- stage

def test_run_stage_offline_fixtures(tmp_path):
    obj, source = run_stage(tmp_path, tmp_path / "cache", GENERATED_AT,
                            skip=False, offline_fixtures=True,
                            backfill_batch=5, log=lambda m: None)
    market_contracts.validate("market_hype.json", obj)
    assert obj["generated_at"] == GENERATED_AT
    assert "stale" not in obj
    assert source == {"fetched_at": GENERATED_AT, "term_count": 6,
                      "backfill_remaining": 3}
    assert not (tmp_path / "cache").exists()   # no disk-state writes
    assert list(tmp_path.iterdir()) == []      # no output writes either


def test_run_stage_skip_carries_prior_file_forward(tmp_path):
    prior = {"generated_at": "2026-06-01T00:00:00Z", "window_months": 60,
             "sources": ["gdelt", "hn", "arxiv"], "backfill_remaining": 2,
             "terms": [],
             "headline": {"top_riser": None, "top_faller": None,
                          "top_divergence": None}}
    (tmp_path / "market_hype.json").write_text(json.dumps(prior),
                                               encoding="utf-8")
    logs = []
    obj, source = run_stage(tmp_path, tmp_path / "cache", GENERATED_AT,
                            skip=True, offline_fixtures=False,
                            backfill_batch=5, log=logs.append)
    assert obj["stale"] is True
    assert obj["generated_at"] == GENERATED_AT
    assert obj["terms"] == [] and obj["backfill_remaining"] == 2  # untouched
    assert source == {"fetched_at": "2026-06-01T00:00:00Z", "stale": True}
    market_contracts.validate("market_hype.json", obj)  # stale shape is valid
    assert any("carrying forward" in m for m in logs)


def test_run_stage_skip_without_prior_returns_nothing(tmp_path):
    logs = []
    obj, source = run_stage(tmp_path, tmp_path / "cache", GENERATED_AT,
                            skip=True, offline_fixtures=False,
                            backfill_batch=5, log=logs.append)
    assert (obj, source) == (None, None)
    assert any("no previous market_hype.json" in m for m in logs)


def _capture_sync(monkeypatch):
    """Stub out fetch_market.sync_state, recording the state it was given
    and returning it unchanged (None becomes a minimal empty state)."""
    from pipeline import fetch_market

    seen = {}

    def fake_sync(state, terms, **kwargs):
        seen["state"] = state
        return state or {"version": 1, "last_sync": GENERATED_AT,
                         "series": {}, "pending": []}

    monkeypatch.setattr(fetch_market, "sync_state", fake_sync)
    return seen


def test_run_stage_live_reconstructs_lost_state_from_published_output(
        tmp_path, monkeypatch):
    from pipeline import fetch_market

    prior = build_market_hype(_state({"aaa": {"hn": {"2026-06": 5}}}),
                              [_term("aaa")], "2026-06-01T00:00:00Z")
    (tmp_path / "market_hype.json").write_text(json.dumps(prior),
                                               encoding="utf-8")
    seen = _capture_sync(monkeypatch)
    logs = []
    run_stage(tmp_path, tmp_path / "cache", GENERATED_AT,
              skip=False, offline_fixtures=False,
              backfill_batch=5, log=logs.append)
    assert any("reconstructed sync state" in m for m in logs)
    assert seen["state"]["series"]["aaa"]["hn"] == {"2026-06": 5}
    assert seen["state"]["last_sync"] == "2026-06-01T00:00:00Z"
    # the reconstructed-then-synced state is persisted for the next night
    assert fetch_market.load_state(tmp_path / "cache") == seen["state"]


def test_run_stage_live_starts_fresh_when_nothing_to_reconstruct(
        tmp_path, monkeypatch):
    seen = _capture_sync(monkeypatch)
    run_stage(tmp_path, tmp_path / "cache", GENERATED_AT,
              skip=False, offline_fixtures=False,
              backfill_batch=5, log=lambda m: None)
    assert seen["state"] is None  # absent output -> fresh-state behavior
