"""EPSS Volatility: diff engine, state, daily log, builder, stage.

The diff is driven directly with hand-built fingerprint maps and EpssData
objects — every movement kind, the no-compare cases, the reset quarantine,
and the same-snapshot guard. The offline seeding path (a prior-night state
fixture diffed against the EPSS fixture) is exercised end-to-end by
test_e2e_offline.py; here the synthetic two-run drives the live path.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline import epss_volatility as ev
from pipeline import contracts
from pipeline.epss_volatility import (build_epss_volatility, diff_day,
                                      load_state, make_state, merge_row,
                                      persist, read_events, run_stage,
                                      state_path, write_events, write_state)
from pipeline.fetch_epss import EpssData

GEN = "2026-07-09T02:43:00Z"


def _epss(scores, pcts, *, model="v1", date="2026-07-08"):
    return EpssData(model_version=model, score_date=date,
                    row_count=len(scores), scores=dict(scores),
                    percentiles=dict(pcts))


# ---- a fingerprint map + feed that exercise every movement kind -------------

_OLD = {
    "CVE-A": [0.02000, 0.85000],   # prob same, percentile moves -> THE GAP
    "CVE-B": [0.00300, 0.60000],   # prob moves (no crossing), percentile moves
    "CVE-C": [0.00090, 0.35000],   # prob moves crossing 0.001, percentile same
    "CVE-D": [0.04000, 0.97000],   # prob moves crossing 0.05 -> top mover
    "CVE-E": [0.50000, 0.98500],   # prob same, percentile moves
    "CVE-F": [0.50000, 0.50000],   # identical both nights -> no movement
}
_NEW_SCORES = {"CVE-A": 0.02, "CVE-B": 0.005, "CVE-C": 0.001, "CVE-D": 0.97,
               "CVE-E": 0.5, "CVE-F": 0.5, "CVE-G": 0.9}  # G brand-new tonight
_NEW_PCTS = {"CVE-A": 0.88, "CVE-B": 0.62, "CVE-C": 0.35, "CVE-D": 0.999,
             "CVE-E": 0.99, "CVE-F": 0.5, "CVE-G": 0.95}

# Tonight's persisted state — the builder reads its header/size for the
# catalog. Production always passes a real state (make_state(epss)); never
# None (the contract requires a non-empty model_version).
_STATE = make_state(_epss(_NEW_SCORES, _NEW_PCTS, model="v1",
                          date="2026-07-08"))


# -------------------------------------------------------------- diff engine

def test_crossed_edges_both_directions():
    assert ev._crossed(0.0009, 0.0010, 0.001) is True    # up over 0.001
    assert ev._crossed(0.04, 0.97, 0.05) is True         # up over 0.05
    assert ev._crossed(0.9, 0.0005, 0.05) is True         # down under 0.05
    assert ev._crossed(0.003, 0.005, 0.001) is False      # both above
    assert ev._crossed(0.06, 0.9, 0.05) is False          # both above
    assert ev._crossed(0.001, 0.001, 0.001) is False      # unchanged on line


def test_diff_day_counts_moves_crossings_and_top_mover():
    row = diff_day(_OLD, _NEW_SCORES, _NEW_PCTS, "2026-07-08", "v1",
                   reset=False)
    assert row["n_scored"] == 7          # tonight's whole feed
    assert row["n_compared"] == 6        # CVE-G brand-new -> not compared
    assert row["prob_moved"] == 3        # B, C, D
    assert row["pct_moved"] == 4         # A, B, D, E
    assert row["crossed_lo"] == 1        # C crossed 0.001
    assert row["crossed_mid"] == 0
    assert row["crossed_hi"] == 1        # D crossed 0.05
    assert row["top_cve"] == "CVE-D"     # |0.93| beats |0.002|, |0.0001|
    assert row["top_old"] == 0.04 and row["top_new"] == 0.97
    assert row["reset"] is False


def test_diff_day_reset_suppresses_top_mover():
    # A model_version change moves ~everything; the row is kept for the
    # audit trail but carries no mover (a whole-corpus rescore is not one
    # CVE changing its mind) and the builder quarantines it entirely.
    row = diff_day(_OLD, _NEW_SCORES, _NEW_PCTS, "2026-07-08", "v2",
                   reset=True)
    assert row["reset"] is True
    assert row["top_cve"] is None
    assert row["top_old"] is None and row["top_new"] is None
    assert row["prob_moved"] == 3        # the movement is still counted


def test_diff_day_missing_percentile_never_counts_as_a_move():
    old = {"CVE-A": [0.5, None]}          # no prior percentile
    row = diff_day(old, {"CVE-A": 0.5}, {"CVE-A": 0.9}, "2026-07-08", "v1",
                   reset=False)
    assert row["pct_moved"] == 0          # an absent prior can't have "moved"


# -------------------------------------------------------------------- state

def test_state_round_trip(tmp_path):
    epss = _epss({"CVE-A": 0.02, "CVE-B": 0.5},
                 {"CVE-A": 0.88}, model="v1", date="2026-07-08")
    state = make_state(epss)
    assert state == {"model_version": "v1", "score_date": "2026-07-08",
                     "last_observed": "2026-07-08",
                     "fingerprints": {"CVE-A": [0.02, 0.88],
                                      "CVE-B": [0.5, None]}}
    assert state_path(tmp_path) == tmp_path / "history" / \
        "epss_volatility_state.json.gz"
    write_state(state_path(tmp_path), state)
    assert load_state(tmp_path, log=lambda m: None) == state


def test_missing_unreadable_or_misshapen_state_is_none(tmp_path):
    assert load_state(tmp_path, log=lambda m: None) is None  # missing
    path = state_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_bytes(b"not json")  # not gzip -> unreadable
    assert load_state(tmp_path, log=lambda m: None) is None
    write_state(path, {"model_version": 42})  # valid gzip, wrong shape
    assert load_state(tmp_path, log=lambda m: None) is None


# ---------------------------------------------------------------- daily log

def test_event_csv_round_trip_and_merge_by_date(tmp_path):
    path = tmp_path / "history" / "epss_volatility.csv"
    row1 = diff_day(_OLD, _NEW_SCORES, _NEW_PCTS, "2026-07-08", "v1",
                    reset=False)
    write_events(path, [row1])
    assert read_events(path) == [row1]
    text = path.read_text(encoding="utf-8")
    assert "0.04000" in text and "0.97000" in text and "None" not in text

    # merge replaces the same date (last run per date wins), keeps order
    row1b = diff_day(_OLD, _NEW_SCORES, _NEW_PCTS, "2026-07-08", "v1",
                     reset=False)
    row1b["prob_moved"] = 99
    row0 = dict(row1, observed_date="2026-07-07")
    merged = merge_row(merge_row([row1], row0), row1b)
    assert [r["observed_date"] for r in merged] == ["2026-07-07",
                                                    "2026-07-08"]
    assert merged[-1]["prob_moved"] == 99  # replaced, not duplicated


def test_event_csv_missing_file_and_malformed_row(tmp_path):
    assert read_events(tmp_path / "epss_volatility.csv") == []
    path = tmp_path / "epss_volatility.csv"
    path.write_text("observed_date,model_version,n_scored,n_compared,"
                    "prob_moved,pct_moved,crossed_lo,crossed_mid,crossed_hi,"
                    "top_cve,top_old,top_new,reset\n"
                    "2026-07-08,v1,7,6,not_an_int,5,1,0,1,,,,\n",
                    encoding="utf-8")
    with pytest.raises(ValueError, match="malformed EPSS-volatility row"):
        read_events(path)


# ------------------------------------------------------------------ builder

def _rows(*, min_days_worth=1):
    """A few forward nights of the same shape, distinct dates/weeks."""
    dates = ["2026-07-06", "2026-07-08", "2026-07-20"][:min_days_worth]
    return [diff_day(_OLD, _NEW_SCORES, _NEW_PCTS, d, "v1", reset=False)
            for d in dates]


def test_build_gate_closed_reports_the_thin_record():
    obj = build_epss_volatility(_rows(min_days_worth=2), state=_STATE,
                                generated_at=GEN, min_days=3)
    assert obj["gap"]["prob_moved_pct"] is None
    assert obj["gap"]["pct_moved_pct"] is None
    assert obj["gap"]["days"] == []
    assert obj["churn"]["weeks"] == []          # gated too
    assert obj["catalog"]["trend_days"] == 2    # but the count is honest
    contracts.validate("epss_volatility.json", obj)


def test_build_gate_open_weeks_gap_and_movers():
    obj = build_epss_volatility(_rows(min_days_worth=3), state=_STATE,
                                generated_at=GEN, min_days=1, min_delta=0.0)
    # weeks gap-filled across the two-week span (W28 empty W29 -> W30)
    weeks = obj["churn"]["weeks"]
    assert [w["week"] for w in weeks] == ["2026-W28", "2026-W29", "2026-W30"]
    assert weeks[1] == {"week": "2026-W29", "crossed_lo": 0, "crossed_mid": 0,
                        "crossed_hi": 0, "days": 0}   # gap-filled empty week
    assert sum(w["crossed_lo"] for w in weeks) == \
        obj["catalog"]["crossed_totals"]["lo"] == 3
    # gap: per-day shares + averages over 3 identical nights
    assert obj["gap"]["prob_moved_pct"] == 50.0     # 3 of 6 each night
    assert obj["gap"]["pct_moved_pct"] == pytest.approx(66.7, abs=0.05)
    assert len(obj["gap"]["days"]) == 3
    # movers: each night's top mover, all CVE-D +0.93
    assert [m["cve"] for m in obj["movers"]["entries"]] == \
        ["CVE-D", "CVE-D", "CVE-D"]
    assert obj["movers"]["entries"][0]["delta"] == 0.93
    contracts.validate("epss_volatility.json", obj)


def test_build_min_delta_filters_small_movers():
    # a night whose only move is tiny (< min_delta) yields no mover
    tiny = diff_day({"CVE-X": [0.500, 0.5]}, {"CVE-X": 0.502},
                    {"CVE-X": 0.5}, "2026-07-08", "v1", reset=False)
    obj = build_epss_volatility([tiny], state=_STATE, generated_at=GEN,
                                min_days=1, min_delta=0.1)
    assert obj["movers"]["entries"] == []           # 0.002 < 0.1
    assert obj["movers"]["min_delta"] == 0.1


def test_build_reset_night_is_quarantined_from_every_trend():
    good = diff_day(_OLD, _NEW_SCORES, _NEW_PCTS, "2026-07-08", "v1",
                    reset=False)
    reset = diff_day(_OLD, _NEW_SCORES, _NEW_PCTS, "2026-07-09", "v2",
                     reset=True)
    obj = build_epss_volatility([good, reset], state=_STATE, generated_at=GEN,
                                min_days=1, min_delta=0.0)
    cat = obj["catalog"]
    assert cat["days_observed"] == 2 and cat["trend_days"] == 1
    assert cat["resets_quarantined"] == 1
    assert len(obj["gap"]["days"]) == 1             # reset day excluded
    assert obj["gap"]["days"][0]["date"] == "2026-07-08"
    assert cat["crossed_totals"]["hi"] == 1         # only the good night
    assert [m["observed_date"] for m in obj["movers"]["entries"]] == \
        ["2026-07-08"]
    contracts.validate("epss_volatility.json", obj)


def test_build_empty_log_is_the_launch_shape():
    obj = build_epss_volatility([], state=_STATE, generated_at=GEN)
    assert obj["churn"]["weeks"] == []
    assert obj["gap"]["prob_moved_pct"] is None and obj["gap"]["days"] == []
    assert obj["movers"]["entries"] == []
    assert obj["catalog"]["days_observed"] == 0
    assert obj["catalog"]["first_observed"] is None
    contracts.validate("epss_volatility.json", obj)


# -------------------------------------------------------------------- stage

def _run(out: Path, epss: EpssData, *, min_days=1, min_delta=0.0, log=None):
    obj, source, rows, state = run_stage(
        out, epss, f"{epss.score_date}T02:43:00Z", offline_fixtures=False,
        min_days=min_days, min_delta=min_delta, log=log or (lambda m: None))
    persist(out, rows, state, log=lambda m: None)
    return obj, source


def test_stage_baseline_then_diff_then_snapshot_guard(tmp_path):
    out = tmp_path / "out"

    # Night 1: no committed state -> baseline, zero rows, state written.
    n1 = _epss({"CVE-A": 0.02, "CVE-B": 0.003, "CVE-C": 0.0009,
                "CVE-D": 0.04, "CVE-E": 0.5, "CVE-F": 0.5},
               {"CVE-A": 0.85, "CVE-B": 0.60, "CVE-C": 0.35, "CVE-D": 0.97,
                "CVE-E": 0.985, "CVE-F": 0.5}, model="v1", date="2026-07-07")
    obj, source = _run(out, n1)
    assert obj["catalog"]["days_observed"] == 0
    assert obj["catalog"]["state_size"] == 6
    assert source == {"score_date": "2026-07-07", "days_observed": 0}
    assert state_path(out).exists()

    # Night 2: tonight's feed diffs against night 1 -> one row.
    n2 = _epss(_NEW_SCORES, _NEW_PCTS, model="v1", date="2026-07-08")
    obj, source = _run(out, n2)
    assert obj["catalog"]["days_observed"] == 1
    assert source["days_observed"] == 1
    rows = read_events(out / "history" / "epss_volatility.csv")
    assert len(rows) == 1 and rows[0]["prob_moved"] == 3

    # Same-snapshot re-run: the score_date guard skips; merge keeps 1 row.
    obj, _ = _run(out, n2)
    assert obj["catalog"]["days_observed"] == 1
    assert len(read_events(out / "history" / "epss_volatility.csv")) == 1


def test_stage_model_reset_is_flagged_and_quarantined(tmp_path):
    out = tmp_path / "out"
    n1 = _epss({"CVE-A": 0.02, "CVE-D": 0.04}, {"CVE-A": 0.85, "CVE-D": 0.97},
               model="v1", date="2026-07-08")
    _run(out, n1)
    # A new model version tonight: everything rebaselines -> quarantined.
    n2 = _epss({"CVE-A": 0.90, "CVE-D": 0.10}, {"CVE-A": 0.99, "CVE-D": 0.40},
               model="v2", date="2026-07-09")
    obj, _ = _run(out, n2)
    assert obj["catalog"]["days_observed"] == 1
    assert obj["catalog"]["resets_quarantined"] == 1
    assert obj["catalog"]["trend_days"] == 0
    assert obj["gap"]["days"] == []                 # nothing charts
    rows = read_events(out / "history" / "epss_volatility.csv")
    assert rows[0]["reset"] is True and rows[0]["top_cve"] is None


def test_stage_offline_seeds_prior_state_from_fixture(tmp_path):
    # Mirrors the __main__ offline path: no committed state, so the prior
    # night is seeded from fixtures/epss_volatility_state.json and the
    # fixture feed produces a real row; a re-run is idempotent.
    out = tmp_path / "out"
    epss = _epss(
        {"CVE-2014-0001": 0.02, "CVE-2023-0001": 0.005,
         "CVE-2023-0002": 0.0005,
         "CVE-2023-0003": 0.001, "CVE-2024-0001": 0.97, "CVE-2025-0001": 0.5,
         "CVE-2099-9999": 0.4},
        {"CVE-2014-0001": 0.88, "CVE-2023-0001": 0.62, "CVE-2023-0002": 0.21,
         "CVE-2023-0003": 0.35, "CVE-2024-0001": 0.999, "CVE-2025-0001": 0.99,
         "CVE-2099-9999": 0.98},
        model="v2025.03.14", date="2026-07-08")
    obj, source, rows, state = run_stage(
        out, epss, GEN, offline_fixtures=True, log=lambda m: None)
    assert obj["catalog"]["days_observed"] == 1
    assert obj["gap"]["prob_moved_pct"] == 50.0     # 3 of 6
    assert obj["movers"]["entries"][0]["cve"] == "CVE-2024-0001"
    assert state is not None                         # offline writes state
    contracts.validate("epss_volatility.json", obj)
