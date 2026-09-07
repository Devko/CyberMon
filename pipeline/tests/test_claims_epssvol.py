"""Claims audit for the EPSS Volatility copy (test_claims_rescores.py pattern).

Like Silent Rescores, this module launches with no accumulated record, so
every check here is RANGE-FREE: there is no number a range could honestly
bound yet. The copy makes structural promises instead — the min-days gate
fires consistently, reset nights are quarantined from every trend, the
movers board only ever shows real moves, and the JSON and the committed CSV
describe the same record — and those are asserted as structural truths
against whatever data has accumulated. Never silence a failure here: fix the
copy in site/js/editorial.js or the pipeline, never the test.

Skips itself when site/data/ holds sample data or the file is missing (on
first ship the orchestrator generates epss_volatility.json; until then this
audit has nothing to judge — the committed CSV starts empty by design).
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parents[2] / "site" / "data"

_meta_path = DATA_DIR / "meta.json"
if not _meta_path.exists():
    pytest.skip(
        "site/data/meta.json missing — no committed data to audit",
        allow_module_level=True,
    )
if json.loads(_meta_path.read_text("utf-8")).get("sample") is True:
    pytest.skip(
        "site/data holds sample data — claims audit only judges real data",
        allow_module_level=True,
    )


def load_obj() -> dict:
    path = DATA_DIR / "epss_volatility.json"
    if not path.exists():
        pytest.skip("epss_volatility.json missing — nothing to audit")
    return json.loads(path.read_text("utf-8"))


def load_csv() -> list[dict]:
    path = DATA_DIR / "history" / "epss_volatility.csv"
    if not path.exists():
        pytest.skip("history/epss_volatility.csv missing — nothing to audit")
    with path.open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_catalog_day_counts_split_cleanly():
    # methodology: reset, pooled and lurch nights are "quarantined ... and
    # listed with a reason" — days_observed splits exactly into trend
    # nights + the named quarantined nights, and the per-reason counts add
    # up to the list.
    cat = load_obj()["catalog"]
    assert cat["trend_days"] + len(cat["quarantined"]) == cat["days_observed"]
    assert (cat["resets_quarantined"] + cat["gaps_quarantined"]
            + cat["anomalies_quarantined"]) == len(cat["quarantined"])


def test_anomaly_rule_matches_the_copy():
    # hero methodology: "more than five times the clean-night median (and
    # above five percent)" — the numbers in the copy are the builder's.
    cat = load_obj()["catalog"]
    assert cat["anomaly_rule"] == {"factor": 5.0, "min_share_pct": 5.0,
                                   "min_nights": 5}


def test_no_trend_night_is_a_lurch():
    # churn caption: lurch nights "are quarantined from these bars" — so no
    # night left in the trend exceeds the rule's cutoff over the trend's own
    # median (judged only once the rule has its baseline).
    gap = load_obj()["gap"]
    shares = sorted(d["prob_moved"] for d in gap["days"])
    if len(shares) < 5:
        pytest.skip("fewer than five trend nights — the rule has no baseline")
    mid = len(shares) // 2
    median = shares[mid] if len(shares) % 2 else \
        (shares[mid - 1] + shares[mid]) / 2
    assert max(shares) <= max(5.0 * median, 5.0)


def test_material_crossings_are_vanishingly_rare():
    # churn caption: "material crossings are vanishingly rare" set against
    # the percentile churn — over the trend, crossings of any line are
    # under one percent of percentile moves.
    d = load_obj()
    cat = d["catalog"]
    if not d["gap"]["days"]:
        pytest.skip("gap gate closed — nothing charted yet")
    trend_dates = {x["date"] for x in d["gap"]["days"]}
    pct_moves = sum(int(r["pct_moved"]) for r in load_csv()
                    if r["observed_date"] in trend_dates)
    crossings = sum(cat["crossed_totals"].values())
    assert pct_moves > 0
    assert crossings / pct_moves < 0.01


def test_gap_gate_fires_consistently():
    # caption/placeholder: "the gap charts once {min_days} nights have
    # accumulated" — the two averages and the per-day series are present
    # exactly when the gate is open, and absent otherwise.
    gap = load_obj()["gap"]
    gated = gap["trend_days"] < gap["min_days"]
    assert (gap["prob_moved_pct"] is None) == gated
    assert (gap["pct_moved_pct"] is None) == gated
    assert (len(gap["days"]) == 0) == gated


def test_weekly_crossings_reproduce_the_catalog_totals():
    # hero/churn: the two charts read one committed log, so the weekly
    # material-crossing bars must sum to the catalog's per-band totals.
    d = load_obj()
    weeks = d["churn"]["weeks"]
    totals = d["catalog"]["crossed_totals"]
    if weeks:
        for band in ("lo", "mid", "hi"):
            assert sum(w[f"crossed_{band}"] for w in weeks) == totals[band]


def test_movers_are_real_moves_ranked_by_magnitude():
    # movers copy: "ranked by the size of the move", each above the minimum.
    d = load_obj()
    min_delta = d["movers"]["min_delta"]
    prev = None
    for m in d["movers"]["entries"]:
        assert abs(m["delta"] - round(m["new"] - m["old"], 5)) < 1e-4
        assert abs(m["delta"]) + 1e-6 >= min_delta
        if prev is not None:
            assert abs(m["delta"]) <= prev + 1e-9  # non-increasing magnitude
        prev = abs(m["delta"])


def test_reset_nights_carry_no_mover_on_the_log():
    # methodology: a reset night's top mover is suppressed ("a whole-corpus
    # rescore is not one CVE moving").
    load_obj()  # gate on the published file, like the rest of the audit
    for row in load_csv():
        if row["reset"] == "1":
            assert row["top_cve"] == ""


def test_json_and_csv_agree_on_the_record():
    # the JSON is rebuilt from the committed CSV nightly; the two must
    # describe the same record.
    d = load_obj()
    rows = load_csv()
    cat = d["catalog"]
    assert cat["days_observed"] == len(rows)
    quarantined = {q["date"] for q in cat["quarantined"]}
    assert cat["trend_days"] == sum(1 for r in rows
                                    if r["observed_date"] not in quarantined)
    # every reset flagged on the log is a quarantined night, by that name
    for r in rows:
        if r["reset"] == "1":
            assert any(q["date"] == r["observed_date"] and q["reason"] == "reset"
                       for q in cat["quarantined"])
    if rows:
        assert cat["first_observed"] == min(r["observed_date"] for r in rows)
    else:
        assert cat["first_observed"] is None
