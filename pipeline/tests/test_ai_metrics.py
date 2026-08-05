"""Unit tests for the AI Alibi builder (pipeline/ai_metrics.py).

Synthetic time_to_poc payloads, so a metric can be made to accelerate,
decelerate or sit still on demand — the real corpus does only one of
those, and a module whose entire output is a verdict must be tested
against the verdicts it does NOT currently reach.
"""
from __future__ import annotations

import pytest

from pipeline import ai_metrics
from pipeline.ai_timeline_data import ERAS, MILESTONES

GENERATED_AT = "2026-07-09T00:00:00Z"


def poc_payload(gaps: dict[int, float], *, n: int = 100,
                within_week: float = 50.0, negative: float = 40.0) -> dict:
    """A minimal time_to_poc.json shaped like the real one."""
    return {
        "hero": {
            "years": [
                {"year": year, "n": n, "median_days": value,
                 "p25_days": value - 1, "p75_days": value + 1,
                 "pct_negative": negative, "pct_within_week": within_week}
                for year, value in sorted(gaps.items())
            ],
        },
    }


def flat_years(value: float, start: int = 2000, end: int = 2025) -> dict:
    return {y: value for y in range(start, end + 1)}


def gap_block(out: dict, era: str = "chatgpt") -> dict:
    metric = next(m for m in out["banked"]["metrics"] if m["id"] == "poc_gap")
    return next(b for b in metric["eras"] if b["era"] == era)


# ---- era cutoffs ----------------------------------------------------------


def test_cut_year_never_straddles_the_cutoff_date():
    # The whole pre/post split rests on this: a year containing the cutoff
    # belongs to neither side.
    by_id = {e.id: e for e in ERAS}
    assert ai_metrics.cut_year_for(by_id["chatgpt"]) == 2021  # 2022-11-30
    assert ai_metrics.cut_year_for(by_id["gpt4"]) == 2022     # 2023-03-14
    assert ai_metrics.cut_year_for(by_id["uplift"]) == 2024   # 2025-08-27


def test_exactly_one_default_era():
    out = ai_metrics.build_ai_alibi(poc_payload(flat_years(5.0)), GENERATED_AT)
    assert sum(1 for e in out["eras"] if e["default"]) == 1


# ---- the clock ------------------------------------------------------------


def test_generation_year_is_dropped_not_marked():
    # A partial year is a fake bend at the right-hand edge; this module
    # drops it rather than plotting it with an asterisk.
    out = ai_metrics.build_ai_alibi(
        poc_payload(flat_years(5.0, 2000, 2026)), GENERATED_AT)
    assert out["clock"]["last_year"] == 2025
    years = [r["year"] for r in out["clock"]["metrics"][0]["years"]]
    assert 2026 not in years


def test_every_clock_metric_shares_one_span():
    out = ai_metrics.build_ai_alibi(poc_payload(flat_years(5.0)), GENERATED_AT)
    spans = {(m["years"][0]["year"], m["years"][-1]["year"])
             for m in out["clock"]["metrics"]}
    assert len(spans) == 1, "metrics from one cohort must share one span"


# ---- verdicts -------------------------------------------------------------


def test_flat_series_shows_no_inflection():
    out = ai_metrics.build_ai_alibi(poc_payload(flat_years(5.0)), GENERATED_AT)
    assert gap_block(out)["verdict"] == "no_inflection"
    assert out["headline"]["accelerated"] == 0


def test_acceleration_after_the_cutoff_is_detected():
    # The module must be able to find the thing it reports not finding,
    # or its null result means nothing. The gap metric is faster-is-down:
    # a big post-2021 drop is an acceleration.
    gaps = flat_years(100.0, 2000, 2021) | flat_years(2.0, 2022, 2025)
    out = ai_metrics.build_ai_alibi(poc_payload(gaps), GENERATED_AT)
    block = gap_block(out)
    assert block["verdict"] == "accelerated"
    assert block["shift_share_pct"] > 0, "toward-faster must sign positive"
    assert out["headline"]["accelerated"] >= 1


def test_deceleration_after_the_cutoff_signs_negative():
    gaps = flat_years(2.0, 2000, 2021) | flat_years(100.0, 2022, 2025)
    out = ai_metrics.build_ai_alibi(poc_payload(gaps), GENERATED_AT)
    block = gap_block(out)
    assert block["verdict"] == "decelerated"
    assert block["shift_share_pct"] < 0


def test_collapse_before_the_cutoff_banks_before_it():
    # The module's actual finding, in miniature: all the movement happens
    # a decade before the cutoff, and the era itself changes nothing.
    gaps = {**flat_years(200.0, 2000, 2004), **flat_years(5.0, 2005, 2025)}
    out = ai_metrics.build_ai_alibi(poc_payload(gaps), GENERATED_AT)
    block = gap_block(out)
    assert block["verdict"] == "no_inflection"
    assert block["pct_banked"] == pytest.approx(100.0, abs=1.0)


def test_young_era_is_withheld_not_judged():
    # 2024 cutoff with only 2025 complete: one year is not an era.
    out = ai_metrics.build_ai_alibi(
        poc_payload(flat_years(5.0, 2000, 2025)), GENERATED_AT)
    block = gap_block(out, era="uplift")
    assert block["post"]["years"] == 1
    assert block["verdict"] == "insufficient"
    assert block["pct_banked"] is None
    assert block["shift_share_pct"] is None


def test_withheld_cells_are_excluded_from_the_scoreboard():
    out = ai_metrics.build_ai_alibi(
        poc_payload(flat_years(5.0, 2000, 2025)), GENERATED_AT)
    head = out["headline"]
    assert head["judged"] < head["cells"]
    assert head["accelerated"] + head["decelerated"] + \
        head["no_inflection"] == head["judged"]


def test_tiny_movement_is_noise_not_a_verdict():
    # Total travel under the days floor: the ratio is withheld rather
    # than dividing by noise.
    gaps = flat_years(5.0, 2000, 2021) | flat_years(6.0, 2022, 2025)
    out = ai_metrics.build_ai_alibi(poc_payload(gaps), GENERATED_AT)
    block = gap_block(out)
    assert block["verdict"] == "no_inflection"
    assert block["pct_banked"] is None


# ---- the timeline ---------------------------------------------------------


def test_month_precision_rows_plot_mid_month():
    out = ai_metrics.build_ai_alibi(poc_payload(flat_years(5.0)), GENERATED_AT)
    for row in out["milestones"]:
        if row["precision"] == "month":
            assert row["plot_date"] == f"{row['date']}-15"
        else:
            assert row["plot_date"] == row["date"]


def test_timeline_is_chronological_and_complete():
    out = ai_metrics.build_ai_alibi(poc_payload(flat_years(5.0)), GENERATED_AT)
    dates = [m["plot_date"] for m in out["milestones"]]
    assert dates == sorted(dates)
    assert len(out["milestones"]) == len(MILESTONES)


def test_every_milestone_carries_a_source():
    out = ai_metrics.build_ai_alibi(poc_payload(flat_years(5.0)), GENERATED_AT)
    assert all(m["source"].startswith("https://") for m in out["milestones"])


def test_external_context_never_reaches_the_payload():
    # Vendor figures that cannot be reproduced from this pipeline are
    # documentation, deliberately inert. If one ever shows up in the
    # emitted object, it is one chart away from an axis.
    out = ai_metrics.build_ai_alibi(poc_payload(flat_years(5.0)), GENERATED_AT)
    blob = repr(out)
    assert "Mandiant" not in blob
    assert "why_not_plotted" not in blob


# ---- attention ------------------------------------------------------------


def market_payload() -> dict:
    return {
        "window_months": 60,
        "terms": [
            {"id": "ai_security", "label": "AI Security", "series": {
                "gdelt": [{"month": "2024-01", "n": 5, "index": 20.0},
                          {"month": "2024-02", "n": 9, "index": 90.0}],
                "hn": [{"month": "2024-02", "n": 3, "index": 50.0}],
            }},
            {"id": "zero_trust", "label": "Zero Trust", "series": {
                "gdelt": [{"month": "2024-01", "n": 1, "index": 10.0}],
            }},
        ],
    }


def test_attention_averages_only_the_lanes_that_have_a_value():
    out = ai_metrics.build_ai_alibi(
        poc_payload(flat_years(5.0, 2000, 2025)), GENERATED_AT,
        market=market_payload())
    term = next(t for t in out["attention"]["terms"] if t["id"] == "ai_security")
    by_month = {p["month"]: p for p in term["months"]}
    assert by_month["2024-01"] == {"month": "2024-01", "index": 20.0,
                                   "sources": 1}
    # (90 + 50) / 2 — the one-lane month is not penalised for the gap.
    assert by_month["2024-02"] == {"month": "2024-02", "index": 70.0,
                                   "sources": 2}


def test_attention_only_carries_curated_ai_terms():
    out = ai_metrics.build_ai_alibi(
        poc_payload(flat_years(5.0, 2000, 2025)), GENERATED_AT,
        market=market_payload())
    assert [t["id"] for t in out["attention"]["terms"]] == ["ai_security"]


def test_degraded_market_costs_one_section_not_the_module():
    out = ai_metrics.build_ai_alibi(
        poc_payload(flat_years(5.0, 2000, 2025)), GENERATED_AT, market=None)
    assert out["attention"]["available"] is False
    assert out["attention"]["terms"] == []
    assert out["attention"]["headline"] is None
    # The two sections that don't need the market are untouched.
    assert out["clock"]["metrics"]
    assert out["banked"]["metrics"]


def test_attention_headline_leads_with_the_biggest_rise():
    market = {
        "window_months": 60,
        "terms": [
            {"id": "ai_security", "label": "AI Security", "series": {
                "gdelt": [{"month": "2024-01", "n": 1, "index": 40.0},
                          {"month": "2024-02", "n": 1, "index": 60.0}]}},
            {"id": "agentic_ai", "label": "Agentic AI", "series": {
                "gdelt": [{"month": "2024-01", "n": 0, "index": 0.0},
                          {"month": "2024-02", "n": 1, "index": 55.0}]}},
        ],
    }
    out = ai_metrics.build_ai_alibi(
        poc_payload(flat_years(5.0, 2000, 2025)), GENERATED_AT, market=market)
    # Agentic AI ends lower (55 < 60) but travelled further (55 > 20).
    assert out["attention"]["headline"]["term_id"] == "agentic_ai"


def test_attention_clock_is_reported_as_a_band_not_endpoints():
    # One anomalous cohort year at either end must not write the headline.
    gaps = flat_years(5.0, 2000, 2023) | {2024: 5.0, 2025: -80.0}
    out = ai_metrics.build_ai_alibi(
        poc_payload(gaps), GENERATED_AT, market=market_payload())
    head = out["attention"]["headline"]
    assert "clock_last" not in head and "clock_first" not in head
    assert head["clock_min"] <= head["clock_mean"] <= head["clock_max"]


# ---- thin data ------------------------------------------------------------


def test_empty_corpus_does_not_crash():
    out = ai_metrics.build_ai_alibi(poc_payload({}), GENERATED_AT)
    assert out["clock"]["metrics"][0]["years"] == []
    assert out["banked"]["metrics"] == []
    assert out["headline"]["judged"] == 0
    assert out["headline"]["verdict"] == "insufficient"
