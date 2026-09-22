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
    # belongs to neither side — the pre window ends the year before it
    # and the post window starts the year after it.
    by_id = {e.id: e for e in ERAS}
    assert ai_metrics.cut_year_for(by_id["chatgpt"]) == 2021  # 2022-11-30
    assert ai_metrics.cut_year_for(by_id["gpt4"]) == 2022     # 2023-03-14
    assert ai_metrics.cut_year_for(by_id["uplift"]) == 2024   # 2025-08-27
    assert ai_metrics.post_start_year_for(by_id["chatgpt"]) == 2023
    assert ai_metrics.post_start_year_for(by_id["gpt4"]) == 2024
    assert ai_metrics.post_start_year_for(by_id["uplift"]) == 2026


def test_january_first_cutoff_keeps_the_windows_adjacent():
    # A cutoff dated January 1 contains no pre-cutoff day, so its year is
    # entirely post-era: it starts the post window instead of being
    # skipped. Any other date in the year straddles it.
    from pipeline.ai_timeline_data import Era
    jan1 = Era("x", "X", "2020-01-01", "c")
    jan2 = Era("y", "Y", "2020-01-02", "c")
    assert ai_metrics.cut_year_for(jan1) == 2019
    assert ai_metrics.post_start_year_for(jan1) == 2020
    assert ai_metrics.cut_year_for(jan2) == 2019
    assert ai_metrics.post_start_year_for(jan2) == 2021


def test_straddling_year_is_excluded_from_both_windows():
    # The ChatGPT cutoff (2022-11-30) sits inside 2022. A wild 2022 value
    # must move NEITHER the pre level (2017-2021) nor the post level
    # (2023 onward): the year belongs to no side of the arithmetic.
    base = flat_years(5.0, 2000, 2025)
    out_flat = ai_metrics.build_ai_alibi(poc_payload(base), GENERATED_AT)
    wild = {**base, 2022: 900.0}
    out_wild = ai_metrics.build_ai_alibi(poc_payload(wild), GENERATED_AT)
    flat, spiked = gap_block(out_flat), gap_block(out_wild)
    assert spiked["post_start_year"] == 2023
    assert spiked["pre"] == flat["pre"]
    assert spiked["post"] == flat["post"]
    assert spiked["post"]["years"] == 3  # 2023, 2024, 2025
    assert spiked["verdict"] == "no_inflection"


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
    # GPT-4 cutoff (2023-03-14): 2023 straddles it, so with 2024 the last
    # complete year the post window holds 2024 alone — one year is not
    # an era.
    out = ai_metrics.build_ai_alibi(
        poc_payload(flat_years(5.0, 2000, 2024)), "2025-07-09T00:00:00Z")
    block = gap_block(out, era="gpt4")
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


# ---- the primary metric: provisional cohorts never carry a verdict -------


def arming_years(values: dict[int, float], *, provisional_from: int) -> list:
    return [{"year": y, "n": 50, "median_days": v, "pct_within_week": 50.0,
             "pct_negative": 10.0, "provisional": y >= provisional_from}
            for y, v in sorted(values.items())]


def lfl_block(out: dict, era: str = "chatgpt") -> dict:
    metric = next(m for m in out["banked"]["metrics"] if m["primary"])
    assert metric["id"] == "poc_like_for_like"
    return next(b for b in metric["eras"] if b["era"] == era)


def test_banked_withholds_when_every_post_cutoff_year_is_provisional():
    # A clear acceleration after the ChatGPT cut (2021), but every
    # post-cutoff cohort is still being indexed. Publishing a verdict on
    # cohorts known to read biased is exactly the artifact the flag
    # exists to prevent, so the cell is withheld.
    payload = poc_payload(flat_years(5.0))
    payload["arming"] = {
        "horizon_days": 90, "ingestion_allowance_days": 365,
        "observed_through": "2026-04-10", "min_n": 30,
        "years": arming_years(flat_years(100.0, 2000, 2021)
                              | flat_years(2.0, 2022, 2025),
                              provisional_from=2022)}
    out = ai_metrics.build_ai_alibi(payload, GENERATED_AT)
    block = lfl_block(out)
    # The post level is a mean over SETTLED years only, so with every
    # post-cutoff cohort provisional there is no level to report at all.
    assert block["post"]["years"] == 0
    assert block["post"]["value"] is None
    assert block["verdict"] == "insufficient"
    assert block["pct_banked"] is None and block["shift_share_pct"] is None
    # The headline quotes the primary metric, so it withholds too.
    assert out["headline"]["verdict"] == "insufficient"

    # One settled post-cutoff year is still under the two-year minimum:
    # a provisional year cannot stand in for a settled one.
    payload["arming"]["years"] = arming_years(
        flat_years(100.0, 2000, 2021) | flat_years(2.0, 2022, 2025),
        provisional_from=2024)
    out = ai_metrics.build_ai_alibi(payload, GENERATED_AT)
    assert lfl_block(out)["post"]["years"] == 1      # 2023 only
    assert lfl_block(out)["verdict"] == "insufficient"

    # Two settled post-cutoff years (2023, 2024) are enough to judge.
    payload["arming"]["years"] = arming_years(
        flat_years(100.0, 2000, 2021) | flat_years(2.0, 2022, 2025),
        provisional_from=2025)
    out = ai_metrics.build_ai_alibi(payload, GENERATED_AT)
    assert lfl_block(out)["verdict"] == "accelerated"


def test_raw_metrics_do_not_count_provisional_cohorts_either():
    # The regression: only the like-for-like rows carried `provisional`,
    # so the three raw metrics judged the GPT-4 era on 2024 + the
    # still-indexing 2025 cohort and published verdicts the stated rule
    # forbids. Ingestion lag belongs to the cohort YEAR, so the raw rows
    # must inherit the flag and the minimum must count settled years only.
    payload = poc_payload(flat_years(100.0, 2000, 2021)
                          | flat_years(2.0, 2022, 2025))
    payload["arming"] = {
        "horizon_days": 90, "ingestion_allowance_days": 365,
        "observed_through": "2026-04-10", "min_n": 30,
        "years": arming_years(flat_years(5.0, 2000, 2025),
                              provisional_from=2025)}
    out = ai_metrics.build_ai_alibi(payload, GENERATED_AT)
    for m in out["clock"]["metrics"]:
        flagged = [r["year"] for r in m["years"] if r["provisional"]]
        assert flagged == [2025], (m["id"], flagged)
    for m in out["banked"]["metrics"]:
        by_era = {b["era"]: b for b in m["eras"]}
        # ChatGPT: 2023 + 2024 settled, 2025 excluded from the mean too.
        assert by_era["chatgpt"]["post"]["years"] == 2, m["id"]
        assert by_era["chatgpt"]["verdict"] != "insufficient", m["id"]
        # GPT-4: 2024 is the only settled post year — withheld.
        assert by_era["gpt4"]["post"]["years"] == 1, m["id"]
        assert by_era["gpt4"]["verdict"] == "insufficient", m["id"]
    gap = gap_block(out)
    assert gap["post"]["n"] == 200               # 2023 + 2024, not 2025
    assert out["headline"]["judged"] == 4        # one ChatGPT cell each


def test_raw_years_the_arming_series_lacks_get_the_same_rule():
    # A cohort too thin for the arming series still has a tracker lag.
    # The raw row is flagged by time_to_poc's own rule — settled once
    # observed_through reaches Dec 31 + the ingestion allowance.
    payload = poc_payload(flat_years(5.0, 2000, 2025))
    payload["arming"] = {
        "horizon_days": 90, "ingestion_allowance_days": 365,
        "observed_through": "2026-04-10", "min_n": 30,
        "years": arming_years(flat_years(5.0, 2000, 2023),
                              provisional_from=2099)}
    out = ai_metrics.build_ai_alibi(payload, GENERATED_AT)
    flags = {r["year"]: r["provisional"]
             for r in out["clock"]["metrics"][0]["years"]}
    # 2024 settles 2025-12-31 (reached); 2025 settles 2026-12-31 (not).
    assert flags[2024] is False and flags[2025] is True
    assert not any(v for y, v in flags.items() if y < 2025)


def test_no_arming_section_leaves_raw_rows_unflagged():
    out = ai_metrics.build_ai_alibi(
        poc_payload(flat_years(5.0, 2000, 2025)), GENERATED_AT)
    assert all(r["provisional"] is False
               for m in out["clock"]["metrics"] for r in m["years"])


def test_attention_propagates_the_market_stale_marker():
    from pipeline import contracts

    fresh = ai_metrics.build_ai_alibi(
        poc_payload(flat_years(5.0, 2000, 2025)), GENERATED_AT,
        market=market_payload())
    assert "stale" not in fresh["attention"]

    carried = dict(market_payload(), stale=True)   # a --skip-market night
    out = ai_metrics.build_ai_alibi(
        poc_payload(flat_years(5.0, 2000, 2025)), GENERATED_AT,
        market=carried)
    assert out["attention"]["stale"] is True
    assert out["attention"]["available"] is True
    assert "stale" not in out                      # the module itself is fresh
    contracts.validate("ai_alibi.json", out)
