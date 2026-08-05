"""ai_contracts tests: the valid shape passes through the core dispatch;
each deviation that would break the page — or, worse, publish a verdict
nothing backs — fails loudly.

The builder is the normal producer of this object, so most cases start
from a real build and corrupt one field. That is deliberate: a contract
test written against a hand-typed dict drifts away from the builder and
ends up guarding a shape nobody emits.
"""
from __future__ import annotations

import copy

import pytest

# contracts must load before ai_contracts: the coordinator registers
# module contracts from its own module bottom, so importing the contract
# file first would hit the registration mid-initialization.
from pipeline import contracts
from pipeline import ai_contracts  # noqa: E402  (see above)
from pipeline import ai_metrics
from pipeline.contracts import ContractViolation

GENERATED_AT = "2026-07-09T00:00:00Z"


def poc_payload(gaps: dict[int, float]) -> dict:
    return {"hero": {"years": [
        {"year": y, "n": 100, "median_days": v, "p25_days": v - 1,
         "p75_days": v + 1, "pct_negative": 40.0, "pct_within_week": 50.0}
        for y, v in sorted(gaps.items())]}}


def market_payload() -> dict:
    return {"window_months": 60, "terms": [
        {"id": "ai_security", "label": "AI Security", "series": {
            "gdelt": [{"month": "2024-01", "n": 5, "index": 20.0},
                      {"month": "2024-02", "n": 9, "index": 90.0}]}}]}


def valid_obj() -> dict:
    """A real build with a movement history — flat enough to be honest,
    varied enough that every section has something in it."""
    gaps = {**{y: 200.0 for y in range(2000, 2005)},
            **{y: 5.0 for y in range(2005, 2026)}}
    return ai_metrics.build_ai_alibi(poc_payload(gaps), GENERATED_AT,
                                     market=market_payload())


def test_valid_object_passes():
    contracts.validate("ai_alibi.json", valid_obj())


def test_degraded_market_object_passes():
    gaps = {y: 5.0 for y in range(2000, 2026)}
    obj = ai_metrics.build_ai_alibi(poc_payload(gaps), GENERATED_AT,
                                    market=None)
    contracts.validate("ai_alibi.json", obj)


# ---- eras -----------------------------------------------------------------


def test_straddling_cut_year_is_rejected():
    # The no-straddle rule is the reason the pre/post split is defensible;
    # the contract re-derives it rather than trusting the payload.
    obj = valid_obj()
    obj["eras"][0]["cut_year"] += 1
    with pytest.raises(ContractViolation, match="last year ending before"):
        contracts.validate("ai_alibi.json", obj)


def test_two_default_eras_rejected():
    obj = valid_obj()
    for era in obj["eras"]:
        era["default"] = True
    with pytest.raises(ContractViolation, match="exactly one era"):
        contracts.validate("ai_alibi.json", obj)


def test_missing_era_rejected():
    obj = valid_obj()
    obj["eras"].pop()
    with pytest.raises(ContractViolation, match="expected"):
        contracts.validate("ai_alibi.json", obj)


# ---- milestones -----------------------------------------------------------


def test_unsourced_milestone_rejected():
    obj = valid_obj()
    obj["milestones"][0]["source"] = "internal note"
    with pytest.raises(ContractViolation, match="https source URL"):
        contracts.validate("ai_alibi.json", obj)


def test_unknown_milestone_kind_rejected():
    obj = valid_obj()
    obj["milestones"][0]["kind"] = "vibes"
    with pytest.raises(ContractViolation, match="unknown kind"):
        contracts.validate("ai_alibi.json", obj)


def test_moved_plot_date_rejected():
    # plot_date is derived; a hand-edit that shifts a marker off its own
    # date must not survive to the chart.
    obj = valid_obj()
    obj["milestones"][0]["plot_date"] = "2019-01-01"
    with pytest.raises(ContractViolation, match="must plot at"):
        contracts.validate("ai_alibi.json", obj)


def test_month_precision_must_plot_mid_month():
    obj = valid_obj()
    row = next(m for m in obj["milestones"] if m["precision"] == "month")
    row["plot_date"] = f"{row['date']}-01"
    with pytest.raises(ContractViolation, match="must plot at"):
        contracts.validate("ai_alibi.json", obj)


def test_unsorted_timeline_rejected():
    obj = valid_obj()
    obj["milestones"].reverse()
    with pytest.raises(ContractViolation, match="sorted|ascending|order"):
        contracts.validate("ai_alibi.json", obj)


def test_empty_timeline_rejected():
    obj = valid_obj()
    obj["milestones"] = []
    with pytest.raises(ContractViolation, match="may not be empty"):
        contracts.validate("ai_alibi.json", obj)


# ---- clock ----------------------------------------------------------------


def test_metrics_with_different_spans_rejected():
    # Three metrics from one cohort must share one span; a mismatch means
    # the builder silently dropped rows from one of them.
    obj = valid_obj()
    obj["clock"]["metrics"][1]["years"].pop()
    with pytest.raises(ContractViolation, match="must share one span"):
        contracts.validate("ai_alibi.json", obj)


def test_percent_metric_out_of_range_rejected():
    obj = valid_obj()
    pct = next(m for m in obj["clock"]["metrics"] if m["unit"] == "percent")
    pct["years"][0]["value"] = 140.0
    with pytest.raises(ContractViolation):
        contracts.validate("ai_alibi.json", obj)


def test_negative_days_metric_allowed():
    # Exploit code predating the CVE record is the finding, not an error.
    obj = valid_obj()
    days = next(m for m in obj["clock"]["metrics"] if m["unit"] == "days")
    days["years"][0]["value"] = -900.0
    contracts.validate("ai_alibi.json", obj)


# ---- verdicts -------------------------------------------------------------


def test_verdict_on_a_thin_era_rejected():
    # The MIN_POST_YEARS guard exists so one anomalous year can't produce
    # a headline; the contract refuses to publish a verdict that ignores it.
    obj = valid_obj()
    block = obj["banked"]["metrics"][0]["eras"][-1]
    assert block["verdict"] == "insufficient", "fixture assumption"
    block["verdict"] = "accelerated"
    block["era_shift"] = 0.0
    with pytest.raises(ContractViolation, match="post-cutoff year"):
        contracts.validate("ai_alibi.json", obj)


def test_unjudged_cell_carrying_a_share_rejected():
    obj = valid_obj()
    block = obj["banked"]["metrics"][0]["eras"][-1]
    block["pct_banked"] = 90.0
    with pytest.raises(ContractViolation, match="unjudged cell"):
        contracts.validate("ai_alibi.json", obj)


def test_era_shift_must_equal_post_minus_pre():
    obj = valid_obj()
    block = obj["banked"]["metrics"][0]["eras"][0]
    block["era_shift"] = block["era_shift"] + 25.0
    with pytest.raises(ContractViolation, match="must equal post - pre"):
        contracts.validate("ai_alibi.json", obj)


def test_accelerated_verdict_with_negative_share_rejected():
    # The sign IS the finding — a chart reads it without knowing which
    # direction is bad for which metric, so it may never contradict the
    # verdict that names that direction in words.
    obj = valid_obj()
    block = obj["banked"]["metrics"][0]["eras"][0]
    block["verdict"] = "accelerated"
    block["shift_share_pct"] = -20.0
    with pytest.raises(ContractViolation, match="toward faster"):
        contracts.validate("ai_alibi.json", obj)


def test_decelerated_verdict_with_positive_share_rejected():
    obj = valid_obj()
    block = obj["banked"]["metrics"][0]["eras"][0]
    block["verdict"] = "decelerated"
    block["shift_share_pct"] = 20.0
    with pytest.raises(ContractViolation, match="toward slower"):
        contracts.validate("ai_alibi.json", obj)


def test_metric_judged_against_a_subset_of_eras_rejected():
    obj = valid_obj()
    obj["banked"]["metrics"][0]["eras"].pop()
    with pytest.raises(ContractViolation, match="against all eras"):
        contracts.validate("ai_alibi.json", obj)


def test_banked_metric_without_a_clock_series_rejected():
    obj = valid_obj()
    obj["banked"]["metrics"][0]["id"] = "invented_metric"
    with pytest.raises(ContractViolation, match="no clock series"):
        contracts.validate("ai_alibi.json", obj)


# ---- attention ------------------------------------------------------------


def test_unavailable_attention_carrying_terms_rejected():
    obj = valid_obj()
    obj["attention"]["available"] = False
    with pytest.raises(ContractViolation, match="unavailable attention"):
        contracts.validate("ai_alibi.json", obj)


def test_attention_month_with_no_backing_lane_rejected():
    obj = valid_obj()
    obj["attention"]["terms"][0]["months"][0]["sources"] = 0
    with pytest.raises(ContractViolation):
        contracts.validate("ai_alibi.json", obj)


def test_inverted_clock_band_rejected():
    obj = valid_obj()
    head = obj["attention"]["headline"]
    head["clock_min"], head["clock_max"] = head["clock_max"] + 1.0, \
        head["clock_min"]
    with pytest.raises(ContractViolation, match="clock_min exceeds"):
        contracts.validate("ai_alibi.json", obj)


# ---- headline -------------------------------------------------------------


def test_scoreboard_that_does_not_add_up_rejected():
    obj = valid_obj()
    obj["headline"]["accelerated"] += 1
    with pytest.raises(ContractViolation, match="must equal judged"):
        contracts.validate("ai_alibi.json", obj)


def test_headline_milestone_count_must_match_the_timeline():
    obj = valid_obj()
    obj["headline"]["milestones"] += 1
    with pytest.raises(ContractViolation, match="timeline length"):
        contracts.validate("ai_alibi.json", obj)


def test_judged_cannot_exceed_cells():
    obj = valid_obj()
    obj["headline"]["judged"] = obj["headline"]["cells"] + 1
    with pytest.raises(ContractViolation, match="cannot exceed"):
        contracts.validate("ai_alibi.json", obj)


def test_unchanged_valid_object_is_not_mutated_by_validation():
    obj = valid_obj()
    before = copy.deepcopy(obj)
    contracts.validate("ai_alibi.json", obj)
    assert obj == before
