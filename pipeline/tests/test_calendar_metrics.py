"""CVE Calendar metrics + contract: fixture math, edge rules, corruptions."""
from __future__ import annotations

import copy
from datetime import date

import pytest

from pipeline import contracts
from pipeline import calendar_contracts, calendar_metrics  # noqa: E402
from pipeline import metrics
from pipeline.contracts import ContractViolation

from .conftest import GENERATED_AT


@pytest.fixture()
def obj(agg) -> dict:
    return calendar_metrics.build_cve_calendar(agg, GENERATED_AT, min_n=1)


# ----------------------------------------------------------- patch Tuesday

def test_is_patch_tuesday_second_tuesday_only():
    assert calendar_metrics.is_patch_tuesday(date(2024, 2, 13))   # 2nd Tue
    assert not calendar_metrics.is_patch_tuesday(date(2024, 2, 6))   # 1st
    assert not calendar_metrics.is_patch_tuesday(date(2024, 2, 20))  # 3rd
    assert not calendar_metrics.is_patch_tuesday(date(2024, 2, 14))  # Wed
    # boundary days: a Tuesday on day 8 or 14 is the second one
    assert calendar_metrics.is_patch_tuesday(date(2024, 10, 8))
    assert calendar_metrics.is_patch_tuesday(date(2025, 1, 14))
    assert not calendar_metrics.is_patch_tuesday(date(2024, 10, 15))


# ------------------------------------------------------------ hero: id age

def test_id_age_buckets_from_fixture_corpus(obj):
    by_year = {y["year"]: y for y in obj["id_age"]["years"]}
    # CVE-2012-0002 published 2014 -> two-plus; CVE-2014-0001 same-year.
    assert by_year[2014]["n"] == 2
    assert by_year[2014]["same_year"] == 1
    assert by_year[2014]["two_plus"] == 1
    assert by_year[2014]["pct_prior_year"] == 50.0
    # CVE-2024-0005 published 2025 -> one-year; the datePublished-less
    # CVE-2025-0001 dates itself FROM its ID -> same-year by construction.
    assert by_year[2025] == {
        "year": 2025, "n": 2, "same_year": 1, "one_year": 1, "two_plus": 0,
        "pct_same_year": 50.0, "pct_one_year": 50.0, "pct_two_plus": 0.0,
        "pct_prior_year": 50.0}
    # all-same-year years
    assert by_year[2023]["same_year"] == 3 and by_year[2023]["n"] == 3
    assert obj["id_age"]["clamped_negative"] == 0


def test_id_age_headline_skips_partial_year_and_names_baseline(obj):
    # GENERATED_AT is 2026 -> 2025 is the latest complete charted year;
    # 2015 isn't charted, so the baseline falls back to the earliest (2014).
    assert obj["id_age"]["headline"] == {
        "latest_year": 2025, "pct_prior_year_latest": 50.0,
        "baseline_year": 2014, "pct_prior_year_baseline": 50.0}


def test_negative_id_age_clamps_to_zero_and_is_counted():
    agg = metrics.Aggregator()
    agg.add(metrics.CveFacts("CVE-2027-0001", "PUBLISHED", 2026, "a",
                             date_published="2026-12-30"))
    out = calendar_metrics.build_cve_calendar(agg, GENERATED_AT, min_n=1)
    row = out["id_age"]["years"][0]
    assert row == {"year": 2026, "n": 1, "same_year": 1, "one_year": 0,
                   "two_plus": 0, "pct_same_year": 100.0,
                   "pct_one_year": 0.0, "pct_two_plus": 0.0,
                   "pct_prior_year": 0.0}
    assert out["id_age"]["clamped_negative"] == 1


def test_rejected_records_never_join_the_calendar(agg):
    # The fixture corpus has one REJECTED 2024 record; only 3 published.
    out = calendar_metrics.build_cve_calendar(agg, GENERATED_AT, min_n=1)
    by_year = {y["year"]: y for y in out["id_age"]["years"]}
    assert by_year[2024]["n"] == 3


# ------------------------------------------------- weekday + patch Tuesday

def test_weekday_counts_are_monday_first_utc(obj):
    by_year = {y["year"]: y for y in obj["weekday"]["years"]}
    # 2024: Tue 2024-02-13, Mon 2024-04-01, Thu 2024-07-04.
    assert by_year[2024]["counts"] == [1, 1, 0, 1, 0, 0, 0]
    # 2023: Sun 2023-01-15, Mon 2023-03-20, Sat 2023-08-05.
    assert by_year[2023]["counts"] == [1, 0, 0, 0, 0, 1, 1]
    assert by_year[2023]["pct"][0] == 33.3


def test_undated_record_joins_id_age_but_not_the_day_tally(obj):
    # CVE-2025-0001 has no datePublished: id_age 2025 n=2, weekday n=1.
    wk = {y["year"]: y for y in obj["weekday"]["years"]}
    assert wk[2025]["n"] == 1
    assert wk[2025]["counts"] == [1, 0, 0, 0, 0, 0, 0]  # 2025-05-05, a Monday


def test_patch_tuesday_share_and_top_day(obj):
    pt = {y["year"]: y for y in obj["patch_tuesday"]["years"]}
    assert pt[2024]["on_pt"] == 1 and pt[2024]["pct"] == 33.3
    assert pt[2023]["on_pt"] == 0 and pt[2023]["pct"] == 0.0
    # single-count days tie; the earliest date wins deterministically
    assert pt[2023]["top_day"] == {"date": "2023-01-15", "n": 1}
    assert pt[2024]["top_day"] == {"date": "2024-02-13", "n": 1}
    assert obj["patch_tuesday"]["calendar_pct"] == 3.3
    assert obj["patch_tuesday"]["headline"] == {"latest_year": 2025,
                                                "pct_latest": 0.0}


def test_min_n_filters_each_section_on_its_own_denominator(agg):
    out = calendar_metrics.build_cve_calendar(agg, GENERATED_AT, min_n=2)
    # id_age keeps 2014/2023/2024/2025 (n >= 2 everywhere) ...
    assert [y["year"] for y in out["id_age"]["years"]] == [2014, 2023, 2024,
                                                           2025]
    # ... but 2025 has only ONE dated record, so the day-derived sections
    # drop it and their comparison/headline move to 2024.
    assert [y["year"] for y in out["weekday"]["years"]] == [2014, 2023, 2024]
    assert out["weekday"]["comparison"] == {"latest_year": 2024,
                                            "baseline_year": 2014}
    assert out["patch_tuesday"]["headline"]["latest_year"] == 2024


def test_empty_aggregator_yields_null_headlines():
    out = calendar_metrics.build_cve_calendar(metrics.Aggregator(),
                                              GENERATED_AT)
    assert out["id_age"] == {"years": [], "clamped_negative": 0,
                             "headline": None}
    assert out["weekday"] == {"years": [], "comparison": None}
    assert out["patch_tuesday"]["years"] == []
    assert out["patch_tuesday"]["headline"] is None
    contracts.validate("cve_calendar.json", out)


# ----------------------------------------------------------------- contract

def test_valid_output_passes_both_dispatchers(obj):
    contracts.validate("cve_calendar.json", obj)
    calendar_contracts.VALIDATORS["cve_calendar.json"](obj)


def _corrupt(obj):
    return copy.deepcopy(obj)


def test_contract_rejects_buckets_not_summing_to_n(obj):
    bad = _corrupt(obj)
    bad["id_age"]["years"][0]["same_year"] += 1
    with pytest.raises(ContractViolation, match="sum"):
        contracts.validate("cve_calendar.json", bad)


def test_contract_rejects_wrong_weekday_arity(obj):
    bad = _corrupt(obj)
    bad["weekday"]["years"][0]["counts"] = [1, 2, 3]
    with pytest.raises(ContractViolation, match="Monday-first"):
        contracts.validate("cve_calendar.json", bad)


def test_contract_rejects_on_pt_above_n(obj):
    bad = _corrupt(obj)
    bad["patch_tuesday"]["years"][0]["on_pt"] = \
        bad["patch_tuesday"]["years"][0]["n"] + 1
    with pytest.raises(ContractViolation, match="on_pt"):
        contracts.validate("cve_calendar.json", bad)


def test_contract_rejects_headline_year_not_charted(obj):
    bad = _corrupt(obj)
    bad["id_age"]["headline"]["latest_year"] = 1999
    with pytest.raises(ContractViolation, match="charted"):
        contracts.validate("cve_calendar.json", bad)


def test_contract_rejects_wrong_calendar_pct(obj):
    bad = _corrupt(obj)
    bad["patch_tuesday"]["calendar_pct"] = 3.4
    with pytest.raises(ContractViolation, match="calendar_pct"):
        contracts.validate("cve_calendar.json", bad)


def test_contract_rejects_day_sections_charting_different_years(obj):
    bad = _corrupt(obj)
    bad["patch_tuesday"]["years"].pop()
    with pytest.raises(ContractViolation, match="same day tally"):
        contracts.validate("cve_calendar.json", bad)
