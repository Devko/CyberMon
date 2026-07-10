"""epss_report contract: the built output passes; corruptions fail loudly."""
from __future__ import annotations

import copy

import pytest

from pipeline import epss_report_contracts, epss_report_metrics
from pipeline.contracts import ContractViolation, validate
from pipeline.fetch_kev import KevEntry

GENERATED_AT = "2026-07-09T00:00:00Z"


@pytest.fixture()
def report():
    state = {"version": 1, "last_sync": GENERATED_AT, "entries": {
        "CVE-2021-1111|2021-11-03": {"score_date": "2021-11-02",
                                     "epss": 0.35064, "percentile": 0.98923,
                                     "model": "v1", "reason": None},
        "CVE-2023-3333|2023-06-02": {"score_date": "2023-06-01",
                                     "epss": 0.002, "percentile": 0.45,
                                     "model": "v3", "reason": None},
        "CVE-2024-5555|2024-03-30": {"score_date": "2024-03-29",
                                     "epss": None, "percentile": None,
                                     "model": None,
                                     "reason": "no_score_for_date"},
    }}
    kev = [KevEntry("CVE-2021-1111", "2021-11-03", None),
           KevEntry("CVE-2023-3333", "2023-06-02", None),
           KevEntry("CVE-2024-5555", "2024-03-30", None),
           KevEntry("CVE-2025-6666", "2025-01-15", None)]  # pending
    return epss_report_metrics.build_epss_report(
        state, kev, {"CVE-2024-5555": "2024-04-01"}, GENERATED_AT, min_n=1)


def test_built_report_validates(report):
    validate("epss_report.json", report)


def test_percentile_bucket_lists_agree():
    # The validator and the builder each carry the bucket list; they must
    # never drift apart.
    assert epss_report_contracts.PERCENTILE_BUCKETS == \
        epss_report_metrics.PERCENTILE_BUCKETS


def _expect_violation(obj, fragment):
    with pytest.raises(ContractViolation, match=fragment):
        validate("epss_report.json", obj)


def test_catalog_arithmetic_enforced(report):
    bad = copy.deepcopy(report)
    bad["catalog"]["pending_backfill"] += 1
    _expect_violation(bad, "must equal total")


def test_band_counts_must_sum_to_graded(report):
    bad = copy.deepcopy(report)
    bad["grade_by_year"][0]["n_below_1pct"] += 1
    _expect_violation(bad, "band counts")


def test_entries_must_stay_sorted(report):
    bad = copy.deepcopy(report)
    bad["entries"].reverse()
    _expect_violation(bad, "not sorted")


def test_score_date_must_be_day_before(report):
    bad = copy.deepcopy(report)
    bad["entries"][0]["score_date"] = bad["entries"][0]["date_added"]
    _expect_violation(bad, "day before")


def test_epss_five_decimal_exception_is_bounded(report):
    bad = copy.deepcopy(report)
    bad["entries"][0]["epss"] = 0.123456  # 6 decimals: too precise
    _expect_violation(bad, "5 decimal")


def test_null_epss_requires_reason(report):
    bad = copy.deepcopy(report)
    null_entry = next(e for e in bad["entries"] if e["epss"] is None)
    null_entry["reason"] = None
    _expect_violation(bad, "reason")


def test_scored_entry_rejects_reason(report):
    bad = copy.deepcopy(report)
    scored = next(e for e in bad["entries"] if e["epss"] is not None)
    scored["reason"] = "no_score_for_date"
    _expect_violation(bad, "no reason")


def test_distribution_must_cover_graded_total(report):
    bad = copy.deepcopy(report)
    bad["distribution"]["by_model"].pop()
    _expect_violation(bad, "catalog.graded")


def test_distribution_eras_must_follow_release_order(report):
    bad = copy.deepcopy(report)
    bad["distribution"]["by_model"].reverse()
    _expect_violation(bad, "era order")


def test_percentile_buckets_fixed_order(report):
    bad = copy.deepcopy(report)
    bad["percentiles"]["buckets"][0]["bucket"] = "0-30"
    _expect_violation(bad, "bucket labels")


def test_headline_must_match_catalog(report):
    bad = copy.deepcopy(report)
    bad["headline"]["graded"] += 1
    _expect_violation(bad, "catalog.graded")


def test_newest_era_must_be_open_ended(report):
    bad = copy.deepcopy(report)
    bad["model_eras"][-1]["to"] = "2030-01-01"
    _expect_violation(bad, "open-ended")


def test_ungradeable_keys_exact(report):
    bad = copy.deepcopy(report)
    bad["catalog"]["ungradeable"]["mystery"] = 0
    _expect_violation(bad, "exactly the keys")


def test_min_n_enforced_on_charted_years(report):
    bad = copy.deepcopy(report)
    bad["min_n"] = 5  # every charted year has fewer graded than this
    _expect_violation(bad, "below minimum")
