"""CVSS 4.0 adoption (cvss_v4.json): coverage classes from the CNA
container, the monthly window, adopters, the v4-vs-v3 comparison, the
headline, and the contract."""
from __future__ import annotations

import copy

import pytest

from pipeline import contracts, metrics
from pipeline.cvss_v4_metrics import _delta_bins, build_cvss_v4

from .conftest import GENERATED_AT  # 2026-07-09


def _facts(cve_id, cna, date, cna_scores=None, adp_scores=None):
    return metrics.CveFacts(cve_id, "PUBLISHED", int(date[:4]), cna,
                            cna_scores=dict(cna_scores or {}),
                            adp_scores=dict(adp_scores or {}),
                            date_published=date)


def _agg(facts_list) -> metrics.Aggregator:
    agg = metrics.Aggregator()
    for f in facts_list:
        agg.add(f)
    return agg


def _corpus():
    return _agg([
        _facts("CVE-2023-0001", "a", "2023-06-01", {"v3": 7.5}),     # pre-window
        _facts("CVE-2023-0002", "a", "2023-11-20", {"v4": 8.7, "v3": 9.8}),
        _facts("CVE-2024-0001", "a", "2024-01-05", {"v4": 6.9}),
        _facts("CVE-2024-0002", "b", "2024-01-09", {"v3": 5.0}),
        _facts("CVE-2024-0003", "b", "2024-03-09", {"v2": 5.0}),     # v2 only
        _facts("CVE-2026-0001", "c", "2026-02-01", {},
               adp_scores={"v3": 9.8}),                               # ADP only
        _facts("CVE-2026-0002", "a", "2026-02-02", {"v4": 9.3, "v3": 9.1}),
    ])


def test_coverage_classes_partition_published_cna_container_only():
    out = build_cvss_v4(_corpus(), GENERATED_AT, adopters_min_v4=1,
                        dual_min_n=1)
    years = {r["year"]: r for r in out["years"]}
    assert years[2023] == {"year": 2023, "published": 2, "v4_only": 0,
                           "both": 1, "v3_only": 1, "neither": 0,
                           "neither_adp": 0, "v4_cnas": 1}
    # the v2-only record is "neither"; no ADP score on it
    assert years[2024]["neither"] == 1 and years[2024]["neither_adp"] == 0
    assert years[2024]["v4_only"] == 1 and years[2024]["v3_only"] == 1
    # ADP's v3.1 does NOT make a record v3-covered here — it is flagged
    assert years[2026]["neither"] == 1 and years[2026]["neither_adp"] == 1
    assert [r["year"] for r in out["years"]] == [2023, 2024, 2025, 2026]
    assert years[2025]["published"] == 0
    contracts.validate("cvss_v4.json", out)


def test_months_start_at_release_and_gap_fill():
    out = build_cvss_v4(_corpus(), GENERATED_AT)
    months = out["months"]
    assert months[0]["month"] == "2023-11"
    assert months[-1]["month"] == "2026-02"
    assert len(months) == 28  # 2023-11 .. 2026-02 inclusive
    by = {m["month"]: m for m in months}
    assert by["2023-11"]["both"] == 1 and by["2023-11"]["published"] == 1
    assert by["2024-01"] == {"month": "2024-01", "published": 2,
                             "v4_only": 1, "both": 0, "v3_only": 1,
                             "neither": 0}
    assert by["2025-06"]["published"] == 0


def test_adopters_window_floor_and_shares():
    out = build_cvss_v4(_corpus(), GENERATED_AT, adopters_min_v4=1)
    ad = out["adopters"]
    # window since 2023-11: a has 3 records, all v4 (one v4-only)
    assert ad["cnas"][0] == {"cna": "a", "published": 3, "v4": 3,
                             "v4_only": 1, "v4_share_pct": 100.0,
                             "v4_only_share_pct": 33.3}
    assert ad["adopter_count"] == 1
    assert ad["window_published"] == 6 and ad["window_v4"] == 3
    assert build_cvss_v4(_corpus(), GENERATED_AT,
                         adopters_min_v4=4)["adopters"]["cnas"] == []


def test_compare_delta_and_band_agreement():
    out = build_cvss_v4(_corpus(), GENERATED_AT, dual_min_n=1)
    cmp_ = out["compare"]
    # 8.7 - 9.8 = -1.1 (critical -> high: v4 lower); 9.3 - 9.1 = +0.2 (same)
    assert cmp_["n"] == 2
    assert (cmp_["same_band"], cmp_["v4_higher"], cmp_["v4_lower"]) == \
        (1, 0, 1)
    assert cmp_["median_delta"] == -0.5  # median of -1.1 and +0.2 (-0.45)
    bins = {b["center"]: b["n"] for b in cmp_["bins"]}
    assert bins[-1.0] == 1 and bins[0.0] == 1
    assert cmp_["cnas"] == [{"cna": "a", "n": 2, "median_delta": -0.5,
                             "same_band_pct": 50.0, "v4_higher_pct": 0.0,
                             "v4_lower_pct": 50.0}]


def test_delta_bins_are_symmetric_with_open_ends():
    from collections import Counter
    bins = _delta_bins(Counter({-2: 1, 2: 1, 3: 1, -3: 1, 28: 1, -45: 1,
                                27: 1}))
    by = {b["center"]: b for b in bins}
    assert by[0.0]["n"] == 2          # -0.2 and +0.2
    assert by[0.5]["n"] == 1 and by[-0.5]["n"] == 1
    assert by[2.5]["n"] == 1          # +2.7
    assert by[3.0]["n"] == 1 and by[3.0]["hi"] == 10.0 and by[3.0]["lo"] == 2.8
    assert by[-3.0]["n"] == 1 and by[-3.0]["lo"] == -10.0
    assert [b["center"] for b in bins] == [x / 2 for x in range(-6, 7)]


def test_headline_current_and_latest_complete_year():
    out = build_cvss_v4(_corpus(), GENERATED_AT)
    h = out["headline"]
    assert h["current_year"] == 2026 and h["current_month"] == "2026-07"
    assert h["v4_current"] == 1 and h["published_current"] == 2
    assert h["v4_share_current_pct"] == 50.0
    # 2025 has no records at all, so the latest complete year is 2024
    assert h["latest_year"] == 2024 and h["v4_share_latest_pct"] == 33.3


def test_empty_aggregator_is_a_valid_edition():
    out = build_cvss_v4(metrics.Aggregator(), GENERATED_AT)
    assert out["months"] == [] and out["compare"]["n"] == 0
    contracts.validate("cvss_v4.json", out)


def test_contract_rejects_inconsistent_payloads():
    out = build_cvss_v4(_corpus(), GENERATED_AT, adopters_min_v4=1,
                        dual_min_n=1)
    bad = copy.deepcopy(out)
    bad["years"][0]["neither"] += 1  # classes no longer partition published
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("cvss_v4.json", bad)
    bad = copy.deepcopy(out)
    bad["container"] = "any"
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("cvss_v4.json", bad)
    bad = copy.deepcopy(out)
    bad["compare"]["bins"][0]["n"] += 1  # bins must sum to n
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("cvss_v4.json", bad)
    bad = copy.deepcopy(out)
    bad["months"] = bad["months"][1:]  # must start at since_month
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("cvss_v4.json", bad)
