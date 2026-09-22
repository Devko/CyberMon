"""Advisory Gap / Registry Malware builders and their contracts, on the
synthetic OSV fixtures (pipeline/tests/fixtures/osv) and hand-made
summaries."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from pipeline import contracts, osv_metrics
from pipeline.fetch_osv import EcosystemSummary, load_fixture_dir

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "osv"
GEN = "2026-09-22T05:00:00Z"


@pytest.fixture(scope="module")
def summaries():
    return load_fixture_dir(FIXTURES)


@pytest.fixture(scope="module")
def gap(summaries):
    return osv_metrics.build_advisory_gap(summaries, GEN, min_n=2)


@pytest.fixture(scope="module")
def mal(summaries):
    return osv_metrics.build_registry_malware(summaries, GEN)


# ---- module 25 ------------------------------------------------------------------

def test_gap_dedupes_multi_ecosystem_advisories_and_drops_withdrawn(gap):
    cat = gap["catalog"]
    # 10 GHSA files, one advisory in two zips, one withdrawn -> 8 live.
    assert cat["advisories"] == 8
    assert cat["withdrawn_excluded"] == 1
    assert cat["multi_ecosystem"] == 1
    assert (cat["with_cve"], cat["without_cve"]) == (5, 3)
    assert cat["without_cve_pct"] == 37.5
    assert cat["not_reviewed"] == 0


def test_gap_years_are_consecutive_with_the_partial_year_flagged(gap):
    rows = gap["years"]
    assert [r["year"] for r in rows] == [2023, 2024, 2025, 2026]
    assert [r["partial"] for r in rows] == [False, False, False, True]
    by = {r["year"]: r for r in rows}
    assert (by[2024]["total"], by[2024]["without_cve"]) == (3, 2)
    assert by[2025]["without_cve"] == 1  # the npm+PyPI advisory, once


def test_gap_multi_ecosystem_advisory_counts_in_each_ecosystem(gap):
    ecos = {e["ecosystem"]: e for e in gap["ecosystems"]}
    assert ecos["npm"]["total"] == 4 and ecos["PyPI"]["total"] == 3
    assert ecos["npm"]["without_cve"] == 2 and ecos["PyPI"]["without_cve"] == 1
    assert [e["ecosystem"] for e in gap["ecosystems"]] == \
        ["npm", "PyPI", "crates.io"]


def test_gap_share_is_null_below_min_n(summaries):
    obj = osv_metrics.build_advisory_gap(summaries, GEN, min_n=4)
    ecos = {e["ecosystem"]: e for e in obj["ecosystems"]}
    assert ecos["npm"]["without_cve_pct"] == 50.0
    assert ecos["crates.io"]["without_cve_pct"] is None
    contracts.validate("advisory_gap.json", obj)


def test_gap_young_cohort_is_relative_to_the_edition_date(summaries):
    # From 2025-05-01 the 90-day window reaches back to 2025-01-31: the
    # npm+PyPI no-CVE advisory of 2025-02-02 is young; the 2024 ones are
    # settled.
    obj = osv_metrics.build_advisory_gap(summaries, "2025-05-01T00:00:00Z",
                                         min_n=1)
    assert obj["young_since"] == "2025-01-31"
    assert obj["catalog"]["without_cve_young"] == 1


def test_gap_severity_and_cve_lag(gap):
    sev = {r["level"]: r for r in gap["severity"]}
    assert sev["CRITICAL"]["with_cve"] == 1
    assert sev["CRITICAL"]["without_cve"] == 1
    assert sev["UNRATED"] == {"level": "UNRATED", "with_cve": 0,
                              "without_cve": 0, "with_cve_pct": 0.0,
                              "without_cve_pct": 0.0}
    # CVE-2025-0003 reached NVD 172 days after its advisory; the rest
    # within a day (or before).
    assert gap["cve_lag"] == {"n": 5, "later_30d": 1, "later_90d": 1,
                              "later_365d": 0}


def test_gap_validates_and_contract_catches_a_broken_partition(gap):
    contracts.validate("advisory_gap.json", gap)
    broken = copy.deepcopy(gap)
    broken["years"][0]["with_cve"] += 1
    broken["years"][0]["total"] += 1
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("advisory_gap.json", broken)
    broken = copy.deepcopy(gap)
    broken["years"][-1]["partial"] = False
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("advisory_gap.json", broken)


def test_gap_carried_forward_across_new_year_still_validates(gap):
    carried = dict(copy.deepcopy(gap), generated_at="2027-01-02T05:00:00Z",
                   stale=True)
    contracts.validate("advisory_gap.json", carried)


def test_empty_editions_are_legal():
    empty = {"npm": EcosystemSummary("npm")}
    contracts.validate("advisory_gap.json",
                       osv_metrics.build_advisory_gap(empty, GEN))
    contracts.validate("registry_malware.json",
                       osv_metrics.build_registry_malware(empty, GEN))


# ---- module 26 ------------------------------------------------------------------

def test_mal_counts_reports_per_ecosystem_and_withdrawn(mal):
    cat = mal["catalog"]
    assert cat["reports"] == 8
    assert cat["withdrawn"] == 1
    assert [(e["ecosystem"], e["reports"]) for e in mal["ecosystems"]] == \
        [("npm", 5), ("PyPI", 2), ("VSCode", 1)]
    assert cat["this_year"] == 1


def test_mal_months_run_to_the_edition_month_gap_filled(mal):
    months = mal["months"]
    assert months[0]["month"] == "2023-02"
    assert months[-1]["month"] == "2026-09" and months[-1]["partial"]
    assert months[-1]["total"] == 0
    assert len(months) == 44
    nov = next(m for m in months if m["month"] == "2025-11")
    assert nov == {"month": "2025-11", "total": 3, "withdrawn": 0,
                   "by_ecosystem": {"npm": 3}, "partial": False}


def test_mal_bursts_name_the_top_source_and_ecosystem(mal):
    top = mal["bursts"][0]
    assert top == {"month": "2025-11", "reports": 3, "share_pct": 37.5,
                   "top_source": "amazon-inspector", "top_source_reports": 2,
                   "top_ecosystem": "npm"}
    assert mal["catalog"]["peak_month"] == "2025-11"
    sources = {s["source"]: s["reports"] for s in mal["sources"]}
    assert sources["unattributed"] == 1 and sources["amazon-inspector"] == 2


def test_mal_median_uses_the_complete_months_only(mal):
    cat = mal["catalog"]
    assert cat["median_window"] == ["2024-09", "2026-08"]
    assert cat["median_month"] == 0


def test_mal_validates_and_contract_catches_drift(mal):
    contracts.validate("registry_malware.json", mal)
    broken = copy.deepcopy(mal)
    broken["months"][0]["by_ecosystem"]["PyPI"] += 1
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("registry_malware.json", broken)
    broken = copy.deepcopy(mal)
    del broken["months"][5]
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("registry_malware.json", broken)


def test_meta_osv_block_contract():
    base = {"generated_at": GEN, "sample": False, "sources": {
        "cvelist": {"release": "r", "cve_count": 1},
        "epss": {"model_version": "v4", "score_date": "2026-09-21",
                 "row_count": 1},
        "kev": {"catalog_version": "x", "count": 1},
        "osv": {"fetched_at": GEN, "ghsa_advisories": 7, "mal_reports": 8,
                "ecosystems": 4, "downloaded": 1, "not_modified": 3}}}
    contracts.validate("meta.json", base)
    bad = copy.deepcopy(base)
    bad["sources"]["osv"]["downloaded"] = 2
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("meta.json", bad)
