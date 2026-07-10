"""KEV latency math: buckets, cohorts, negative latency, min_n, the join.
Plus the ransomware-share builder (no CVE join involved)."""
from __future__ import annotations

from pipeline import metrics
from pipeline.fetch_kev import KevEntry
from pipeline.kev_metrics import (BUCKETS, LAUNCH_CUTOFF, build_kev_latency,
                                  build_kev_ransomware, latency_bucket)

from .conftest import GENERATED_AT


def _agg(published_dates: dict[str, str]) -> metrics.Aggregator:
    """An Aggregator carrying a prebuilt KEV publish-date join."""
    agg = metrics.Aggregator(kev_ids=published_dates)
    agg.kev_published_dates = dict(published_dates)
    return agg


def _entry(cve_id: str, date_added: str, due_date: str | None = None,
           ransomware_use: str | None = None):
    return KevEntry(cve_id=cve_id, date_added=date_added, due_date=due_date,
                    ransomware_use=ransomware_use)


# ------------------------------------------------------------- bucket edges

def test_latency_bucket_edges_lower_edge_inclusive():
    assert latency_bucket(-1) == "before_publish"
    assert latency_bucket(-612) == "before_publish"
    assert latency_bucket(0) == "0-7d"
    assert latency_bucket(7) == "0-7d"
    assert latency_bucket(8) == "8-30d"
    assert latency_bucket(30) == "8-30d"
    assert latency_bucket(31) == "31-90d"
    assert latency_bucket(90) == "31-90d"
    assert latency_bucket(91) == "91-365d"
    assert latency_bucket(365) == "91-365d"
    assert latency_bucket(366) == "1-3y"
    assert latency_bucket(1095) == "1-3y"
    assert latency_bucket(1096) == "3y+"


# ------------------------------------------------------- the Aggregator join

def test_aggregator_records_publish_dates_only_for_kev_ids():
    agg = metrics.Aggregator(kev_ids=["CVE-2024-0001"])
    agg.add(metrics.CveFacts("CVE-2024-0001", "PUBLISHED", 2024, "acme",
                             date_published="2024-03-01"))
    agg.add(metrics.CveFacts("CVE-2024-0009", "PUBLISHED", 2024, "acme",
                             date_published="2024-03-02"))  # not KEV-listed
    assert agg.kev_published_dates == {"CVE-2024-0001": "2024-03-01"}


def test_aggregator_joins_kev_dates_even_for_rejected_records():
    # The KEV listing is real even if the record was later rejected.
    agg = metrics.Aggregator(kev_ids=["CVE-2024-0001"])
    agg.add(metrics.CveFacts("CVE-2024-0001", "REJECTED", 2024, "acme",
                             date_published="2024-03-01"))
    assert agg.kev_published_dates == {"CVE-2024-0001": "2024-03-01"}
    assert agg.rejected_by_year[2024] == 1


def test_extract_facts_slices_date_published_to_day_precision():
    facts = metrics.extract_facts({
        "cveMetadata": {"cveId": "CVE-2024-0001", "state": "PUBLISHED",
                        "datePublished": "2024-02-14T09:00:00.000Z"}})
    assert facts.date_published == "2024-02-14"
    facts = metrics.extract_facts(
        {"cveMetadata": {"cveId": "CVE-2024-0001", "state": "PUBLISHED"}})
    assert facts.date_published is None


# ------------------------------------------------------- fixture-based build

def test_fixture_build_matched_and_cohorts(agg, kev):
    obj = build_kev_latency(agg, kev.entries, GENERATED_AT, min_n=1)
    # the 4 guards-module fixture entries (Fortinet/Cisco) have no CVE
    # records in the fixture corpus on purpose: they count as unmatched
    # and stay out of every latency stat below
    assert obj["matched"] == {"total_kev": 7, "matched_cve": 3,
                              "unmatched_cve": 4}
    # CVE-2023-0003 (dateAdded 2021-12-01) is launch backfill: reported
    # separately, absent from every trend stat.
    assert obj["launch_backfill"] == {"date_added_before": LAUNCH_CUTOFF,
                                      "n": 1, "median_days": -612.0}
    assert [(r["year"], r["n"], r["median_days"])
            for r in obj["latency_by_year"]] == [(2023, 1, 30.0),
                                                 (2024, 1, -2.0)]
    assert sum(b["n"] for b in obj["latency_buckets"]) == 2  # trend only


def test_fixture_negative_latency_kept_not_floored(agg, kev):
    obj = build_kev_latency(agg, kev.entries, GENERATED_AT, min_n=1)
    year_2024 = obj["latency_by_year"][-1]
    assert year_2024["median_days"] == -2.0  # never floored to 0
    assert year_2024["pct_negative"] == 100.0
    buckets = {b["bucket"]: b for b in obj["latency_buckets"]}
    assert buckets["before_publish"]["n"] == 1
    assert buckets["0-7d"]["n"] == 0  # not counted as a same-day listing


def test_fixture_all_seven_buckets_present_in_order(agg, kev):
    obj = build_kev_latency(agg, kev.entries, GENERATED_AT, min_n=1)
    assert [b["bucket"] for b in obj["latency_buckets"]] == BUCKETS
    assert BUCKETS == ["before_publish", "0-7d", "8-30d", "31-90d",
                       "91-365d", "1-3y", "3y+"]


def test_fixture_remediation_span_includes_launch_cohort(agg, kev):
    obj = build_kev_latency(agg, kev.entries, GENERATED_AT, min_n=1)
    # deadline policy is real regardless of CVE age: 2021 launch included
    assert [(r["year"], r["n"], r["median_days"])
            for r in obj["remediation_span_by_year"]] == \
        [(2021, 1, 14.0), (2023, 1, 21.0), (2024, 1, 21.0)]


def test_fixture_headline_prefers_last_complete_year(agg, kev):
    obj = build_kev_latency(agg, kev.entries, GENERATED_AT, min_n=1)
    # GENERATED_AT is 2026: 2024 is the last complete year; 2021 (latest-3)
    # never plotted, so the baseline falls back to the earliest survivor.
    assert obj["headline"] == {"latest_year": 2024,
                               "median_days_latest": -2.0,
                               "pct_over_365d_latest": 0.0,
                               "baseline_year": 2023,
                               "median_days_baseline": 30.0}


def test_fixture_min_n_drops_thin_years_but_not_buckets(agg, kev):
    obj = build_kev_latency(agg, kev.entries, GENERATED_AT, min_n=2)
    assert obj["latency_by_year"] == []       # every year has n=1
    assert obj["remediation_span_by_year"] == []
    assert sum(b["n"] for b in obj["latency_buckets"]) == 2  # unfiltered


# ---------------------------------------------------------- synthetic cases

def test_unmatched_kev_ids_counted_and_excluded_from_stats():
    agg = _agg({"CVE-2024-0001": "2024-01-01"})
    entries = [_entry("CVE-2024-0001", "2024-01-11", "2024-02-01"),
               _entry("CVE-1999-9999", "2024-01-11", "2024-02-01")]  # no join
    obj = build_kev_latency(agg, entries, GENERATED_AT, min_n=1)
    assert obj["matched"] == {"total_kev": 2, "matched_cve": 1,
                              "unmatched_cve": 1}
    assert obj["latency_by_year"] == [
        {"year": 2024, "n": 1, "median_days": 10.0, "p25_days": 10.0,
         "p75_days": 10.0, "pct_negative": 0.0, "pct_over_365d": 0.0}]
    # excluded from ALL stats, remediation spans included
    assert [r["n"] for r in obj["remediation_span_by_year"]] == [1]


def test_launch_cutoff_boundary_day_is_trend_not_backfill():
    agg = _agg({"CVE-2021-0001": "2021-01-01", "CVE-2021-0002": "2021-01-01"})
    entries = [_entry("CVE-2021-0001", "2022-12-31"),   # seeding era: backfill
               _entry("CVE-2021-0002", "2023-01-01")]   # cutoff day: trend
    obj = build_kev_latency(agg, entries, GENERATED_AT, min_n=1)
    assert obj["launch_backfill"]["n"] == 1
    assert [r["year"] for r in obj["latency_by_year"]] == [2023]


def test_quartiles_and_pcts_over_a_real_distribution():
    agg = _agg({f"CVE-2024-{i:04d}": "2023-01-01" for i in range(1, 5)})
    # latencies vs 2023-01-01: 10, 20, 30, 400 days into 2023
    entries = [_entry("CVE-2024-0001", "2023-01-11"),
               _entry("CVE-2024-0002", "2023-01-21"),
               _entry("CVE-2024-0003", "2023-01-31"),
               _entry("CVE-2024-0004", "2024-02-05")]
    obj = build_kev_latency(agg, entries, GENERATED_AT, min_n=1)
    row_2023 = obj["latency_by_year"][0]
    assert (row_2023["p25_days"], row_2023["median_days"],
            row_2023["p75_days"]) == (15.0, 20.0, 25.0)
    row_2024 = obj["latency_by_year"][1]
    assert row_2024["pct_over_365d"] == 100.0  # 400 days > 365


def test_missing_or_blank_due_date_skipped_in_remediation():
    agg = _agg({"CVE-2024-0001": "2024-01-01", "CVE-2024-0002": "2024-01-01"})
    entries = [_entry("CVE-2024-0001", "2024-01-11", None),
               _entry("CVE-2024-0002", "2024-01-11", "2024-02-01")]
    obj = build_kev_latency(agg, entries, GENERATED_AT, min_n=1)
    assert obj["remediation_span_by_year"] == [
        {"year": 2024, "n": 1, "median_days": 21.0,
         "p25_days": 21.0, "p75_days": 21.0}]


def test_headline_falls_back_to_partial_current_year():
    # Only the current (partial) year survives: use it rather than nothing.
    agg = _agg({"CVE-2026-0001": "2026-01-01"})
    obj = build_kev_latency(agg, [_entry("CVE-2026-0001", "2026-01-31")],
                            GENERATED_AT, min_n=1)
    assert obj["headline"]["latest_year"] == 2026
    assert obj["headline"]["baseline_year"] == 2026  # earliest survivor


def test_headline_baseline_three_years_back_when_present():
    dates = {f"CVE-0000-{y}": f"{y}-01-01" for y in (2023, 2026)}
    agg = _agg(dates)
    entries = [_entry("CVE-0000-2023", "2023-01-31"),
               _entry("CVE-0000-2026", "2026-03-02")]  # 60 days
    # generated in 2027 so 2026 counts as a complete year
    obj = build_kev_latency(agg, entries, "2027-01-01T00:00:00Z", min_n=1)
    assert obj["headline"] == {"latest_year": 2026,
                               "median_days_latest": 60.0,
                               "pct_over_365d_latest": 0.0,
                               "baseline_year": 2023,
                               "median_days_baseline": 30.0}


def test_empty_backfill_median_is_null_never_zero():
    agg = _agg({"CVE-2024-0001": "2024-01-01"})
    obj = build_kev_latency(agg, [_entry("CVE-2024-0001", "2024-01-11")],
                            GENERATED_AT, min_n=1)
    assert obj["launch_backfill"]["n"] == 0
    assert obj["launch_backfill"]["median_days"] is None


# --------------------------------------------------------- ransomware share

def test_fixture_ransomware_share_includes_seeding_era(kev):
    obj = build_kev_ransomware(kev.entries, GENERATED_AT, min_n=1)
    # Every dateAdded year charts — the 2021 seeding-era entry included.
    assert obj["years"] == [
        {"year": 2021, "total": 1, "known": 0, "pct_known": 0.0},
        {"year": 2022, "total": 1, "known": 0, "pct_known": 0.0},
        {"year": 2023, "total": 3, "known": 2, "pct_known": 66.7},
        {"year": 2024, "total": 2, "known": 0, "pct_known": 0.0},
    ]
    assert obj["catalog"] == {"total": 7, "known": 2, "pct_known": 28.6}


def test_ransomware_missing_field_counts_as_unknown():
    entries = [_entry("CVE-2024-0001", "2024-01-11"),  # no field at all
               _entry("CVE-2024-0002", "2024-01-12", None, "Unknown"),
               _entry("CVE-2024-0003", "2024-01-13", None, "Known")]
    obj = build_kev_ransomware(entries, GENERATED_AT, min_n=1)
    assert obj["years"] == [{"year": 2024, "total": 3, "known": 1,
                             "pct_known": 33.3}]


def test_ransomware_flag_normalized_case_and_whitespace():
    entries = [_entry("CVE-2024-0001", "2024-01-11", None, " known "),
               _entry("CVE-2024-0002", "2024-01-12", None, "KNOWN"),
               _entry("CVE-2024-0003", "2024-01-13", None, "unknown")]
    obj = build_kev_ransomware(entries, GENERATED_AT, min_n=1)
    assert obj["years"][0]["known"] == 2


def test_ransomware_min_n_drops_thin_years():
    entries = [_entry(f"CVE-2024-{i:04d}", "2024-01-11", None, "Known")
               for i in range(1, 11)]
    entries.append(_entry("CVE-2025-0001", "2025-01-11", None, "Known"))
    obj = build_kev_ransomware(entries, GENERATED_AT, min_n=10)
    assert [r["year"] for r in obj["years"]] == [2024]  # 2025 has n=1
    # ... but the catalog totals stay unfiltered.
    assert obj["catalog"] == {"total": 11, "known": 11, "pct_known": 100.0}


def test_ransomware_undated_entries_count_only_in_catalog():
    entries = [_entry("CVE-2024-0001", "2024-01-11", None, "Known"),
               _entry("CVE-2024-0002", "", None, "Known"),        # blank
               _entry("CVE-2024-0003", "not-a-date", None, "Known")]
    obj = build_kev_ransomware(entries, GENERATED_AT, min_n=1)
    assert obj["years"] == [{"year": 2024, "total": 1, "known": 1,
                             "pct_known": 100.0}]
    assert obj["catalog"]["total"] == 3 and obj["catalog"]["known"] == 3


def test_ransomware_empty_catalog():
    obj = build_kev_ransomware([], GENERATED_AT)
    assert obj["years"] == []
    assert obj["catalog"] == {"total": 0, "known": 0, "pct_known": 0.0}
