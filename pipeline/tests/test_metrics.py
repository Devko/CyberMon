"""Metrics math against the hand-written fixture corpus (no network)."""
from __future__ import annotations

from pipeline import metrics
from pipeline.metrics import (cvss_bucket, epss_bucket, extract_facts,
                              severity_bucket)

from .conftest import GENERATED_AT


# ------------------------------------------------------------ bucket edges

def test_severity_bucket_edges():
    assert severity_bucket(6.9) == "medium"
    assert severity_bucket(7.0) == "high"
    assert severity_bucket(8.9) == "high"
    assert severity_bucket(9.0) == "critical"
    assert severity_bucket(3.9) == "low"
    assert severity_bucket(4.0) == "medium"
    assert severity_bucket(0.0) == "low"
    assert severity_bucket(10.0) == "critical"


def test_cvss_bucket_edges():
    assert cvss_bucket(6.9) == "4.0-6.9"
    assert cvss_bucket(7.0) == "7.0-8.9"
    assert cvss_bucket(8.9) == "7.0-8.9"
    assert cvss_bucket(9.0) == "9.0-10.0"


def test_epss_bucket_edges():
    assert epss_bucket(0.0009) == "<0.1%"
    assert epss_bucket(0.001) == "0.1-1%"
    assert epss_bucket(0.0099) == "0.1-1%"
    assert epss_bucket(0.01) == "1-10%"
    assert epss_bucket(0.1) == ">10%"
    assert epss_bucket(0.97) == ">10%"


# -------------------------------------------------------- facts extraction

def test_extract_facts_dual_version_record():
    record = {
        "cveMetadata": {"cveId": "CVE-2024-0001", "state": "PUBLISHED",
                        "assignerShortName": "GitHub_M",
                        "datePublished": "2024-02-14T09:00:00.000Z"},
        "containers": {"cna": {"metrics": [
            {"cvssV4_0": {"baseScore": 9.0}},
            {"cvssV3_1": {"baseScore": 8.9}},
        ]}},
    }
    facts = extract_facts(record)
    assert facts.cna_scores == {"v4": 9.0, "v3": 8.9}
    assert facts.newest_cna_score == 9.0  # newest version wins for blended
    assert facts.effective_score == 9.0
    assert facts.year == 2024


def test_extract_facts_v30_counts_as_v3():
    record = {
        "cveMetadata": {"cveId": "CVE-2024-0004", "state": "PUBLISHED",
                        "datePublished": "2024-07-04T00:00:00.000Z"},
        "containers": {"cna": {"metrics": [{"cvssV3_0": {"baseScore": 5.5}}]}},
    }
    assert extract_facts(record).cna_scores == {"v3": 5.5}


def test_extract_facts_v31_beats_v30_within_family():
    record = {
        "cveMetadata": {"cveId": "CVE-2024-0005", "state": "PUBLISHED"},
        "containers": {"cna": {"metrics": [
            {"cvssV3_0": {"baseScore": 5.0}},
            {"cvssV3_1": {"baseScore": 6.0}},
        ]}},
    }
    assert extract_facts(record).cna_scores == {"v3": 6.0}


def test_extract_facts_year_falls_back_to_cve_id():
    record = {"cveMetadata": {"cveId": "CVE-2025-0001", "state": "PUBLISHED"},
              "containers": {"cna": {}}}
    assert extract_facts(record).year == 2025


def test_effective_score_prefers_cna_over_adp_but_uses_adp_fallback():
    record = {
        "cveMetadata": {"cveId": "CVE-2025-0001", "state": "PUBLISHED"},
        "containers": {
            "cna": {},
            "adp": [{"metrics": [{"cvssV3_1": {"baseScore": 9.9}}]}],
        },
    }
    facts = extract_facts(record)
    assert facts.newest_cna_score is None  # not CNA-scored
    assert facts.effective_score == 9.9    # but scored "anywhere in the record"


def test_extract_facts_ignores_non_cve_documents():
    assert extract_facts({"fetchTime": "2026-07-09"}) is None
    assert extract_facts({"cveMetadata": {"cveId": None}}) is None


# ---------------------------------------------------- chart 1: severity

def test_severity_series_and_blended_dedup(agg):
    out = metrics.build_severity_inflation(agg, GENERATED_AT)

    v2_2014 = next(r for r in out["series"]["v2"] if r["year"] == 2014)
    assert v2_2014["n"] == 2 and v2_2014["median"] == 5.4
    assert v2_2014["p25"] <= v2_2014["median"] <= v2_2014["p75"]

    # dual-version CVE-2024-0001: v3 series sees 8.9, v4 series sees 9.0 ...
    v3_2024 = next(r for r in out["series"]["v3"] if r["year"] == 2024)
    assert v3_2024["n"] == 2  # 8.9 (dual) + 5.5 (CVE-2024-0004)
    v4_2024 = next(r for r in out["series"]["v4"] if r["year"] == 2024)
    assert v4_2024 == {"year": 2024, "n": 1, "median": 9.0,
                       "p25": 9.0, "p75": 9.0}

    # ... but blended counts it exactly once, with the newest (v4) score.
    blended_2024 = next(r for r in out["blended"] if r["year"] == 2024)
    assert blended_2024["n"] == 2  # 9.0 (newest of dual) + 5.5; unscored absent
    assert blended_2024["pct_high_critical"] == 50.0

    # ADP-only CVE-2025-0001 is NOT CNA-scored: blended 2025 has just 8.9.
    blended_2025 = next(r for r in out["blended"] if r["year"] == 2025)
    assert blended_2025["n"] == 1 and blended_2025["pct_high_critical"] == 100.0


def test_pct_high_critical_edge_at_7(agg):
    out = metrics.build_severity_inflation(agg, GENERATED_AT)
    b2023 = next(r for r in out["blended"] if r["year"] == 2023)
    # scores 9.8, 7.0, 6.9 -> 7.0 counts as high, 6.9 does not.
    assert b2023["n"] == 3 and b2023["pct_high_critical"] == 66.7


def test_headline_falls_back_when_decade_ago_missing(agg):
    out = metrics.build_severity_inflation(agg, GENERATED_AT)
    assert out["headline"]["latest_year"] == 2025
    assert out["headline"]["pct_high_critical_latest"] == 100.0
    # 2015 has no data: falls back to the earliest blended year (2014, 0%).
    assert out["headline"]["pct_high_critical_decade_ago"] == 0.0


# ---------------------------------------------------- chart 2: 9.8 flood

def test_flood_buckets_unscored_and_rejected(agg):
    out = metrics.build_nine_eight_flood(agg, GENERATED_AT)
    by_year = {r["year"]: r for r in out["years"]}
    assert by_year[2014] == {"year": 2014, "critical": 0, "high": 0,
                             "medium": 2, "low": 0, "unscored": 0}
    # 2024: 9.0 critical (v4 of dual), 5.5 medium, one unscored;
    # the REJECTED record does not appear at all.
    assert by_year[2024] == {"year": 2024, "critical": 1, "high": 0,
                             "medium": 1, "low": 0, "unscored": 1}
    # ADP-only 9.9 counts as scored ("anywhere in the record").
    assert by_year[2025]["critical"] == 1 and by_year[2025]["unscored"] == 0
    # gap years are zero-filled and the series is contiguous 2014..2025.
    assert [r["year"] for r in out["years"]] == list(range(2014, 2026))
    assert by_year[2019] == {"year": 2019, "critical": 0, "high": 0,
                             "medium": 0, "low": 0, "unscored": 0}


# ------------------------------------------------------- chart 3: grid/KEV

def test_grid_cells_and_headline(agg, epss, kev):
    out = metrics.build_score_vs_reality(agg, epss.scores, kev.cve_ids,
                                         GENERATED_AT)
    cells = {(c["cvss_bucket"], c["epss_bucket"]): c["n"] for c in out["grid"]}
    assert len(cells) == 16  # every cell present, even empty ones
    assert cells[("9.0-10.0", "0.1-1%")] == 1   # CVE-2023-0001
    assert cells[("9.0-10.0", ">10%")] == 2     # CVE-2024-0001, CVE-2025-0001
    assert cells[("4.0-6.9", "0.1-1%")] == 1    # CVE-2023-0003 (epss 0.001 edge)
    assert cells[("7.0-8.9", "<0.1%")] == 1     # CVE-2023-0002
    assert cells[("4.0-6.9", "1-10%")] == 1     # CVE-2014-0001
    assert sum(cells.values()) == 6  # unknown EPSS CVE ignored

    # criticals with EPSS: 9.8@0.005, 9.0@0.97, 9.9@0.5 -> 1 of 3 below 1%.
    assert out["headline"] == {"pct_critical_epss_below_1pct": 33.3,
                               "n_critical_with_epss": 3}


def test_kev_cut(agg, epss, kev):
    out = metrics.build_score_vs_reality(agg, epss.scores, kev.cve_ids,
                                         GENERATED_AT)
    assert out["kev"]["total"] == 3
    assert out["kev"]["below_high"] == 1  # CVE-2023-0003 at 6.9
    assert out["kev"]["pct_below_high"] == 33.3
    dist = {d["bucket"]: d["n"] for d in out["kev"]["cvss_distribution"]}
    # the unscored KEV entry is not in the distribution
    assert dist == {"0.1-3.9": 0, "4.0-6.9": 1, "7.0-8.9": 0, "9.0-10.0": 1}


# ------------------------------------------------- chart 5: CNA leaderboard

def test_cna_leaderboard_window_min_cves_and_sort(agg):
    out = metrics.build_cna_leaderboard(agg, GENERATED_AT, min_cves=1)
    assert out["window_years"] == 3 and out["min_cves"] == 1
    # window = 2023-2025; mitre has no *scored* CVE there -> excluded.
    assert [c["cna"] for c in out["cnas"]] == ["GitHub_M", "VendorX"]

    github = out["cnas"][0]
    assert github["n"] == 2  # 6.9 (2023) + 9.0 (2024, newest of dual)
    assert github["pct_geq_9"] == 50.0 and github["pct_geq_7"] == 50.0

    vendorx = out["cnas"][1]
    assert vendorx["n"] == 4  # 9.8, 7.0 (2023), 5.5 (2024), 8.9 (2025)
    assert vendorx["avg_cvss"] == 7.8
    assert vendorx["pct_geq_9"] == 25.0 and vendorx["pct_geq_7"] == 75.0


def test_cna_leaderboard_min_cves_threshold(agg):
    out = metrics.build_cna_leaderboard(agg, GENERATED_AT, min_cves=3)
    assert [c["cna"] for c in out["cnas"]] == ["VendorX"]  # only one with >=3
    out = metrics.build_cna_leaderboard(agg, GENERATED_AT, min_cves=100)
    assert out["cnas"] == []


# --------------------------------------------------- chart 6: volume curve

def test_volume_curve_counts_rejected_by_publication_year(agg):
    out = metrics.build_volume_curve(agg, GENERATED_AT)
    by_year = {r["year"]: r for r in out["years"]}
    assert by_year[2014] == {"year": 2014, "published": 2, "rejected": 0}
    assert by_year[2024] == {"year": 2024, "published": 3, "rejected": 1}
    assert by_year[2025] == {"year": 2025, "published": 2, "rejected": 0}
    assert by_year[2020] == {"year": 2020, "published": 0, "rejected": 0}


# --------------------------------------------------------- chart 4 helpers

def test_backlog_row_and_nvd_decay():
    statuses = {"Received": 290, "Awaiting Analysis": 30412,
                "Undergoing Analysis": 400, "Analyzed": 200000}
    row = metrics.backlog_row(statuses, "2026-07-09")
    assert row == {"date": "2026-07-09", "backlog_total": 31102,
                   "awaiting_analysis": 30412, "undergoing_analysis": 400,
                   "received": 290}
    out = metrics.build_nvd_decay(statuses, [row], GENERATED_AT)
    assert out["current"]["backlog_total"] == 31102
    assert out["current"]["statuses"][0] == {"status": "Analyzed", "n": 200000}
    assert out["history"] == [{"date": "2026-07-09", "backlog_total": 31102,
                               "awaiting_analysis": 30412}]
