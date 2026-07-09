"""Advisory-quality and bug-class metrics: extraction rules, thresholds,
window edges, the "other" bucket, unmapped-CWE fallback."""
from __future__ import annotations

from pipeline import metrics, quality_metrics
from pipeline.metrics import extract_facts
from pipeline.quality_metrics import (build_advisory_quality,
                                      build_cwe_distribution, cwe_name)

from .conftest import GENERATED_AT


def _record(cve_id="CVE-2024-0100", cna_extra=None, adp=None):
    record = {
        "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED",
                        "datePublished": f"{cve_id.split('-')[1]}-06-01T00:00:00Z"},
        "containers": {"cna": dict(cna_extra or {})},
    }
    if adp is not None:
        record["containers"]["adp"] = adp
    return record


# ------------------------------------------------------- facts extraction

def test_extract_facts_first_cwe_from_cna():
    facts = extract_facts(_record(cna_extra={"problemTypes": [
        {"descriptions": [{"cweId": "CWE-79"}, {"cweId": "CWE-89"}]},
    ]}))
    assert facts.cwe == "CWE-79"  # first-listed wins


def test_extract_facts_cwe_adp_fallback_but_cna_preferred():
    adp = [{"problemTypes": [{"descriptions": [{"cweId": "CWE-1321"}]}]}]
    facts = extract_facts(_record(adp=adp))
    assert facts.cwe == "CWE-1321"  # ADP-only record is still tagged
    facts = extract_facts(_record(
        cna_extra={"problemTypes": [{"descriptions": [{"cweId": "CWE-79"}]}]},
        adp=adp))
    assert facts.cwe == "CWE-79"  # CNA container preferred


def test_extract_facts_text_only_problem_types_not_tagged():
    facts = extract_facts(_record(cna_extra={"problemTypes": [
        {"descriptions": [{"lang": "en", "type": "text", "description": "n/a"}]},
    ]}))
    assert facts.cwe is None


def test_extract_facts_affected_usable_rules():
    concrete = {"affected": [{"versions": [{"version": "1.2.3",
                                            "status": "affected"}]}]}
    assert extract_facts(_record(cna_extra=concrete)).has_affected is True

    default_status = {"affected": [{"defaultStatus": "unaffected"}]}
    assert extract_facts(_record(cna_extra=default_status)).has_affected is True

    placeholder = {"affected": [{"versions": [{"version": "n/a",
                                               "status": "affected"}]}]}
    assert extract_facts(_record(cna_extra=placeholder)).has_affected is False

    unknown_default = {"affected": [{"defaultStatus": "unknown"}]}
    assert extract_facts(
        _record(cna_extra=unknown_default)).has_affected is False

    assert extract_facts(_record()).has_affected is False  # no affected[]


def test_extract_facts_affected_found_in_adp_container():
    adp = [{"affected": [{"defaultStatus": "affected"}]}]
    assert extract_facts(_record(adp=adp)).has_affected is True


# ------------------------------------------- chart 7: advisory quality

def test_fixture_advisory_quality_per_year(agg):
    out = build_advisory_quality(agg, GENERATED_AT, min_n=1)
    assert out["min_n"] == 1
    by_year = {r["year"]: r for r in out["years"]}
    assert sorted(by_year) == [2014, 2023, 2024, 2025]

    # 2014: v2 scores exist, but nothing else is machine-readable.
    assert by_year[2014] == {"year": 2014, "n": 2,
                             "missing_cwe": 2, "pct_missing_cwe": 100.0,
                             "missing_cvss": 0, "pct_missing_cvss": 0.0,
                             "missing_affected": 2,
                             "pct_missing_affected": 100.0}
    # 2023: all tagged and scored; CVE-2023-0003 carries no affected[].
    assert by_year[2023] == {"year": 2023, "n": 3,
                             "missing_cwe": 0, "pct_missing_cwe": 0.0,
                             "missing_cvss": 0, "pct_missing_cvss": 0.0,
                             "missing_affected": 1,
                             "pct_missing_affected": 33.3}
    # 2024 (REJECTED record excluded from n): the unscored record misses
    # everything; CVE-2024-0004's text-only problemTypes and "n/a"-only
    # affected[] both count as missing.
    assert by_year[2024] == {"year": 2024, "n": 3,
                             "missing_cwe": 2, "pct_missing_cwe": 66.7,
                             "missing_cvss": 1, "pct_missing_cvss": 33.3,
                             "missing_affected": 2,
                             "pct_missing_affected": 66.7}
    # 2025: ADP-only CWE/score counts as present (record-level check).
    assert by_year[2025] == {"year": 2025, "n": 2,
                             "missing_cwe": 1, "pct_missing_cwe": 50.0,
                             "missing_cvss": 0, "pct_missing_cvss": 0.0,
                             "missing_affected": 1,
                             "pct_missing_affected": 50.0}


def test_advisory_quality_min_n_drops_thin_years(agg):
    out = build_advisory_quality(agg, GENERATED_AT, min_n=3)
    assert [r["year"] for r in out["years"]] == [2023, 2024]  # n=2 dropped


def test_advisory_quality_empty_aggregator():
    out = build_advisory_quality(metrics.Aggregator(), GENERATED_AT)
    assert out["years"] == []


# ------------------------------------------ chart 8: bug-class inertia

def test_fixture_cwe_distribution_window_top_and_shares(agg):
    out = build_cwe_distribution(agg, GENERATED_AT, min_n=1)
    # last 10 complete years for a 2026 generation date
    assert out["window"] == {"start_year": 2016, "end_year": 2025}
    # volume rank: CWE-79 twice; count-1 ties break by CWE number.
    assert [t["id"] for t in out["top_cwes"]] == \
        ["CWE-79", "CWE-416", "CWE-787", "CWE-1321"]
    names = {t["id"]: t["name"] for t in out["top_cwes"]}
    assert names["CWE-79"] == "Cross-site scripting"
    assert names["CWE-1321"] == "CWE-1321"  # unmapped -> bare id

    by_year = {r["year"]: r for r in out["years"]}
    assert sorted(by_year) == [2023, 2024, 2025]  # 2014 outside the window
    assert by_year[2023]["n_tagged"] == 3
    assert by_year[2023]["pct_tagged"] == 100.0
    assert by_year[2023]["shares"] == {"CWE-79": 66.7, "CWE-416": 0.0,
                                       "CWE-787": 33.3, "CWE-1321": 0.0,
                                       "other": 0.0}
    assert by_year[2024]["n_tagged"] == 1
    assert by_year[2024]["n_published"] == 3
    assert by_year[2024]["pct_tagged"] == 33.3
    assert by_year[2024]["shares"]["CWE-416"] == 100.0


def test_cwe_distribution_min_n_drops_thin_years(agg):
    out = build_cwe_distribution(agg, GENERATED_AT, min_n=2)
    assert [r["year"] for r in out["years"]] == [2023]  # 2024/2025 n_tagged=1


def _cwe_agg(year_counts: dict[int, dict[str, int]]) -> metrics.Aggregator:
    agg = metrics.Aggregator()
    for year, counts in year_counts.items():
        for cwe_id, n in counts.items():
            agg.cwe_year_counts[year][cwe_id] += n
            agg.published_by_year[year] += n
    return agg


def test_cwe_distribution_other_bucket_and_top_k():
    counts = {f"CWE-{i}": 20 - i for i in range(1, 10)}  # 9 distinct classes
    agg = _cwe_agg({2024: counts})
    out = build_cwe_distribution(agg, GENERATED_AT, min_n=1)
    assert len(out["top_cwes"]) == 8  # never more than top_k
    assert [t["id"] for t in out["top_cwes"]] == \
        [f"CWE-{i}" for i in range(1, 9)]  # CWE-9 (lowest volume) folds away
    row = out["years"][0]
    n_tagged = sum(counts.values())
    assert row["shares"]["other"] == round(100.0 * 11 / n_tagged, 1)


def test_cwe_distribution_partial_current_year_excluded():
    # 2026 is the generation year: its counts must not chart AND must not
    # influence the decade ranking.
    agg = _cwe_agg({2025: {"CWE-79": 5}, 2026: {"CWE-89": 500}})
    out = build_cwe_distribution(agg, GENERATED_AT, min_n=1)
    assert [t["id"] for t in out["top_cwes"]] == ["CWE-79"]
    assert [r["year"] for r in out["years"]] == [2025]


def test_cwe_distribution_years_before_window_excluded():
    agg = _cwe_agg({2015: {"CWE-79": 100}, 2016: {"CWE-89": 1}})
    out = build_cwe_distribution(agg, GENERATED_AT, min_n=1)
    assert [t["id"] for t in out["top_cwes"]] == ["CWE-89"]  # 2015 outside
    assert [r["year"] for r in out["years"]] == [2016]


def test_cwe_distribution_empty_corpus():
    out = build_cwe_distribution(metrics.Aggregator(), GENERATED_AT)
    assert out["top_cwes"] == [] and out["years"] == []


def test_cwe_name_map_and_fallback():
    assert cwe_name("CWE-787") == "Out-of-bounds write"
    assert cwe_name("CWE-424242") == "CWE-424242"
    assert quality_metrics._cwe_number("CWE-79") == 79
    assert quality_metrics._cwe_number("CWE-weird") == 1 << 30
