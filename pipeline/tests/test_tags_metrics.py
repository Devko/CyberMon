"""Record Tags (cve_tags.json): tag extraction, per-year counts, the
who-tags boards, the severity baselines, context tags, headline rules, and
the contract."""
from __future__ import annotations

import copy

import pytest

from pipeline import contracts, metrics
from pipeline.metrics import CveFacts, extract_facts
from pipeline.tags_metrics import build_cve_tags

from .conftest import GENERATED_AT  # 2026-07-09 -> 2025 is the latest full year

UWA = "unsupported-when-assigned"


def _record(cve_id, cna, published, tags=None, adp_tags=None, score=None):
    cna_c = {"providerMetadata": {"shortName": cna}}
    if tags is not None:
        cna_c["tags"] = tags
    if score is not None:
        cna_c["metrics"] = [{"cvssV3_1": {"baseScore": score}}]
    rec = {"cveMetadata": {"cveId": cve_id, "state": "PUBLISHED",
                           "assignerShortName": cna,
                           "datePublished": f"{published}T00:00:00Z"},
           "containers": {"cna": cna_c}}
    if adp_tags is not None:
        rec["containers"]["adp"] = [{"providerMetadata": {"shortName": "CVE"},
                                     "tags": adp_tags}]
    return rec


def _agg(records) -> metrics.Aggregator:
    agg = metrics.Aggregator()
    agg.consume(records)
    return agg


# ------------------------------------------------------------ extraction

def test_tags_are_deduplicated_strings_only():
    facts = extract_facts(_record("CVE-2025-0001", "a", "2025-01-02",
                                  tags=[UWA, UWA, "", 7, None, "x_ICS"],
                                  adp_tags=["x_bundling-flagged-by-CVE-Program"]))
    assert facts.tags == (UWA, "x_ICS")
    assert facts.adp_tags == ("x_bundling-flagged-by-CVE-Program",)
    # malformed tags (not a list) read as untagged, never crash
    bad = _record("CVE-2025-0002", "a", "2025-01-02")
    bad["containers"]["cna"]["tags"] = "disputed"
    assert extract_facts(bad).tags == ()


def test_rejected_records_never_count():
    rec = _record("CVE-2025-0003", "a", "2025-01-02", tags=["disputed"])
    rec["cveMetadata"]["state"] = "REJECTED"
    agg = _agg([rec])
    assert not agg.tag_year_counts


# ------------------------------------------------------------- per year

def test_years_span_from_first_tagged_year_gap_filled():
    agg = _agg([
        _record("CVE-2019-0001", "old", "2019-05-01"),               # untagged
        _record("CVE-2021-0001", "mitre", "2021-05-01", tags=["disputed"]),
        _record("CVE-2023-0001", "v", "2023-05-01", tags=[UWA]),
        _record("CVE-2023-0002", "v", "2023-06-01"),
    ])
    out = build_cve_tags(agg, GENERATED_AT, min_n=1)
    assert [r["year"] for r in out["years"]] == [2021, 2022, 2023]
    by_year = {r["year"]: r for r in out["years"]}
    assert by_year[2022] == {"year": 2022, "published": 0,
                             "counts": {UWA: 0, "disputed": 0,
                                        "exclusively-hosted-service": 0}}
    assert by_year[2023]["published"] == 2
    assert by_year[2023]["counts"][UWA] == 1
    contracts.validate("cve_tags.json", out)


def test_no_schema_tags_yields_empty_valid_edition():
    agg = _agg([_record("CVE-2025-0001", "a", "2025-01-02",
                        tags=["x_open-source"])])
    out = build_cve_tags(agg, GENERATED_AT)
    assert out["years"] == []
    assert out["boards"][UWA]["cnas"] == []
    assert out["context"]["private_tags"] == [{"tag": "x_open-source", "n": 1}]
    contracts.validate("cve_tags.json", out)
    empty = build_cve_tags(metrics.Aggregator(), GENERATED_AT)
    contracts.validate("cve_tags.json", empty)


# --------------------------------------------------------------- boards

def _board_agg():
    records = []
    # window for a 2026 corpus and window_years=2: 2025-2026
    for i in range(6):
        records.append(_record(f"CVE-2025-1{i:03d}", "big", "2025-03-01",
                               tags=[UWA], score=9.8))
    for i in range(4):
        records.append(_record(f"CVE-2025-2{i:03d}", "big", "2025-03-01",
                               score=5.0))
    for i in range(3):
        records.append(_record(f"CVE-2026-3{i:03d}", "small", "2026-02-01",
                               tags=[UWA], score=7.5))
    records.append(_record("CVE-2026-4000", "rare", "2026-02-01", tags=[UWA]))
    records.append(_record("CVE-2026-5000", "never", "2026-02-01", score=4.0))
    # outside the window: must not count
    records.append(_record("CVE-2024-6000", "big", "2024-03-01", tags=[UWA]))
    return _agg(records)


def test_board_window_floor_shares_and_rates():
    out = build_cve_tags(_board_agg(), GENERATED_AT, window_years=2, min_n=2)
    assert out["window"] == {"from": 2025, "to": 2026, "years": 2}
    board = out["boards"][UWA]
    assert board["total"] == 10          # 6 + 3 + 1; the 2024 one is out
    assert board["cna_count"] == 3       # "rare" counts, below the floor
    assert board["active_cnas"] == 4     # "never" published, never tagged
    assert board["top1_share_pct"] == 60.0
    assert board["top3_share_pct"] == 100.0
    assert board["cnas"] == [
        {"cna": "big", "n": 6, "share_pct": 60.0, "cna_published": 10,
         "rate_pct": 60.0},
        {"cna": "small", "n": 3, "share_pct": 30.0, "cna_published": 3,
         "rate_pct": 100.0},
    ]
    contracts.validate("cve_tags.json", out)


def test_severity_tagged_vs_same_cna_untagged_vs_all():
    out = build_cve_tags(_board_agg(), GENERATED_AT, window_years=2, min_n=2)
    sev = out["severity"]
    tagged = sev[UWA]["tagged"]
    assert tagged == {"critical": 6, "high": 3, "medium": 0, "low": 0,
                      "unscored": 1}
    # the taggers' OTHER records: big's four 5.0s; small/rare have none
    assert sev[UWA]["same_cnas_untagged"] == {
        "critical": 0, "high": 0, "medium": 4, "low": 0, "unscored": 0}
    # every published record in the window, "never" included
    assert sev["all"] == {"critical": 6, "high": 3, "medium": 5, "low": 0,
                          "unscored": 1}


# -------------------------------------------------------------- headline

def test_headline_growth_uses_complete_years_and_flat_window():
    records = []
    counts = {2019: 0, 2020: 2, 2021: 3, 2022: 5, 2023: 8, 2024: 9,
              2025: 12, 2026: 11}
    n = 0
    for year, k in counts.items():
        for i in range(k):
            n += 1
            records.append(_record(f"CVE-{year}-{n:05d}", "c", f"{year}-04-01",
                                   tags=[UWA]))
        # disputed: 1 or 2 a year, and 10 untagged records a year
        for i in range(1 + year % 2):
            n += 1
            records.append(_record(f"CVE-{year}-{n:05d}", "mitre",
                                   f"{year}-04-01", tags=["disputed"]))
        for i in range(10):
            n += 1
            records.append(_record(f"CVE-{year}-{n:05d}", "c", f"{year}-04-01"))
    out = build_cve_tags(_agg(records), GENERATED_AT)
    h = out["headline"]
    assert h["latest_year"] == 2025
    assert (h["unsupported_first_year"], h["unsupported_first"]) == (2020, 2)
    assert h["unsupported_latest"] == 12
    assert h["unsupported_current"] == 11 and h["current_year"] == 2026
    # 2025: 12 / (12 + 2 + 10)
    assert h["unsupported_latest_share_pct"] == 50.0
    # flat window: the last six complete years
    assert (h["disputed_from"], h["disputed_to"]) == (2020, 2025)
    assert (h["disputed_min"], h["disputed_max"]) == (1, 2)
    contracts.validate("cve_tags.json", out)


# -------------------------------------------------------------- contract

def test_contract_rejects_inconsistent_payloads():
    out = build_cve_tags(_board_agg(), GENERATED_AT, window_years=2, min_n=2)
    contracts.validate("cve_tags.json", out)

    bad = copy.deepcopy(out)
    bad["years"][0]["counts"][UWA] = bad["years"][0]["published"] + 1
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("cve_tags.json", bad)

    bad = copy.deepcopy(out)
    bad["severity"][UWA]["tagged"]["critical"] += 1  # != board total
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("cve_tags.json", bad)

    bad = copy.deepcopy(out)
    bad["boards"][UWA]["cnas"].reverse()  # must be sorted by n desc
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("cve_tags.json", bad)

    bad = copy.deepcopy(out)
    bad["schema_tags"] = ["disputed"]
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("cve_tags.json", bad)


def test_hand_built_facts_default_to_untagged():
    agg = metrics.Aggregator()
    agg.add(CveFacts("CVE-2025-0001", "PUBLISHED", 2025, "a"))
    assert build_cve_tags(agg, GENERATED_AT)["years"] == []
