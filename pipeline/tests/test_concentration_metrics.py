"""CNA concentration math: HHI, newcomers, leaderboard, headline rules."""
from __future__ import annotations

from pipeline import metrics
from pipeline.concentration_metrics import build_cna_concentration

from .conftest import GENERATED_AT


def _agg(facts_list) -> metrics.Aggregator:
    agg = metrics.Aggregator()
    for facts in facts_list:
        agg.add(facts)
    return agg


def _facts(cve_id, year, cna, state="PUBLISHED"):
    return metrics.CveFacts(cve_id, state, year, cna)


# --------------------------------------------------------------------- HHI

def test_hhi_single_cna_year_is_10000():
    agg = _agg([_facts("CVE-1999-0001", 1999, "solo")])
    obj = build_cna_concentration(agg, GENERATED_AT, min_total=1)
    assert obj["years"] == [{"year": 1999, "cna_count": 1,
                             "newcomer_count": 1, "top5_share": 100.0,
                             "top10_share": 100.0, "hhi": 10000.0}]


def test_hhi_even_split():
    agg = _agg([_facts(f"CVE-2020-000{i}", 2020, cna)
                for i, cna in enumerate(("a", "b", "c", "d"))])
    obj = build_cna_concentration(agg, GENERATED_AT, min_total=1)
    assert obj["years"][0]["hhi"] == 2500.0  # 4 * (1/4)^2 * 10000


def test_gap_year_with_zero_published_gets_zero_stats():
    agg = _agg([_facts("CVE-2020-0001", 2020, "a"),
                _facts("CVE-2022-0001", 2022, "a")])
    obj = build_cna_concentration(agg, GENERATED_AT, min_total=1)
    assert obj["years"][1] == {"year": 2021, "cna_count": 0,
                               "newcomer_count": 0, "top5_share": 0.0,
                               "top10_share": 0.0, "hhi": 0.0}


def test_rejected_only_year_counts_cnas_but_zero_shares():
    agg = _agg([_facts("CVE-2020-0001", 2020, "a"),
                _facts("CVE-2021-0001", 2021, "b", state="REJECTED"),
                _facts("CVE-2022-0001", 2022, "a")])
    obj = build_cna_concentration(agg, GENERATED_AT, min_total=1)
    row_2021 = obj["years"][1]
    assert row_2021["cna_count"] == 1        # b was active (rejecting)
    assert row_2021["newcomer_count"] == 1   # ... and new that year
    assert row_2021["top5_share"] == 0.0 and row_2021["hhi"] == 0.0


def test_top5_share_with_more_than_five_cnas():
    facts = [_facts(f"CVE-2020-1{i:03d}", 2020, "big")
             for i in range(5)]                            # big: 5 of 11
    facts += [_facts(f"CVE-2020-2{i:03d}", 2020, f"cna{i}")
              for i in range(6)]                           # six singletons
    obj = build_cna_concentration(_agg(facts), GENERATED_AT, min_total=1)
    row = obj["years"][0]
    # top 5 = big(5) + four singletons(4) = 9 of 11
    assert row["top5_share"] == 81.8
    assert row["top10_share"] == 100.0  # all 7 CNAs fit in the top 10
    assert row["cna_count"] == 7


# --------------------------------------------------------------- newcomers

def test_newcomers_first_ever_activity_year_only():
    agg = _agg([_facts("CVE-2020-0001", 2020, "old"),
                _facts("CVE-2021-0001", 2021, "old"),
                _facts("CVE-2021-0002", 2021, "new")])
    obj = build_cna_concentration(agg, GENERATED_AT, min_total=1)
    assert [(r["year"], r["newcomer_count"]) for r in obj["years"]] == \
        [(2020, 1), (2021, 1)]


def test_rejected_activity_counts_as_first_activity():
    # A CNA that debuts with a rejection is not a "newcomer" again later.
    agg = _agg([_facts("CVE-2020-0001", 2020, "x", state="REJECTED"),
                _facts("CVE-2021-0001", 2021, "x")])
    obj = build_cna_concentration(agg, GENERATED_AT, min_total=1)
    assert [(r["year"], r["newcomer_count"]) for r in obj["years"]] == \
        [(2020, 1), (2021, 0)]


# ------------------------------------------------------- fixture-based build

def test_fixture_years_exact(agg):
    obj = build_cna_concentration(agg, GENERATED_AT, min_total=1)
    by_year = {r["year"]: r for r in obj["years"]}
    assert sorted(by_year) == list(range(2014, 2026))  # gap-filled span
    assert by_year[2014] == {"year": 2014, "cna_count": 1,
                             "newcomer_count": 1, "top5_share": 100.0,
                             "top10_share": 100.0, "hhi": 10000.0}
    assert by_year[2018]["hhi"] == 0.0  # gap year: history, not noise
    # 2023: VendorX 2 + GitHub_M 1 -> (2/3)^2 + (1/3)^2 = 5/9
    assert by_year[2023] == {"year": 2023, "cna_count": 2,
                             "newcomer_count": 2, "top5_share": 100.0,
                             "top10_share": 100.0, "hhi": 5555.6}
    # 2024: three CNAs publish 1 each (mitre also rejects 1)
    assert by_year[2024] == {"year": 2024, "cna_count": 3,
                             "newcomer_count": 0, "top5_share": 100.0,
                             "top10_share": 100.0, "hhi": 3333.3}
    assert by_year[2025] == {"year": 2025, "cna_count": 1,
                             "newcomer_count": 0, "top5_share": 100.0,
                             "top10_share": 100.0, "hhi": 10000.0}


def test_fixture_rejection_leaderboard_sort_and_rate(agg):
    obj = build_cna_concentration(agg, GENERATED_AT, min_total=1)
    board = obj["rejection_leaderboard"]
    assert board["window_years"] == 5 and board["min_total"] == 1
    # window 2021-2025: mitre 1 pub + 1 rej (bounded rate 50.0, not the
    # unbounded rejected/published); VendorX/GitHub_M tie at 0.0 and
    # break by total desc.
    assert board["cnas"] == [
        {"cna": "mitre", "total": 2, "rejected": 1,
         "rejected_rate_pct": 50.0},
        {"cna": "VendorX", "total": 5, "rejected": 0,
         "rejected_rate_pct": 0.0},
        {"cna": "GitHub_M", "total": 2, "rejected": 0,
         "rejected_rate_pct": 0.0},
    ]


def test_fixture_leaderboard_min_total_excludes_thin_cnas(agg):
    obj = build_cna_concentration(agg, GENERATED_AT, min_total=3)
    assert [c["cna"] for c in obj["rejection_leaderboard"]["cnas"]] == \
        ["VendorX"]  # mitre and GitHub_M have only 2 records in window


def test_fixture_headline_complete_year_and_ten_year_baseline(agg):
    obj = build_cna_concentration(agg, GENERATED_AT, min_total=1)
    # GENERATED_AT is 2026 -> latest complete year 2025; baseline
    # 2015 (latest - 10) is in the gap-filled span.
    assert obj["headline"] == {"latest_year": 2025, "cna_count_latest": 1,
                               "top5_share_latest": 100.0,
                               "hhi_latest": 10000.0,
                               "baseline_year": 2015,
                               "top5_share_baseline": 0.0,
                               "hhi_baseline": 0.0}


# ----------------------------------------------------------------- headline

def test_headline_falls_back_to_partial_current_year():
    agg = _agg([_facts("CVE-2026-0001", 2026, "a")])
    obj = build_cna_concentration(agg, GENERATED_AT, min_total=1)
    assert obj["headline"]["latest_year"] == 2026  # nothing else exists


def test_headline_baseline_earliest_when_ten_years_back_absent():
    agg = _agg([_facts("CVE-2020-0001", 2020, "a"),
                _facts("CVE-2021-0001", 2021, "a"),
                _facts("CVE-2021-0002", 2021, "b")])
    obj = build_cna_concentration(agg, GENERATED_AT, min_total=1)
    assert obj["headline"]["latest_year"] == 2021
    assert obj["headline"]["baseline_year"] == 2020  # 2011 not in span
    assert obj["headline"]["hhi_baseline"] == 10000.0


def test_leaderboard_window_ends_at_newest_published_year():
    # 2019 rejections fall outside a 2-year window ending 2021.
    agg = _agg([_facts("CVE-2019-0001", 2019, "a", state="REJECTED"),
                _facts("CVE-2020-0001", 2020, "a"),
                _facts("CVE-2021-0001", 2021, "a")])
    obj = build_cna_concentration(agg, GENERATED_AT, window_years=2,
                                  min_total=1)
    assert obj["rejection_leaderboard"]["cnas"] == [
        {"cna": "a", "total": 2, "rejected": 0, "rejected_rate_pct": 0.0}]
