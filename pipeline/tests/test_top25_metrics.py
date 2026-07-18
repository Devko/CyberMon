"""top25_metrics tests: the kev_cwe_counts accumulator, build_cwe_top25's
window / measured-rank / KEV math, the min_n degradation, and the offline
end-to-end run emitting a valid cwe_top25.json + meta.sources.top25."""
from __future__ import annotations

import json
from collections import Counter

# contracts must load before top25_contracts (registration order — see the
# note in test_naming_contracts.py).
from pipeline import contracts
from pipeline import cwe_top25_data
from pipeline import metrics
from pipeline import top25_contracts  # noqa: E402
from pipeline.__main__ import main
from pipeline.metrics import CveFacts
from pipeline.top25_metrics import build_cwe_top25

GENERATED_AT = "2026-07-09T00:00:00Z"  # window -> 2021..2025


# --------------------------------------------------- kev_cwe_counts accumulator

def test_kev_cwe_counts_only_published_kev_records_with_a_cwe():
    agg = metrics.Aggregator(kev_ids=["CVE-1", "CVE-3", "CVE-4"])
    # KEV + CWE + published -> counted
    agg.add(CveFacts("CVE-1", "PUBLISHED", 2024, "x", cwe="CWE-79"))
    # not in KEV -> not counted (still lands in cwe_year_counts)
    agg.add(CveFacts("CVE-2", "PUBLISHED", 2024, "x", cwe="CWE-79"))
    # KEV but no CWE -> not counted
    agg.add(CveFacts("CVE-3", "PUBLISHED", 2024, "x", cwe=None))
    # KEV + CWE but REJECTED -> not counted (rejected returns before CWE math)
    agg.add(CveFacts("CVE-4", "REJECTED", 2024, "x", cwe="CWE-89"))
    assert agg.kev_cwe_counts == Counter({"CWE-79": 1})
    # purely additive: the measured tally still sees both published CWE rows
    assert agg.cwe_year_counts[2024] == Counter({"CWE-79": 2})


# ------------------------------------------------------------ build_cwe_top25

def _agg_with(cwe_year, kev_cwe):
    agg = metrics.Aggregator()
    for year, counts in cwe_year.items():
        agg.cwe_year_counts[year] = Counter(counts)
    agg.kev_cwe_counts = Counter(kev_cwe)
    return agg


def test_measured_rank_and_kev_math():
    # CWE-1234 is the most prevalent MEASURED class but is NOT on the official
    # list — so an official #1 (CWE-79) is only measured-rank 2 here. CWE-999
    # is exploited but off-list, so it doesn't count toward KEV coverage.
    agg = _agg_with(
        cwe_year={2024: {"CWE-79": 50, "CWE-787": 40, "CWE-1234": 60},
                  2023: {"CWE-79": 30, "CWE-22": 10},
                  2019: {"CWE-89": 999}},           # outside the 2021-2025 window
        kev_cwe={"CWE-79": 5, "CWE-787": 3, "CWE-999": 2})
    obj = build_cwe_top25(agg, GENERATED_AT,
                          official_lists=cwe_top25_data.OFFICIAL,
                          window_years=5, min_n=1)
    contracts.validate("cwe_top25.json", obj)

    assert obj["official_year"] == 2024
    assert obj["official_years"] == [2023, 2024]
    assert obj["window"] == {"start": 2021, "end": 2025}
    assert obj["measured_total"] == 190      # 80 + 40 + 60 + 10; 2019 excluded
    assert obj["kev_total"] == 10            # off-list CWE-999 still in total

    by_cwe = {r["cwe"]: r for r in obj["ranks"]}
    assert by_cwe["CWE-79"]["official_rank"] == 1
    assert by_cwe["CWE-79"]["measured_rank"] == 1   # 80 is the top measured
    assert by_cwe["CWE-79"]["measured_n"] == 80
    assert by_cwe["CWE-79"]["kev_n"] == 5
    assert by_cwe["CWE-787"]["measured_rank"] == 3  # behind off-list CWE-1234
    assert by_cwe["CWE-22"]["measured_rank"] == 4
    # An official pick never observed in the window: null rank, zero counts.
    assert by_cwe["CWE-89"]["measured_rank"] is None
    assert by_cwe["CWE-89"]["measured_n"] == 0

    h = obj["headline"]
    assert h["official_top_cwe"] == "CWE-79"
    assert h["measured_top_cwe"] == "CWE-79"      # equals official #1 here
    assert h["in_measured_top25"] == 3            # only 79, 787, 22 observed
    assert h["outside_measured_top25"] == 22
    assert h["in_kev"] == 2                        # 79, 787 (999 is off-list)
    assert h["kev_coverage_pct"] == 80.0          # 8 of 10 KEV hits on-list


def test_ranks_cover_the_full_official_list_in_order():
    agg = _agg_with(cwe_year={2024: {"CWE-79": 5}}, kev_cwe={})
    obj = build_cwe_top25(agg, GENERATED_AT,
                          official_lists=cwe_top25_data.OFFICIAL, min_n=1)
    assert [r["official_rank"] for r in obj["ranks"]] == list(range(1, 26))
    assert [r["cwe"] for r in obj["ranks"]] == cwe_top25_data.OFFICIAL[2024]
    contracts.validate("cwe_top25.json", obj)


def test_min_n_gate_nulls_the_headline_but_keeps_the_board():
    agg = _agg_with(cwe_year={2024: {"CWE-79": 5}}, kev_cwe={"CWE-79": 1})
    obj = build_cwe_top25(agg, GENERATED_AT,
                          official_lists=cwe_top25_data.OFFICIAL,
                          min_n=1000)
    assert obj["measured_total"] == 5
    assert obj["headline"] is None            # 5 < 1000
    assert len(obj["ranks"]) == 25            # the official list is always known
    contracts.validate("cwe_top25.json", obj)


def test_measured_top_cwe_can_diverge_from_official_number_one():
    # The most common measured class (CWE-787) is NOT the official #1 (CWE-79).
    agg = _agg_with(cwe_year={2024: {"CWE-787": 100, "CWE-79": 10}}, kev_cwe={})
    obj = build_cwe_top25(agg, GENERATED_AT,
                          official_lists=cwe_top25_data.OFFICIAL, min_n=1)
    assert obj["headline"]["official_top_cwe"] == "CWE-79"
    assert obj["headline"]["measured_top_cwe"] == "CWE-787"


# ---------------------------------------------------------------------- e2e

def test_offline_pipeline_run_emits_valid_cwe_top25(tmp_path):
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    obj = json.loads((tmp_path / "cwe_top25.json").read_text(encoding="utf-8"))
    contracts.validate("cwe_top25.json", obj)

    # Static, clock-independent facts.
    assert obj["official_year"] == 2024
    assert obj["official_years"] == [2023, 2024]
    assert len(obj["ranks"]) == 25
    assert obj["ranks"][0]["cwe"] == "CWE-79"      # official rank 1

    # The window slides with the run clock; assert it relative to generated_at.
    gen_year = int(obj["generated_at"][:4])
    assert obj["window"] == {"start": gen_year - 5, "end": gen_year - 1}

    # The KEV cut is NOT windowed, so it is clock-independent: two fixture
    # KEV entries match a published corpus record carrying a CWE —
    # CVE-2023-0001 (CWE-787) and CVE-2023-0003 (CWE-79); both are on the
    # official 2024 list, so coverage is total.
    assert obj["kev_total"] == 2
    by_cwe = {r["cwe"]: r for r in obj["ranks"]}
    assert by_cwe["CWE-79"]["kev_n"] == 1
    assert by_cwe["CWE-787"]["kev_n"] == 1
    h = obj["headline"]
    assert h["in_kev"] == 2
    assert h["kev_coverage_pct"] == 100.0
    assert h["official_top_cwe"] == "CWE-79"

    meta = json.loads((tmp_path / "meta.json").read_text(encoding="utf-8"))
    contracts.validate("meta.json", meta)
    assert meta["sources"]["top25"] == {
        "fetched_at": meta["generated_at"], "official_year": 2024,
        "list_count": 2}
