"""Tier-1 contracts: valid fixture outputs pass; corruptions fail loudly."""
from __future__ import annotations

import copy

import pytest

from pipeline import contracts, tier1_contracts
from pipeline.contracts import ContractViolation


def _corrupt(outputs, name):
    return copy.deepcopy(outputs[name])


# ----------------------------------------------------------------- dispatch

def test_valid_outputs_pass_both_dispatchers(outputs):
    for name in ("kev_latency.json", "cna_concentration.json"):
        tier1_contracts.validate(name, outputs[name])
        contracts.validate(name, outputs[name])  # registered centrally


def test_tier1_validators_registered_in_core_dispatch():
    assert "kev_latency.json" in contracts.VALIDATORS
    assert "cna_concentration.json" in contracts.VALIDATORS


# -------------------------------------------------------------- kev_latency

def test_bad_bucket_label_rejected(outputs):
    obj = _corrupt(outputs, "kev_latency.json")
    obj["latency_buckets"][1]["bucket"] = "0-7"  # label drift
    with pytest.raises(ContractViolation, match="bucket labels"):
        tier1_contracts.validate("kev_latency.json", obj)


def test_bucket_order_is_fixed(outputs):
    obj = _corrupt(outputs, "kev_latency.json")
    obj["latency_buckets"].reverse()
    with pytest.raises(ContractViolation, match="bucket labels"):
        tier1_contracts.validate("kev_latency.json", obj)


def test_missing_bucket_rejected(outputs):
    obj = _corrupt(outputs, "kev_latency.json")
    del obj["latency_buckets"][0]  # all 7 must always be present
    with pytest.raises(ContractViolation, match="bucket labels"):
        tier1_contracts.validate("kev_latency.json", obj)


def test_unsorted_latency_years_rejected(outputs):
    obj = _corrupt(outputs, "kev_latency.json")
    obj["latency_by_year"].reverse()
    with pytest.raises(ContractViolation, match="not sorted"):
        tier1_contracts.validate("kev_latency.json", obj)


def test_inconsistent_matched_counts_rejected(outputs):
    obj = _corrupt(outputs, "kev_latency.json")
    obj["matched"]["matched_cve"] += 1
    with pytest.raises(ContractViolation, match="total_kev"):
        tier1_contracts.validate("kev_latency.json", obj)


def test_empty_backfill_median_must_be_null_not_zero(outputs):
    obj = _corrupt(outputs, "kev_latency.json")
    obj["launch_backfill"]["n"] = 0
    obj["launch_backfill"]["median_days"] = 0.0  # a fabricated median
    with pytest.raises(ContractViolation, match="null when n == 0"):
        tier1_contracts.validate("kev_latency.json", obj)


def test_empty_backfill_with_null_median_passes(outputs):
    obj = _corrupt(outputs, "kev_latency.json")
    obj["launch_backfill"]["n"] = 0
    obj["launch_backfill"]["median_days"] = None
    tier1_contracts.validate("kev_latency.json", obj)


def test_nonempty_backfill_median_must_be_a_number(outputs):
    obj = _corrupt(outputs, "kev_latency.json")
    assert obj["launch_backfill"]["n"] > 0
    obj["launch_backfill"]["median_days"] = None
    with pytest.raises(ContractViolation):
        tier1_contracts.validate("kev_latency.json", obj)


def test_wrong_launch_cutoff_rejected(outputs):
    obj = _corrupt(outputs, "kev_latency.json")
    obj["launch_backfill"]["date_added_before"] = "2021-11-03"
    with pytest.raises(ContractViolation, match="2023-01-01"):
        tier1_contracts.validate("kev_latency.json", obj)


def test_unrounded_pct_rejected(outputs):
    obj = _corrupt(outputs, "kev_latency.json")
    obj["latency_by_year"][0]["pct_negative"] = 12.34
    with pytest.raises(ContractViolation, match="not rounded"):
        tier1_contracts.validate("kev_latency.json", obj)


def test_negative_latency_median_is_legal(outputs):
    # negative medians are real signal, the contract must not floor them
    obj = _corrupt(outputs, "kev_latency.json")
    assert any(r["median_days"] < 0 for r in obj["latency_by_year"])
    tier1_contracts.validate("kev_latency.json", obj)


def test_pct_over_100_rejected(outputs):
    obj = _corrupt(outputs, "kev_latency.json")
    obj["latency_buckets"][0]["pct"] = 100.1
    with pytest.raises(ContractViolation, match="outside range"):
        tier1_contracts.validate("kev_latency.json", obj)


# -------------------------------------------------------- cna_concentration

def test_unsorted_concentration_years_rejected(outputs):
    obj = _corrupt(outputs, "cna_concentration.json")
    obj["years"].reverse()
    with pytest.raises(ContractViolation, match="not sorted"):
        tier1_contracts.validate("cna_concentration.json", obj)


def test_hhi_above_10000_rejected(outputs):
    obj = _corrupt(outputs, "cna_concentration.json")
    obj["years"][0]["hhi"] = 10000.1
    with pytest.raises(ContractViolation, match="outside range"):
        tier1_contracts.validate("cna_concentration.json", obj)


def test_hhi_10000_exactly_is_legal(outputs):
    # the documented exception to the 0-100 rule: HHI scales to 10000
    obj = _corrupt(outputs, "cna_concentration.json")
    assert any(r["hhi"] == 10000.0 for r in obj["years"])
    tier1_contracts.validate("cna_concentration.json", obj)


def test_unrounded_hhi_rejected(outputs):
    obj = _corrupt(outputs, "cna_concentration.json")
    obj["years"][0]["hhi"] = 5555.55
    with pytest.raises(ContractViolation, match="not rounded"):
        tier1_contracts.validate("cna_concentration.json", obj)


def test_newcomers_exceeding_cna_count_rejected(outputs):
    obj = _corrupt(outputs, "cna_concentration.json")
    row = obj["years"][0]
    row["newcomer_count"] = row["cna_count"] + 1
    with pytest.raises(ContractViolation, match="exceeds"):
        tier1_contracts.validate("cna_concentration.json", obj)


def test_leaderboard_rejected_exceeding_total_rejected(outputs):
    obj = _corrupt(outputs, "cna_concentration.json")
    row = obj["rejection_leaderboard"]["cnas"][0]
    row["rejected"] = row["total"] + 1
    with pytest.raises(ContractViolation, match="exceeds"):
        tier1_contracts.validate("cna_concentration.json", obj)


def test_leaderboard_sort_order_enforced(outputs):
    obj = _corrupt(outputs, "cna_concentration.json")
    obj["rejection_leaderboard"]["cnas"].reverse()
    with pytest.raises(ContractViolation, match="not sorted"):
        tier1_contracts.validate("cna_concentration.json", obj)


def test_headline_missing_key_rejected(outputs):
    for name, key in (("kev_latency.json", "median_days_latest"),
                      ("cna_concentration.json", "hhi_latest")):
        obj = _corrupt(outputs, name)
        del obj["headline"][key]
        with pytest.raises(ContractViolation, match="missing required key"):
            tier1_contracts.validate(name, obj)
