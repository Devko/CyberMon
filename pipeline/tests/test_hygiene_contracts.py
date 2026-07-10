"""Hygiene contract: valid output passes; corruptions fail loudly."""
from __future__ import annotations

import copy

import pytest

from pipeline import contracts, hygiene_contracts, hygiene_metrics
from pipeline.contracts import ContractViolation

GENERATED_AT = "2026-07-09T00:00:00Z"


@pytest.fixture()
def obj() -> dict:
    built, _ = hygiene_metrics.run_stage(GENERATED_AT, offline_fixtures=True)
    return copy.deepcopy(built)


def test_valid_output_passes_both_dispatchers(obj):
    hygiene_contracts.validate("dnssec_adoption.json", obj)
    contracts.validate("dnssec_adoption.json", obj)  # registered centrally


def test_registered_in_core_dispatch():
    assert "dnssec_adoption.json" in contracts.VALIDATORS


def test_wrong_window_rejected(obj):
    obj["window"] = "1_day"
    with pytest.raises(ContractViolation, match="30_day"):
        hygiene_contracts.validate("dnssec_adoption.json", obj)


def test_empty_world_series_rejected(obj):
    obj["world"]["series"] = []
    with pytest.raises(ContractViolation, match="must not be empty"):
        hygiene_contracts.validate("dnssec_adoption.json", obj)


def test_unsorted_world_series_rejected(obj):
    obj["world"]["series"].reverse()
    with pytest.raises(ContractViolation, match="not sorted"):
        hygiene_contracts.validate("dnssec_adoption.json", obj)


def test_duplicate_months_rejected(obj):
    obj["world"]["series"].append(dict(obj["world"]["series"][-1]))
    with pytest.raises(ContractViolation, match="duplicate months"):
        hygiene_contracts.validate("dnssec_adoption.json", obj)


def test_unrounded_rate_rejected(obj):
    obj["world"]["series"][0]["validating_pc"] = 8.649
    with pytest.raises(ContractViolation, match="1 decimal"):
        hygiene_contracts.validate("dnssec_adoption.json", obj)


def test_rate_above_100_rejected(obj):
    obj["world"]["latest"]["validating_pc"] = 204.6
    with pytest.raises(ContractViolation, match="outside range"):
        hygiene_contracts.validate("dnssec_adoption.json", obj)


def test_latest_outside_newest_month_rejected(obj):
    obj["world"]["latest"]["date"] = "1999-01-01"
    with pytest.raises(ContractViolation, match="newest month"):
        hygiene_contracts.validate("dnssec_adoption.json", obj)


def test_baseline_month_must_be_charted(obj):
    obj["world"]["baseline"]["month"] = "1999-01"
    with pytest.raises(ContractViolation, match="series months"):
        hygiene_contracts.validate("dnssec_adoption.json", obj)


def test_economies_must_rank_by_current_rate(obj):
    obj["economies"].reverse()
    with pytest.raises(ContractViolation, match="not sorted descending"):
        hygiene_contracts.validate("dnssec_adoption.json", obj)


def test_duplicate_economy_codes_rejected(obj):
    obj["economies"].insert(0, copy.deepcopy(obj["economies"][0]))
    with pytest.raises(ContractViolation, match="duplicate economy codes"):
        hygiene_contracts.validate("dnssec_adoption.json", obj)


def test_more_than_ten_economies_rejected(obj):
    template = obj["economies"][-1]  # lowest rate: appending keeps the sort
    for i in range(11):
        clone = copy.deepcopy(template)
        clone["cc"] = f"Z{chr(ord('A') + i)}"
        obj["economies"].append(clone)
    with pytest.raises(ContractViolation, match="more than 10"):
        hygiene_contracts.validate("dnssec_adoption.json", obj)


def test_spread_bucket_enum_is_fixed(obj):
    obj["spread"]["buckets"][0]["bucket"] = "0-10%"
    with pytest.raises(ContractViolation, match="bucket labels"):
        hygiene_contracts.validate("dnssec_adoption.json", obj)


def test_spread_bucket_order_is_fixed(obj):
    obj["spread"]["buckets"].reverse()
    with pytest.raises(ContractViolation, match="bucket labels"):
        hygiene_contracts.validate("dnssec_adoption.json", obj)


def test_spread_counts_must_sum_to_total(obj):
    obj["spread"]["n_economies"] += 1
    with pytest.raises(ContractViolation, match="sum to"):
        hygiene_contracts.validate("dnssec_adoption.json", obj)


# ------------------------------------------------------- meta.sources.apnic

def test_meta_apnic_optional_but_checked_when_present(outputs):
    ok = copy.deepcopy(outputs["meta.json"])
    contracts.validate("meta.json", ok)  # absent: fine (older meta files)

    ok["sources"]["apnic"] = {"fetched_at": GENERATED_AT, "economy_count": 10,
                              "spread_economy_count": 203}
    contracts.validate("meta.json", ok)

    bad = copy.deepcopy(ok)
    bad["sources"]["apnic"] = {"fetched_at": "last tuesday"}
    with pytest.raises(ContractViolation, match="apnic"):
        contracts.validate("meta.json", bad)
