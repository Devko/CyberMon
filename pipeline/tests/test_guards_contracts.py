"""Security Products contract: valid fixture output passes; corruptions
fail loudly (test_tier1_contracts' pattern)."""
from __future__ import annotations

import copy

import pytest

from pipeline import contracts, guards_contracts
from pipeline.contracts import ContractViolation

NAME = "kev_guards.json"


def _corrupt(outputs):
    return copy.deepcopy(outputs[NAME])


def test_valid_output_passes_both_dispatchers(outputs):
    guards_contracts.validate(NAME, outputs[NAME])
    contracts.validate(NAME, outputs[NAME])  # registered centrally


def test_guards_validator_registered_in_core_dispatch():
    assert NAME in contracts.VALIDATORS


def test_security_above_total_rejected(outputs):
    obj = _corrupt(outputs)
    obj["years"][0]["security"] = obj["years"][0]["total"] + 1
    with pytest.raises(ContractViolation, match="exceeds total"):
        guards_contracts.validate(NAME, obj)


def test_unsorted_years_rejected(outputs):
    obj = _corrupt(outputs)
    obj["years"].reverse()
    with pytest.raises(ContractViolation, match="sorted and unique"):
        guards_contracts.validate(NAME, obj)


def test_board_sorted_by_entries_descending(outputs):
    obj = _corrupt(outputs)
    obj["vendors"].sort(key=lambda v: v["entries"])  # ascending = wrong
    with pytest.raises(ContractViolation, match="entries descending"):
        guards_contracts.validate(NAME, obj)


def test_duplicate_vendor_rejected(outputs):
    obj = _corrupt(outputs)
    obj["vendors"].insert(0, dict(obj["vendors"][0]))
    with pytest.raises(ContractViolation, match="duplicate vendor"):
        guards_contracts.validate(NAME, obj)


def test_first_after_last_rejected(outputs):
    obj = _corrupt(outputs)
    obj["vendors"][0]["first_added"] = "2030-01-01"
    with pytest.raises(ContractViolation, match="after last_added"):
        guards_contracts.validate(NAME, obj)


def test_missing_gap_for_multi_entry_vendor_rejected(outputs):
    obj = _corrupt(outputs)
    multi = next(v for v in obj["vendors"] if v["entries"] >= 2)
    multi["median_gap_days"] = None
    with pytest.raises(ContractViolation, match="no median gap"):
        guards_contracts.validate(NAME, obj)


def test_ransomware_split_must_cover_catalog(outputs):
    obj = _corrupt(outputs)
    obj["ransomware"]["other"]["total"] += 1
    with pytest.raises(ContractViolation, match="catalog total"):
        guards_contracts.validate(NAME, obj)


def test_unrounded_pct_rejected(outputs):
    obj = _corrupt(outputs)
    obj["catalog"]["pct_security"] = 42.857
    with pytest.raises(ContractViolation, match="1 decimal"):
        guards_contracts.validate(NAME, obj)


def test_missing_classifier_version_rejected(outputs):
    obj = _corrupt(outputs)
    del obj["catalog"]["classifier_version"]
    with pytest.raises(ContractViolation, match="classifier_version"):
        guards_contracts.validate(NAME, obj)
