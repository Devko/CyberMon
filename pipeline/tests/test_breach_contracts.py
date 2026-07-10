"""breach_ledger.json contract: the validator must catch every shape
drift the site would otherwise render as nonsense."""
from __future__ import annotations

import copy

import pytest

from pipeline import breach_metrics, contracts
from pipeline.contracts import ContractViolation

from .conftest import GENERATED_AT


@pytest.fixture()
def ledger(hibp) -> dict:
    return breach_metrics.build_breach_ledger(hibp.breaches, GENERATED_AT,
                                              min_n=1)


def _expect_violation(obj: dict) -> None:
    with pytest.raises(ContractViolation):
        contracts.validate("breach_ledger.json", obj)


def test_fixture_build_passes_and_is_registered(ledger):
    contracts.validate("breach_ledger.json", ledger)  # no raise


def test_catalog_arithmetic_must_sum(ledger):
    bad = copy.deepcopy(ledger)
    bad["catalog"]["cohort"] += 1
    _expect_violation(bad)


def test_catalog_excluded_keys_are_fixed(ledger):
    bad = copy.deepcopy(ledger)
    del bad["catalog"]["excluded"]["malware"]
    _expect_violation(bad)
    bad = copy.deepcopy(ledger)
    bad["catalog"]["excluded"]["retired"] = 0
    _expect_violation(bad)


def test_import_era_cutoff_is_pinned(ledger):
    bad = copy.deepcopy(ledger)
    bad["import_era"]["added_before"] = "2015-01-01"
    _expect_violation(bad)


def test_import_era_median_null_iff_empty(ledger):
    bad = copy.deepcopy(ledger)
    bad["import_era"].update(n=0, median_days=0.0)
    _expect_violation(bad)
    ok = copy.deepcopy(ledger)
    ok["import_era"].update(n=0, median_days=None)
    contracts.validate("breach_ledger.json", ok)


def test_negative_lag_medians_are_legal(ledger):
    # The fixture's 2025 median is -8.0; the validator must accept it.
    assert any(r["median_days"] < 0 for r in ledger["lag_by_year"])
    contracts.validate("breach_ledger.json", ledger)


def test_lag_years_sorted_unique(ledger):
    bad = copy.deepcopy(ledger)
    bad["lag_by_year"] = list(reversed(bad["lag_by_year"]))
    _expect_violation(bad)
    bad = copy.deepcopy(ledger)
    bad["lag_by_year"].append(copy.deepcopy(bad["lag_by_year"][-1]))
    _expect_violation(bad)


def test_volume_year_needs_at_least_one_breach(ledger):
    bad = copy.deepcopy(ledger)
    bad["volume_by_year"][0]["breaches"] = 0
    _expect_violation(bad)


def test_class_shares_keys_must_match_classes(ledger):
    bad = copy.deepcopy(ledger)
    bad["class_shares"]["years"][0]["shares"]["Bank cards"] = 1.0
    _expect_violation(bad)
    bad = copy.deepcopy(ledger)
    first = bad["class_shares"]["classes"][0]
    del bad["class_shares"]["years"][0]["shares"][first]
    _expect_violation(bad)


def test_class_list_capped_and_unique(ledger):
    bad = copy.deepcopy(ledger)
    bad["class_shares"]["classes"] = [f"c{i}" for i in range(7)]
    bad["class_shares"]["years"] = []
    _expect_violation(bad)
    bad["class_shares"]["classes"] = ["dup", "dup"]
    _expect_violation(bad)


def test_headline_latest_year_zero_or_trend_era(ledger):
    ok = copy.deepcopy(ledger)
    ok["headline"].update(latest_year=0, median_days_latest=0.0)
    contracts.validate("breach_ledger.json", ok)
    bad = copy.deepcopy(ledger)
    bad["headline"]["latest_year"] = 2013  # import era can never headline
    _expect_violation(bad)


def test_projection_must_target_generation_year(ledger):
    bad = copy.deepcopy(ledger)
    bad["projection"] = {"year": 2025, "breaches": 100, "elapsed": 0.5}
    _expect_violation(bad)
    ok = copy.deepcopy(ledger)
    ok["projection"] = {"year": 2026, "breaches": 100, "elapsed": 0.521}
    contracts.validate("breach_ledger.json", ok)
