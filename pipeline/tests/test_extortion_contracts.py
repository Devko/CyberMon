"""Contract tests for extortion_ledger.json and the additive
meta.sources.ransomwhere extension: real outputs pass, malformed fail."""
from __future__ import annotations

import copy

import pytest

from pipeline import contracts
from pipeline.contracts import ContractViolation


def _ledger(outputs):
    return copy.deepcopy(outputs["extortion_ledger.json"])


def test_built_ledger_validates(outputs):
    contracts.validate("extortion_ledger.json",
                       outputs["extortion_ledger.json"])


def test_quarter_gap_rejected(outputs):
    bad = _ledger(outputs)
    del bad["revenue_by_quarter"][1]  # tear a hole in the quarter series
    with pytest.raises(ContractViolation, match="contiguous"):
        contracts.validate("extortion_ledger.json", bad)


def test_unlabeled_ranked_as_family_rejected(outputs):
    bad = _ledger(outputs)
    bad["families"]["top"][0]["family"] = "Unlabeled"
    with pytest.raises(ContractViolation, match="Unlabeled"):
        contracts.validate("extortion_ledger.json", bad)


def test_family_board_sort_enforced(outputs):
    bad = _ledger(outputs)
    bad["families"]["top"].reverse()
    with pytest.raises(ContractViolation, match="descending"):
        contracts.validate("extortion_ledger.json", bad)


def test_payments_exceeding_transactions_rejected(outputs):
    bad = _ledger(outputs)
    bad["catalog"]["payments"] = bad["catalog"]["transactions"] + 1
    with pytest.raises(ContractViolation, match="exceed transactions"):
        contracts.validate("extortion_ledger.json", bad)


def test_headline_total_must_match_catalog(outputs):
    bad = _ledger(outputs)
    bad["headline"]["total_usd"] += 1
    with pytest.raises(ContractViolation, match="catalog.total_usd"):
        contracts.validate("extortion_ledger.json", bad)


def test_peak_quarter_must_match_series_maximum(outputs):
    bad = _ledger(outputs)
    bad["headline"]["peak_quarter"]["usd"] += 1
    with pytest.raises(ContractViolation, match="series maximum"):
        contracts.validate("extortion_ledger.json", bad)


def test_median_beyond_two_decimals_rejected(outputs):
    bad = _ledger(outputs)
    bad["payments_by_year"][0]["median_usd"] = 25400.033
    with pytest.raises(ContractViolation, match="2 decimal"):
        contracts.validate("extortion_ledger.json", bad)


def test_sub_dollar_median_accepted(outputs):
    ok = _ledger(outputs)
    ok["payments_by_year"][0]["median_usd"] = 0.03  # 2013-era reality
    contracts.validate("extortion_ledger.json", ok)


def test_implausible_usd_rejected(outputs):
    bad = _ledger(outputs)
    bad["revenue_by_quarter"][0]["usd"] = 10**11  # satoshi-as-dollars error
    with pytest.raises(ContractViolation, match="implausibly large"):
        contracts.validate("extortion_ledger.json", bad)


def test_prehistoric_year_rejected(outputs):
    bad = _ledger(outputs)
    bad["payments_by_year"][0]["year"] = 1999  # predates Bitcoin ransoms
    with pytest.raises(ContractViolation, match="below minimum"):
        contracts.validate("extortion_ledger.json", bad)


def test_meta_ransomwhere_optional_but_checked_when_present(outputs):
    ok = copy.deepcopy(outputs["meta.json"])
    ok["sources"]["ransomwhere"] = {"fetched_at": "2026-07-09T00:00:00Z",
                                    "address_count": 6, "tx_count": 8}
    contracts.validate("meta.json", ok)

    del ok["sources"]["ransomwhere"]
    contracts.validate("meta.json", ok)  # optional: absence is legal

    bad = copy.deepcopy(outputs["meta.json"])
    bad["sources"]["ransomwhere"] = {"fetched_at": "recently",
                                     "address_count": 6, "tx_count": 8}
    with pytest.raises(ContractViolation, match="fetched_at"):
        contracts.validate("meta.json", bad)
