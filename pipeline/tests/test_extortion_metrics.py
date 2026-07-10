"""Unit tests for the Extortion Ledger stage: fetch_ransomwhere parsing
(fail-loud) and extortion_metrics builder semantics."""
from __future__ import annotations

import pytest

from pipeline.extortion_metrics import build_extortion_ledger
from pipeline.fetch_ransomwhere import (RansomwhereData, parse_ransomwhere)

GENERATED_AT = "2026-07-09T00:00:00Z"


# ------------------------------------------------------------ fetch/parsing

def _doc(records):
    return {"result": records}


def _record(**overrides):
    base = {
        "address": "1Addr", "balance": 0, "balanceUSD": 0.0,
        "blockchain": "bitcoin", "family": "Fam",
        "createdAt": "2024-01-01T00:00:00.000Z",
        "updatedAt": "2024-01-01T00:00:00.000Z",
        "transactions": [{"hash": "h", "time": 1716192000,
                          "amount": 100, "amountUSD": 1.0}],
    }
    base.update(overrides)
    return base


def test_parse_counts_addresses_and_transactions():
    data = parse_ransomwhere(_doc([_record(), _record(address="1Other",
                                                      transactions=[])]))
    assert data.address_count == 2
    assert data.tx_count == 1
    assert data.records[0].transactions[0].amount_usd == 1.0


def test_parse_fails_loud_on_missing_result():
    with pytest.raises(ValueError, match="result"):
        parse_ransomwhere({"nope": []})


def test_parse_fails_loud_on_empty_export():
    with pytest.raises(ValueError, match="no address records"):
        parse_ransomwhere(_doc([]))


@pytest.mark.parametrize("field,value", [
    ("address", ""), ("family", "  "), ("blockchain", None),
    ("transactions", "not-a-list"),
])
def test_parse_fails_loud_on_malformed_record(field, value):
    with pytest.raises(ValueError, match="ransomwhere"):
        parse_ransomwhere(_doc([_record(**{field: value})]))


@pytest.mark.parametrize("tx", [
    {"hash": "", "time": 1, "amount": 1, "amountUSD": 1.0},
    {"hash": "h", "time": 0, "amount": 1, "amountUSD": 1.0},
    {"hash": "h", "time": 1, "amount": -1, "amountUSD": 1.0},
    {"hash": "h", "time": 1, "amount": 1, "amountUSD": -0.5},
    {"hash": "h", "time": 1, "amount": 1},  # missing amountUSD
])
def test_parse_fails_loud_on_malformed_transaction(tx):
    with pytest.raises(ValueError, match="ransomwhere"):
        parse_ransomwhere(_doc([_record(transactions=[tx])]))


# ---------------------------------------------------------------- metrics

def test_ledger_from_fixture_exact_numbers(ransomwhere):
    ledger = build_extortion_ledger(ransomwhere, GENERATED_AT, min_n=1)

    # Catalog: 6 addresses (one with zero transactions), 2 labeled families
    # (Unlabeled is not a family), 8 ledger entries, 7 distinct payments
    # (one hash pays two DemoLocker addresses), $121,000 as published.
    assert ledger["catalog"] == {"addresses": 6, "families": 2,
                                 "transactions": 8, "payments": 7,
                                 "total_usd": 121000}

    # Hero: contiguous, gap-filled quarters 2022Q1..2026Q1 (17 rows).
    quarters = ledger["revenue_by_quarter"]
    assert quarters[0] == {"year": 2022, "quarter": 1, "usd": 800}
    assert quarters[-1] == {"year": 2026, "quarter": 1, "usd": 7000}
    assert len(quarters) == 17
    assert sum(q["usd"] for q in quarters) == 121000
    by_q = {(q["year"], q["quarter"]): q["usd"] for q in quarters}
    assert by_q[(2022, 3)] == 50000
    assert by_q[(2022, 4)] == 0  # gap-filled, not skipped
    assert by_q[(2024, 2)] == 30000

    # Payments: per distinct hash; the 2026 multi-output payment is ONE
    # payment of $7,000 (5,000 + 2,000), not two.
    assert ledger["payments_by_year"] == [
        {"year": 2022, "payments": 2, "usd": 50800, "median_usd": 25400.0},
        {"year": 2023, "payments": 1, "usd": 1200, "median_usd": 1200.0},
        {"year": 2024, "payments": 2, "usd": 50000, "median_usd": 25000.0},
        {"year": 2025, "payments": 1, "usd": 12000, "median_usd": 12000.0},
        {"year": 2026, "payments": 1, "usd": 7000, "median_usd": 7000.0},
    ]

    # Families: ranked by all-time USD, Unlabeled reported separately.
    assert ledger["families"]["top"] == [
        {"family": "DemoLocker", "usd": 58200, "payments": 4,
         "first_year": 2023, "last_year": 2026},
        {"family": "PetitEncrypt", "usd": 12800, "payments": 2,
         "first_year": 2022, "last_year": 2025},
    ]
    assert ledger["families"]["other"] == {"families": 0, "usd": 0,
                                           "payments": 0}
    assert ledger["families"]["unattributed"] == {"usd": 50000, "payments": 1}

    assert ledger["headline"] == {
        "total_usd": 121000,
        "peak_quarter": {"year": 2022, "quarter": 3, "usd": 50000},
        "first_year": 2022, "last_year": 2026,
    }


def test_median_absent_below_min_n(ransomwhere):
    ledger = build_extortion_ledger(ransomwhere, GENERATED_AT, min_n=2)
    rows = {r["year"]: r for r in ledger["payments_by_year"]}
    assert "median_usd" in rows[2022] and "median_usd" in rows[2024]
    for year in (2023, 2025, 2026):
        assert "median_usd" not in rows[year]  # absent, never null/zero


def test_top_k_overflow_pools_into_other(ransomwhere):
    ledger = build_extortion_ledger(ransomwhere, GENERATED_AT,
                                    min_n=1, top_k=1)
    assert [f["family"] for f in ledger["families"]["top"]] == ["DemoLocker"]
    assert ledger["families"]["other"] == {"families": 1, "usd": 12800,
                                           "payments": 2}


def test_empty_ledger_refuses_to_emit():
    data = RansomwhereData(address_count=1, tx_count=0, records=[])
    with pytest.raises(ValueError, match="no transactions"):
        build_extortion_ledger(data, GENERATED_AT)


def test_no_projection_key_ever(ransomwhere):
    # Deliberate: crowdsourced reporting lag breaks the uniform-flow
    # assumption behind pace projections (see module docstring).
    ledger = build_extortion_ledger(ransomwhere, GENERATED_AT, min_n=1)
    assert "projection" not in ledger
