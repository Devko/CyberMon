"""Contract for the Extortion Ledger output (extortion_ledger.json).

Same philosophy as pipeline/contracts.py — a hand-rolled stdlib validator
that fails loudly — kept in its own module so this stage lands without
touching the core contracts file (mirrors market/tier1/tier2_contracts).
The coordinator merges :data:`VALIDATORS` into the pipeline's dispatch;
failures raise the same :class:`pipeline.contracts.ContractViolation`.

The core module's private checking helpers are reused read-only.
"""
from __future__ import annotations

from typing import Any, Callable

from .contracts import (_check_generated_at, _check_int, _check_list,
                        _check_str, _fail, _get)

# Must match extortion_metrics.build_extortion_ledger(top_k=8). Hardcoded
# on purpose (tier2_contracts.MAX_TOP_CWES precedent): the contract states
# what the site may rely on, independently of the builder's default.
MAX_TOP_FAMILIES = 8

# Ransomwhere's unattributed bucket must never appear as a ranked family;
# it has its own slot in the payload. Mirrors fetch_ransomwhere.
UNATTRIBUTED_LABEL = "Unlabeled"

# CryptoLocker-era floor: no verified ransomware payment predates Bitcoin
# ransoms, so any year before this is parser breakage, not history.
MIN_YEAR = 2008

# One order of magnitude above the whole live ledger (~1e9 USD): a value
# beyond this is a unit error (satoshi summed as dollars), not revenue.
MAX_USD = 10**10


def _check_usd(v: Any, path: str) -> int:
    """USD amounts are non-negative integers (whole dollars)."""
    _check_int(v, path)
    if v > MAX_USD:
        _fail(path, f"USD amount {v} implausibly large (unit error?)")
    return v


def _check_year(v: Any, path: str) -> int:
    _check_int(v, path, minimum=MIN_YEAR)
    return v


def _validate_extortion_ledger(obj: Any) -> None:
    _check_generated_at(obj, "extortion_ledger")
    _check_int(_get(obj, "min_n", "extortion_ledger"),
               "extortion_ledger.min_n", minimum=1)

    # ---- revenue_by_quarter: contiguous, gap-filled quarters --------------
    quarters = _check_list(_get(obj, "revenue_by_quarter", "extortion_ledger"),
                           "extortion_ledger.revenue_by_quarter")
    if not quarters:
        _fail("extortion_ledger.revenue_by_quarter", "must not be empty")
    prev = None
    peak_usd = 0
    for i, row in enumerate(quarters):
        path = f"extortion_ledger.revenue_by_quarter[{i}]"
        year = _check_year(_get(row, "year", path), f"{path}.year")
        quarter = _get(row, "quarter", path)
        _check_int(quarter, f"{path}.quarter", minimum=1)
        if quarter > 4:
            _fail(f"{path}.quarter", f"quarter {quarter} outside 1-4")
        peak_usd = max(peak_usd, _check_usd(_get(row, "usd", path),
                                            f"{path}.usd"))
        if prev is not None:
            expected = (prev[0] + 1, 1) if prev[1] == 4 else \
                (prev[0], prev[1] + 1)
            if (year, quarter) != expected:
                _fail(path, f"quarters must be contiguous: expected "
                            f"{expected}, got {(year, quarter)}")
        prev = (year, quarter)

    # ---- payments_by_year --------------------------------------------------
    entries = _check_list(_get(obj, "payments_by_year", "extortion_ledger"),
                          "extortion_ledger.payments_by_year")
    if not entries:
        _fail("extortion_ledger.payments_by_year", "must not be empty")
    years = []
    for i, row in enumerate(entries):
        path = f"extortion_ledger.payments_by_year[{i}]"
        years.append(_check_year(_get(row, "year", path), f"{path}.year"))
        _check_int(_get(row, "payments", path), f"{path}.payments", minimum=1)
        _check_usd(_get(row, "usd", path), f"{path}.usd")
        # median_usd is present only for years with >= min_n payments —
        # absence means "not charted", never zero. Rounded to 2 decimals,
        # a documented exception to the 1-decimal float rule: early
        # mass-campaign years have sub-dollar medians ($0.03 in 2013).
        if "median_usd" in row:
            median = row["median_usd"]
            if isinstance(median, bool) or not isinstance(median,
                                                          (int, float)):
                _fail(f"{path}.median_usd",
                      f"expected number, got {median!r}")
            if not 0.0 <= median <= MAX_USD:
                _fail(f"{path}.median_usd",
                      f"number {median} outside range [0, {MAX_USD}]")
            if abs(median * 100 - round(median * 100)) > 1e-6:
                _fail(f"{path}.median_usd",
                      f"number {median} not rounded to 2 decimal places")
    if years != sorted(years) or len(set(years)) != len(years):
        _fail("extortion_ledger.payments_by_year",
              "years must be sorted ascending and unique")

    # ---- families ----------------------------------------------------------
    fams = _get(obj, "families", "extortion_ledger")
    top = _check_list(_get(fams, "top", "extortion_ledger.families"),
                      "extortion_ledger.families.top")
    if len(top) > MAX_TOP_FAMILIES:
        _fail("extortion_ledger.families.top",
              f"more than {MAX_TOP_FAMILIES} entries ({len(top)})")
    names = []
    prev_usd = None
    for i, row in enumerate(top):
        path = f"extortion_ledger.families.top[{i}]"
        name = _get(row, "family", path)
        _check_str(name, f"{path}.family")
        if name == UNATTRIBUTED_LABEL:
            _fail(f"{path}.family",
                  f"{UNATTRIBUTED_LABEL!r} is not a family and must not "
                  f"be ranked (it has its own 'unattributed' slot)")
        names.append(name)
        usd = _check_usd(_get(row, "usd", path), f"{path}.usd")
        if prev_usd is not None and usd > prev_usd:
            _fail("extortion_ledger.families.top",
                  "not sorted descending by usd")
        prev_usd = usd
        _check_int(_get(row, "payments", path), f"{path}.payments", minimum=1)
        first = _check_year(_get(row, "first_year", path), f"{path}.first_year")
        last = _check_year(_get(row, "last_year", path), f"{path}.last_year")
        if first > last:
            _fail(path, f"first_year ({first}) after last_year ({last})")
    if len(set(names)) != len(names):
        _fail("extortion_ledger.families.top", "duplicate family names")

    other = _get(fams, "other", "extortion_ledger.families")
    _check_int(_get(other, "families", "extortion_ledger.families.other"),
               "extortion_ledger.families.other.families")
    _check_usd(_get(other, "usd", "extortion_ledger.families.other"),
               "extortion_ledger.families.other.usd")
    _check_int(_get(other, "payments", "extortion_ledger.families.other"),
               "extortion_ledger.families.other.payments")

    unattributed = _get(fams, "unattributed", "extortion_ledger.families")
    _check_usd(_get(unattributed, "usd",
                    "extortion_ledger.families.unattributed"),
               "extortion_ledger.families.unattributed.usd")
    _check_int(_get(unattributed, "payments",
                    "extortion_ledger.families.unattributed"),
               "extortion_ledger.families.unattributed.payments")

    # ---- catalog (auditability block) --------------------------------------
    catalog = _get(obj, "catalog", "extortion_ledger")
    _check_int(_get(catalog, "addresses", "extortion_ledger.catalog"),
               "extortion_ledger.catalog.addresses", minimum=1)
    _check_int(_get(catalog, "families", "extortion_ledger.catalog"),
               "extortion_ledger.catalog.families")
    transactions = _get(catalog, "transactions", "extortion_ledger.catalog")
    _check_int(transactions, "extortion_ledger.catalog.transactions",
               minimum=1)
    pay_total = _get(catalog, "payments", "extortion_ledger.catalog")
    _check_int(pay_total, "extortion_ledger.catalog.payments", minimum=1)
    if pay_total > transactions:
        _fail("extortion_ledger.catalog.payments",
              f"payments ({pay_total}) exceed transactions ({transactions}) "
              f"— payments are collapsed transactions")
    total_usd = _check_usd(_get(catalog, "total_usd",
                                "extortion_ledger.catalog"),
                           "extortion_ledger.catalog.total_usd")

    # ---- headline -----------------------------------------------------------
    headline = _get(obj, "headline", "extortion_ledger")
    if _get(headline, "total_usd", "extortion_ledger.headline") != total_usd:
        _fail("extortion_ledger.headline.total_usd",
              "must equal catalog.total_usd")
    peak = _get(headline, "peak_quarter", "extortion_ledger.headline")
    _check_year(_get(peak, "year", "extortion_ledger.headline.peak_quarter"),
                "extortion_ledger.headline.peak_quarter.year")
    pq = _get(peak, "quarter", "extortion_ledger.headline.peak_quarter")
    _check_int(pq, "extortion_ledger.headline.peak_quarter.quarter", minimum=1)
    if pq > 4:
        _fail("extortion_ledger.headline.peak_quarter.quarter",
              f"quarter {pq} outside 1-4")
    peak_val = _check_usd(_get(peak, "usd",
                               "extortion_ledger.headline.peak_quarter"),
                          "extortion_ledger.headline.peak_quarter.usd")
    if peak_val != peak_usd:
        _fail("extortion_ledger.headline.peak_quarter.usd",
              f"peak usd {peak_val} does not match the series maximum "
              f"{peak_usd}")
    first = _check_year(_get(headline, "first_year",
                             "extortion_ledger.headline"),
                        "extortion_ledger.headline.first_year")
    last = _check_year(_get(headline, "last_year",
                            "extortion_ledger.headline"),
                       "extortion_ledger.headline.last_year")
    if first > last:
        _fail("extortion_ledger.headline",
              f"first_year ({first}) after last_year ({last})")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "extortion_ledger.json": _validate_extortion_ledger,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the Extortion Ledger contract.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no contract here.
    """
    VALIDATORS[filename](obj)
