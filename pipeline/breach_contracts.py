"""Contract for the Breach Ledger module output (breach_ledger.json).

Same philosophy as pipeline/contracts.py — hand-rolled stdlib validators
that fail loudly — kept in its own module so this stage lands without
touching the core contracts file (mirrors market_contracts,
tier1_contracts and tier2_contracts). The coordinator merges
:data:`VALIDATORS` into the pipeline's dispatch; failures raise the same
:class:`pipeline.contracts.ContractViolation` type.

The core module's private checking helpers are reused read-only.
"""
from __future__ import annotations

from typing import Any, Callable

from .contracts import (DATE_RE, _check_generated_at, _check_int,
                        _check_list, _check_num, _check_pace_projection,
                        _check_sorted, _check_str, _fail, _get)

# Must match breach_metrics.IMPORT_CUTOFF / EXCLUSION_REASONS /
# TOP_CLASSES. Hardcoded here on purpose (as tier1_contracts hardcodes
# LAUNCH_CUTOFF): the contract states what the site may rely on,
# independently of the builder's constants.
IMPORT_CUTOFF = "2014-01-01"
EXCLUSION_REASONS = ["fabricated", "spam_list", "malware", "stealer_log"]
MAX_TOP_CLASSES = 6
# Lag stats are bounded generously (~135 years); a lag may be
# legitimately negative (a breach catalogued before its self-reported,
# usually month-rounded, breach date).
_DAYS_LO, _DAYS_HI = -50000.0, 50000.0
# Catalog-year floor: HIBP launched December 2013.
_MIN_ADDED_YEAR = 2013


def _check_years_sorted_unique(years: list[int], path: str) -> None:
    _check_sorted(years, path)
    if len(set(years)) != len(years):
        _fail(path, "duplicate years")


def _validate_breach_ledger(obj: Any) -> None:
    _check_generated_at(obj, "breach_ledger")
    _check_int(_get(obj, "min_n", "breach_ledger"),
               "breach_ledger.min_n", minimum=1)

    # ---- catalog block: the cohort must be auditable to the last entry --
    catalog = _get(obj, "catalog", "breach_ledger")
    total = _get(catalog, "total", "breach_ledger.catalog")
    _check_int(total, "breach_ledger.catalog.total")
    cohort = _get(catalog, "cohort", "breach_ledger.catalog")
    _check_int(cohort, "breach_ledger.catalog.cohort")
    excluded = _get(catalog, "excluded", "breach_ledger.catalog")
    if not isinstance(excluded, dict) or \
            sorted(excluded) != sorted(EXCLUSION_REASONS):
        _fail("breach_ledger.catalog.excluded",
              f"keys must be exactly {EXCLUSION_REASONS}; "
              f"got {sorted(excluded) if isinstance(excluded, dict) else excluded!r}")
    for reason in EXCLUSION_REASONS:
        _check_int(excluded[reason], f"breach_ledger.catalog.excluded.{reason}")
    if cohort + sum(excluded.values()) != total:
        _fail("breach_ledger.catalog",
              f"cohort ({cohort}) + excluded ({sum(excluded.values())}) "
              f"!= total ({total})")

    # ---- import era (mirrors kev_latency.launch_backfill) ---------------
    era = _get(obj, "import_era", "breach_ledger")
    added_before = _get(era, "added_before", "breach_ledger.import_era")
    _check_str(added_before, "breach_ledger.import_era.added_before", DATE_RE)
    if added_before != IMPORT_CUTOFF:
        _fail("breach_ledger.import_era.added_before",
              f"must equal {IMPORT_CUTOFF!r}, got {added_before!r}")
    n = _get(era, "n", "breach_ledger.import_era")
    _check_int(n, "breach_ledger.import_era.n")
    median = _get(era, "median_days", "breach_ledger.import_era")
    if n == 0:
        if median is not None:  # an empty cohort has no median, not 0.0
            _fail("breach_ledger.import_era.median_days",
                  f"must be null when n == 0, got {median!r}")
    else:
        _check_num(median, "breach_ledger.import_era.median_days",
                   _DAYS_LO, _DAYS_HI)

    # ---- hero: lag by catalog year --------------------------------------
    entries = _check_list(_get(obj, "lag_by_year", "breach_ledger"),
                          "breach_ledger.lag_by_year")
    years = []
    for i, e in enumerate(entries):
        path = f"breach_ledger.lag_by_year[{i}]"
        year = _get(e, "year", path)
        # Trend years start at the import cutoff by construction.
        _check_int(year, f"{path}.year", minimum=2014)
        years.append(year)
        _check_int(_get(e, "n", path), f"{path}.n", minimum=1)
        for key in ("median_days", "p25_days", "p75_days"):
            _check_num(_get(e, key, path), f"{path}.{key}",
                       _DAYS_LO, _DAYS_HI)
        for key in ("pct_negative", "pct_over_365d"):
            _check_num(_get(e, key, path), f"{path}.{key}", 0.0, 100.0)
    _check_years_sorted_unique(years, "breach_ledger.lag_by_year")

    # ---- volume: breaches + records per catalog year (unfiltered) -------
    entries = _check_list(_get(obj, "volume_by_year", "breach_ledger"),
                          "breach_ledger.volume_by_year")
    years = []
    for i, e in enumerate(entries):
        path = f"breach_ledger.volume_by_year[{i}]"
        year = _get(e, "year", path)
        _check_int(year, f"{path}.year", minimum=_MIN_ADDED_YEAR)
        years.append(year)
        # A volume year exists only because >= 1 breach was catalogued.
        _check_int(_get(e, "breaches", path), f"{path}.breaches", minimum=1)
        _check_int(_get(e, "records", path), f"{path}.records")
    _check_years_sorted_unique(years, "breach_ledger.volume_by_year")

    # ---- what leaks: top-class shares per catalog year -------------------
    shares_obj = _get(obj, "class_shares", "breach_ledger")
    classes = _check_list(_get(shares_obj, "classes",
                               "breach_ledger.class_shares"),
                          "breach_ledger.class_shares.classes")
    if not 1 <= len(classes) <= MAX_TOP_CLASSES:
        _fail("breach_ledger.class_shares.classes",
              f"expected 1..{MAX_TOP_CLASSES} classes, got {len(classes)}")
    for i, name in enumerate(classes):
        _check_str(name, f"breach_ledger.class_shares.classes[{i}]")
    if len(set(classes)) != len(classes):
        _fail("breach_ledger.class_shares.classes", "duplicate classes")
    expected_keys = set(classes)

    entries = _check_list(_get(shares_obj, "years",
                               "breach_ledger.class_shares"),
                          "breach_ledger.class_shares.years")
    years = []
    for i, e in enumerate(entries):
        path = f"breach_ledger.class_shares.years[{i}]"
        year = _get(e, "year", path)
        _check_int(year, f"{path}.year", minimum=_MIN_ADDED_YEAR)
        years.append(year)
        _check_int(_get(e, "n", path), f"{path}.n", minimum=1)
        shares = _get(e, "shares", path)
        if not isinstance(shares, dict):
            _fail(f"{path}.shares", "expected object")
        if set(shares) != expected_keys:
            _fail(f"{path}.shares",
                  f"keys must be exactly the emitted classes; "
                  f"got {sorted(shares)}")
        for key, val in shares.items():
            _check_num(val, f"{path}.shares[{key}]", 0.0, 100.0)
    _check_years_sorted_unique(years, "breach_ledger.class_shares.years")

    # ---- headline ---------------------------------------------------------
    headline = _get(obj, "headline", "breach_ledger")
    _check_int(_get(headline, "trend_n", "breach_ledger.headline"),
               "breach_ledger.headline.trend_n")
    for key in ("median_days", "median_days_latest"):
        _check_num(_get(headline, key, "breach_ledger.headline"),
                   f"breach_ledger.headline.{key}", _DAYS_LO, _DAYS_HI)
    _check_num(_get(headline, "pct_over_365d", "breach_ledger.headline"),
               "breach_ledger.headline.pct_over_365d", 0.0, 100.0)
    latest_year = _get(headline, "latest_year", "breach_ledger.headline")
    _check_int(latest_year, "breach_ledger.headline.latest_year")
    if latest_year != 0 and latest_year < 2014:
        # 0 = "no trend year survived"; anything else is a trend year.
        _fail("breach_ledger.headline.latest_year",
              f"must be 0 or >= 2014, got {latest_year}")

    # Optional: full-year pace projection of the current year's breach
    # count (a flow). Records exposed are never projected.
    if "projection" in obj:
        _check_pace_projection(obj["projection"], "breach_ledger.projection",
                               obj["generated_at"], {"breaches": 1})


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "breach_ledger.json": _validate_breach_ledger,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the Breach Ledger contract for ``filename``.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no Breach Ledger contract.
    """
    VALIDATORS[filename](obj)
