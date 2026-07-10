"""Contract for the Security Products module output (kev_guards.json).

Same philosophy as pipeline/contracts.py — a hand-rolled stdlib validator
that fails loudly — kept in its own module so this stage lands without
touching the core contracts file (mirrors market_contracts,
tier1_contracts, tier2_contracts, …). The coordinator merges
:data:`VALIDATORS` into the pipeline's dispatch; failures raise the same
:class:`pipeline.contracts.ContractViolation` type.

The core module's private checking helpers are reused read-only.
"""
from __future__ import annotations

from typing import Any, Callable

from .contracts import (DATE_RE, _check_generated_at, _check_int,
                        _check_list, _check_num, _check_str, _fail, _get)


def _check_split_block(block: Any, path: str) -> None:
    total = _get(block, "total", path)
    _check_int(total, f"{path}.total")
    known = _get(block, "known", path)
    _check_int(known, f"{path}.known")
    if known > total:
        _fail(f"{path}.known", f"known ({known}) exceeds total ({total})")
    _check_num(_get(block, "pct_known", path), f"{path}.pct_known",
               0.0, 100.0)


def _validate_kev_guards(obj: Any) -> None:
    _check_generated_at(obj, "kev_guards")
    _check_int(_get(obj, "min_n", "kev_guards"),
               "kev_guards.min_n", minimum=1)
    _check_int(_get(obj, "min_vendor_entries", "kev_guards"),
               "kev_guards.min_vendor_entries", minimum=1)

    # ---- years: guard share per dateAdded year ----------------------------
    entries = _check_list(_get(obj, "years", "kev_guards"),
                          "kev_guards.years")
    years = []
    for i, e in enumerate(entries):
        path = f"kev_guards.years[{i}]"
        year = _get(e, "year", path)
        _check_int(year, f"{path}.year", minimum=1990)
        years.append(year)
        total = _get(e, "total", path)
        _check_int(total, f"{path}.total", minimum=1)
        security = _get(e, "security", path)
        _check_int(security, f"{path}.security")
        if security > total:
            _fail(f"{path}.security",
                  f"security ({security}) exceeds total ({total})")
        _check_num(_get(e, "pct_security", path), f"{path}.pct_security",
                   0.0, 100.0)
    if years != sorted(years) or len(set(years)) != len(years):
        _fail("kev_guards.years", "years must be sorted and unique")

    # ---- vendors: recidivism board -----------------------------------------
    vendors = _check_list(_get(obj, "vendors", "kev_guards"),
                          "kev_guards.vendors")
    counts = []
    names = []
    for i, v in enumerate(vendors):
        path = f"kev_guards.vendors[{i}]"
        _check_str(_get(v, "vendor", path), f"{path}.vendor")
        names.append(v["vendor"])
        n = _get(v, "entries", path)
        _check_int(n, f"{path}.entries", minimum=1)
        counts.append(n)
        security = _get(v, "security_entries", path)
        _check_int(security, f"{path}.security_entries")
        if security > n:
            _fail(f"{path}.security_entries",
                  f"security_entries ({security}) exceeds entries ({n})")
        _check_num(_get(v, "pct_security", path), f"{path}.pct_security",
                   0.0, 100.0)
        first = _get(v, "first_added", path)
        _check_str(first, f"{path}.first_added", DATE_RE)
        last = _get(v, "last_added", path)
        _check_str(last, f"{path}.last_added", DATE_RE)
        if first > last:
            _fail(f"{path}.first_added",
                  f"first_added ({first}) after last_added ({last})")
        gap = _get(v, "median_gap_days", path)
        if gap is not None:  # null iff the vendor has a single dated entry
            _check_num(gap, f"{path}.median_gap_days", 0.0, 100000.0)
        if n >= 2 and gap is None:
            _fail(f"{path}.median_gap_days",
                  f"{n} entries but no median gap")
    if counts != sorted(counts, reverse=True):
        _fail("kev_guards.vendors", "not sorted by entries descending")
    if len(set(names)) != len(names):
        _fail("kev_guards.vendors", "duplicate vendor names")

    # ---- ransomware overlap -------------------------------------------------
    ransomware = _get(obj, "ransomware", "kev_guards")
    _check_split_block(_get(ransomware, "security", "kev_guards.ransomware"),
                       "kev_guards.ransomware.security")
    _check_split_block(_get(ransomware, "other", "kev_guards.ransomware"),
                       "kev_guards.ransomware.other")

    # ---- catalog audit block ------------------------------------------------
    catalog = _get(obj, "catalog", "kev_guards")
    total = _get(catalog, "total", "kev_guards.catalog")
    _check_int(total, "kev_guards.catalog.total")
    security = _get(catalog, "security", "kev_guards.catalog")
    _check_int(security, "kev_guards.catalog.security")
    if security > total:
        _fail("kev_guards.catalog.security",
              f"security ({security}) exceeds total ({total})")
    _check_num(_get(catalog, "pct_security", "kev_guards.catalog"),
               "kev_guards.catalog.pct_security", 0.0, 100.0)
    _check_int(_get(catalog, "classifier_version", "kev_guards.catalog"),
               "kev_guards.catalog.classifier_version", minimum=1)
    _check_int(_get(catalog, "classifier_rules", "kev_guards.catalog"),
               "kev_guards.catalog.classifier_rules", minimum=1)
    # the split must cover the whole catalog, nothing dropped silently
    r_total = (ransomware["security"]["total"] + ransomware["other"]["total"])
    if r_total != total:
        _fail("kev_guards.ransomware",
              f"security+other totals ({r_total}) != catalog total ({total})")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "kev_guards.json": _validate_kev_guards,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the Security Products contract.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no contract here.
    """
    VALIDATORS[filename](obj)
