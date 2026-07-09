"""Contracts for the Tier-2 corpus/catalog outputs (advisory_quality.json,
cwe_distribution.json and kev_ransomware.json).

Same philosophy as pipeline/contracts.py — hand-rolled stdlib validators
that fail loudly — kept in their own module so this stage lands without
touching the core contracts file (mirrors market_contracts and
tier1_contracts). The coordinator merges :data:`VALIDATORS` into the
pipeline's dispatch; failures raise the same
:class:`pipeline.contracts.ContractViolation` type.

The core module's private checking helpers are reused read-only.
"""
from __future__ import annotations

from typing import Any, Callable

from .contracts import (_check_generated_at, _check_int, _check_list,
                        _check_num, _check_sorted, _check_str, _fail, _get)

# Must match quality_metrics.build_cwe_distribution(top_k=8). Hardcoded here
# on purpose (as tier1_contracts hardcodes LAUNCH_CUTOFF): the contract
# states what the site may rely on, independently of the builder's default.
MAX_TOP_CWES = 8


def _check_years_sorted_unique(years: list[int], path: str) -> None:
    _check_sorted(years, path)
    if len(set(years)) != len(years):
        _fail(path, "duplicate years")


# ------------------------------------------------------- advisory_quality

def _validate_advisory_quality(obj: Any) -> None:
    _check_generated_at(obj, "advisory_quality")
    _check_int(_get(obj, "min_n", "advisory_quality"),
               "advisory_quality.min_n", minimum=1)

    entries = _check_list(_get(obj, "years", "advisory_quality"),
                          "advisory_quality.years")
    years = []
    for i, e in enumerate(entries):
        path = f"advisory_quality.years[{i}]"
        year = _get(e, "year", path)
        _check_int(year, f"{path}.year", minimum=1990)
        years.append(year)
        n = _get(e, "n", path)
        _check_int(n, f"{path}.n", minimum=1)
        for key in ("cwe", "cvss", "affected"):
            missing = _get(e, f"missing_{key}", path)
            _check_int(missing, f"{path}.missing_{key}")
            if missing > n:
                _fail(f"{path}.missing_{key}",
                      f"missing_{key} ({missing}) exceeds n ({n})")
            _check_num(_get(e, f"pct_missing_{key}", path),
                       f"{path}.pct_missing_{key}", 0.0, 100.0)
    _check_years_sorted_unique(years, "advisory_quality.years")


# ------------------------------------------------------- cwe_distribution

def _validate_cwe_distribution(obj: Any) -> None:
    _check_generated_at(obj, "cwe_distribution")
    _check_int(_get(obj, "min_n", "cwe_distribution"),
               "cwe_distribution.min_n", minimum=1)

    window = _get(obj, "window", "cwe_distribution")
    start = _get(window, "start_year", "cwe_distribution.window")
    end = _get(window, "end_year", "cwe_distribution.window")
    _check_int(start, "cwe_distribution.window.start_year", minimum=1990)
    _check_int(end, "cwe_distribution.window.end_year", minimum=1990)
    if start > end:
        _fail("cwe_distribution.window",
              f"start_year ({start}) after end_year ({end})")

    top = _check_list(_get(obj, "top_cwes", "cwe_distribution"),
                      "cwe_distribution.top_cwes")
    if len(top) > MAX_TOP_CWES:
        _fail("cwe_distribution.top_cwes",
              f"more than {MAX_TOP_CWES} entries ({len(top)})")
    top_ids = []
    for i, t in enumerate(top):
        path = f"cwe_distribution.top_cwes[{i}]"
        cwe_id = _get(t, "id", path)
        _check_str(cwe_id, f"{path}.id")
        if not cwe_id.startswith("CWE-"):
            _fail(f"{path}.id", f"id {cwe_id!r} does not start with 'CWE-'")
        _check_str(_get(t, "name", path), f"{path}.name")
        top_ids.append(cwe_id)
    if len(set(top_ids)) != len(top_ids):
        _fail("cwe_distribution.top_cwes", "duplicate CWE ids")
    expected_keys = set(top_ids) | {"other"}

    entries = _check_list(_get(obj, "years", "cwe_distribution"),
                          "cwe_distribution.years")
    years = []
    for i, e in enumerate(entries):
        path = f"cwe_distribution.years[{i}]"
        year = _get(e, "year", path)
        _check_int(year, f"{path}.year", minimum=1990)
        if not start <= year <= end:
            _fail(f"{path}.year",
                  f"year {year} outside window [{start}, {end}]")
        years.append(year)
        n_tagged = _get(e, "n_tagged", path)
        _check_int(n_tagged, f"{path}.n_tagged", minimum=1)
        n_published = _get(e, "n_published", path)
        _check_int(n_published, f"{path}.n_published")
        if n_tagged > n_published:
            _fail(f"{path}.n_tagged",
                  f"n_tagged ({n_tagged}) exceeds n_published ({n_published})")
        _check_num(_get(e, "pct_tagged", path), f"{path}.pct_tagged",
                   0.0, 100.0)
        shares = _get(e, "shares", path)
        if not isinstance(shares, dict):
            _fail(f"{path}.shares", "expected object")
        if set(shares) != expected_keys:
            _fail(f"{path}.shares",
                  f"keys must be exactly the top CWE ids plus 'other'; "
                  f"got {sorted(shares)}")
        for key, val in shares.items():
            _check_num(val, f"{path}.shares[{key}]", 0.0, 100.0)
    _check_years_sorted_unique(years, "cwe_distribution.years")


# -------------------------------------------------------- kev_ransomware

def _validate_kev_ransomware(obj: Any) -> None:
    _check_generated_at(obj, "kev_ransomware")
    _check_int(_get(obj, "min_n", "kev_ransomware"),
               "kev_ransomware.min_n", minimum=1)

    entries = _check_list(_get(obj, "years", "kev_ransomware"),
                          "kev_ransomware.years")
    years = []
    for i, e in enumerate(entries):
        path = f"kev_ransomware.years[{i}]"
        year = _get(e, "year", path)
        _check_int(year, f"{path}.year", minimum=1990)
        years.append(year)
        total = _get(e, "total", path)
        _check_int(total, f"{path}.total", minimum=1)
        known = _get(e, "known", path)
        _check_int(known, f"{path}.known")
        if known > total:
            _fail(f"{path}.known",
                  f"known ({known}) exceeds total ({total})")
        _check_num(_get(e, "pct_known", path), f"{path}.pct_known",
                   0.0, 100.0)
    _check_years_sorted_unique(years, "kev_ransomware.years")

    catalog = _get(obj, "catalog", "kev_ransomware")
    total = _get(catalog, "total", "kev_ransomware.catalog")
    _check_int(total, "kev_ransomware.catalog.total")
    known = _get(catalog, "known", "kev_ransomware.catalog")
    _check_int(known, "kev_ransomware.catalog.known")
    if known > total:
        _fail("kev_ransomware.catalog.known",
              f"known ({known}) exceeds total ({total})")
    _check_num(_get(catalog, "pct_known", "kev_ransomware.catalog"),
               "kev_ransomware.catalog.pct_known", 0.0, 100.0)


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "advisory_quality.json": _validate_advisory_quality,
    "cwe_distribution.json": _validate_cwe_distribution,
    "kev_ransomware.json": _validate_kev_ransomware,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the Tier-2 contract for ``filename``.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no Tier-2 contract.
    """
    VALIDATORS[filename](obj)
