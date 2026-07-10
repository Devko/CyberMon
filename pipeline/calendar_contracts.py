"""Contract for the CVE Calendar output (cve_calendar.json).

Same philosophy as pipeline/contracts.py — a hand-rolled stdlib validator
that fails loudly — kept in its own module so this stage lands without
touching the core contracts file (mirrors tier2_contracts and friends).
The coordinator merges :data:`VALIDATORS` into the pipeline's dispatch;
failures raise the same :class:`pipeline.contracts.ContractViolation`.

The core module's private checking helpers are reused read-only.
"""
from __future__ import annotations

from typing import Any, Callable

from .contracts import (DATE_RE, _check_generated_at, _check_int,
                        _check_list, _check_num, _check_sorted, _check_str,
                        _fail, _get)

# Must match calendar_metrics.WEEKDAY_COUNT / CALENDAR_PCT. Hardcoded here
# on purpose (tier2_contracts precedent): the contract states what the site
# may rely on, independently of the builder.
WEEKDAY_COUNT = 7
CALENDAR_PCT = 3.3


def _check_years_sorted_unique(years: list[int], path: str) -> None:
    _check_sorted(years, path)
    if len(set(years)) != len(years):
        _fail(path, "duplicate years")


def _check_year_n(e: Any, path: str, all_years: list[int]) -> int:
    year = _get(e, "year", path)
    _check_int(year, f"{path}.year", minimum=1990)
    all_years.append(year)
    n = _get(e, "n", path)
    _check_int(n, f"{path}.n", minimum=1)
    return n


def _validate_cve_calendar(obj: Any) -> None:
    _check_generated_at(obj, "cve_calendar")
    _check_int(_get(obj, "min_n", "cve_calendar"),
               "cve_calendar.min_n", minimum=1)

    # ---- id_age -----------------------------------------------------------
    id_age = _get(obj, "id_age", "cve_calendar")
    entries = _check_list(_get(id_age, "years", "cve_calendar.id_age"),
                          "cve_calendar.id_age.years")
    years: list[int] = []
    for i, e in enumerate(entries):
        path = f"cve_calendar.id_age.years[{i}]"
        n = _check_year_n(e, path, years)
        parts = {}
        for key in ("same_year", "one_year", "two_plus"):
            parts[key] = _get(e, key, path)
            _check_int(parts[key], f"{path}.{key}")
            _check_num(_get(e, f"pct_{key}", path), f"{path}.pct_{key}",
                       0.0, 100.0)
        if sum(parts.values()) != n:
            _fail(path, f"buckets {parts} do not sum to n ({n})")
        _check_num(_get(e, "pct_prior_year", path), f"{path}.pct_prior_year",
                   0.0, 100.0)
    _check_years_sorted_unique(years, "cve_calendar.id_age.years")
    _check_int(_get(id_age, "clamped_negative", "cve_calendar.id_age"),
               "cve_calendar.id_age.clamped_negative")
    headline = _get(id_age, "headline", "cve_calendar.id_age")
    if (headline is None) != (not years):
        _fail("cve_calendar.id_age.headline",
              "must be null exactly when no year is charted")
    if headline is not None:
        for key in ("latest_year", "baseline_year"):
            if _get(headline, key, "cve_calendar.id_age.headline") not in years:
                _fail(f"cve_calendar.id_age.headline.{key}",
                      "must be one of the charted years")
        for key in ("pct_prior_year_latest", "pct_prior_year_baseline"):
            _check_num(_get(headline, key, "cve_calendar.id_age.headline"),
                       f"cve_calendar.id_age.headline.{key}", 0.0, 100.0)

    # ---- weekday ----------------------------------------------------------
    weekday = _get(obj, "weekday", "cve_calendar")
    entries = _check_list(_get(weekday, "years", "cve_calendar.weekday"),
                          "cve_calendar.weekday.years")
    years = []
    for i, e in enumerate(entries):
        path = f"cve_calendar.weekday.years[{i}]"
        n = _check_year_n(e, path, years)
        counts = _check_list(_get(e, "counts", path), f"{path}.counts")
        pct = _check_list(_get(e, "pct", path), f"{path}.pct")
        if len(counts) != WEEKDAY_COUNT or len(pct) != WEEKDAY_COUNT:
            _fail(path, f"counts/pct must have exactly {WEEKDAY_COUNT} "
                        "entries (Monday-first)")
        for j, c in enumerate(counts):
            _check_int(c, f"{path}.counts[{j}]")
        for j, p in enumerate(pct):
            _check_num(p, f"{path}.pct[{j}]", 0.0, 100.0)
        if sum(counts) != n:
            _fail(f"{path}.counts", f"sum {sum(counts)} != n ({n})")
    _check_years_sorted_unique(years, "cve_calendar.weekday.years")
    comparison = _get(weekday, "comparison", "cve_calendar.weekday")
    if (comparison is None) != (not years):
        _fail("cve_calendar.weekday.comparison",
              "must be null exactly when no year is charted")
    if comparison is not None:
        for key in ("latest_year", "baseline_year"):
            if _get(comparison, key,
                    "cve_calendar.weekday.comparison") not in years:
                _fail(f"cve_calendar.weekday.comparison.{key}",
                      "must be one of the charted years")

    # ---- patch_tuesday ----------------------------------------------------
    pt = _get(obj, "patch_tuesday", "cve_calendar")
    if _get(pt, "calendar_pct", "cve_calendar.patch_tuesday") != CALENDAR_PCT:
        _fail("cve_calendar.patch_tuesday.calendar_pct",
              f"must equal {CALENDAR_PCT} (12 second Tuesdays / 365 days)")
    entries = _check_list(_get(pt, "years", "cve_calendar.patch_tuesday"),
                          "cve_calendar.patch_tuesday.years")
    pt_years: list[int] = []
    for i, e in enumerate(entries):
        path = f"cve_calendar.patch_tuesday.years[{i}]"
        n = _check_year_n(e, path, pt_years)
        on_pt = _get(e, "on_pt", path)
        _check_int(on_pt, f"{path}.on_pt")
        if on_pt > n:
            _fail(f"{path}.on_pt", f"on_pt ({on_pt}) exceeds n ({n})")
        _check_num(_get(e, "pct", path), f"{path}.pct", 0.0, 100.0)
        top = _get(e, "top_day", path)
        _check_str(_get(top, "date", f"{path}.top_day"),
                   f"{path}.top_day.date", DATE_RE)
        _check_int(_get(top, "n", f"{path}.top_day"),
                   f"{path}.top_day.n", minimum=1)
    _check_years_sorted_unique(pt_years, "cve_calendar.patch_tuesday.years")
    # weekday and patch_tuesday derive from the same day tally: same years.
    if pt_years != years:
        _fail("cve_calendar.patch_tuesday.years",
              "must chart exactly the weekday section's years "
              "(both derive from the same day tally)")
    headline = _get(pt, "headline", "cve_calendar.patch_tuesday")
    if (headline is None) != (not pt_years):
        _fail("cve_calendar.patch_tuesday.headline",
              "must be null exactly when no year is charted")
    if headline is not None:
        if _get(headline, "latest_year",
                "cve_calendar.patch_tuesday.headline") not in pt_years:
            _fail("cve_calendar.patch_tuesday.headline.latest_year",
                  "must be one of the charted years")
        _check_num(_get(headline, "pct_latest",
                        "cve_calendar.patch_tuesday.headline"),
                   "cve_calendar.patch_tuesday.headline.pct_latest",
                   0.0, 100.0)


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "cve_calendar.json": _validate_cve_calendar,
}
