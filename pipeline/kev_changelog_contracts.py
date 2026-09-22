"""Contract for the KEV Changelog output (kev_changelog.json).

Same philosophy as pipeline/contracts.py — hand-rolled stdlib validators
that fail loudly — kept in its own module so the KEV Changelog stage lands
without touching the core contracts file. The coordinator merges
:data:`VALIDATORS` into the pipeline's dispatch; failures raise the same
:class:`pipeline.contracts.ContractViolation` type.

The core module's private checking helpers are reused read-only.

Arithmetic identities enforced here (the file's audit trail):

* ``catalog.edits_total + catalog.additions_excluded ==
  catalog.events_total`` — every logged event is either an edit or an
  addition; additions are excluded from the charts by design (catalog
  growth is not an edit) and the exclusion is disclosed, never hidden.
* per-month category counts sum to the month's ``total``; month totals
  sum to ``catalog.edits_total``; months are contiguous (gap months chart
  at zero).
* ``flips.by_month`` is cumulative and ends at ``flips.total``;
  ``flips.lag`` ships its stats only at ``n >= min_n`` (below that the
  count is published and the stats are null — thin data renders honestly).
* optional ``flips.step_month_flips`` + ``flips.total_after_step`` ==
  ``flips.total``, and the step count equals the first month's flips —
  the step is set apart from the headline, never dropped from the ledger.
* optional ``flag_lag``: bucketed + unusable flips == ``flips.total``
  minus the step month's flips; buckets tile 0.. contiguously and sum to
  ``n_capture``/``n_daily``; per-listing-year counts sum to the same n.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .contracts import (DATE_RE, _check_generated_at, _check_int,
                        _check_list, _check_num, _check_sorted, _check_str,
                        _fail, _get)
from .kev_changelog import HERO_CATEGORIES

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
MONTH_RE = re.compile(r"^\d{4}-\d{2}$")


def _next_month(label: str) -> str:
    y, m = int(label[:4]), int(label[5:7])
    return f"{y + 1:04d}-01" if m == 12 else f"{y:04d}-{m + 1:02d}"


def _check_month_series(rows: list, path: str) -> None:
    """Months must be contiguous ascending YYYY-MM labels (gap months are
    emitted at zero — the axis never silently skips time)."""
    for i, row in enumerate(rows):
        _check_str(_get(row, "month", f"{path}[{i}]"),
                   f"{path}[{i}].month", MONTH_RE)
        if i and row["month"] != _next_month(rows[i - 1]["month"]):
            _fail(f"{path}[{i}].month",
                  f"{row['month']} does not follow "
                  f"{rows[i - 1]['month']} contiguously")


def _check_months(obj: Any) -> int:
    path = "kev_changelog.months"
    rows = _check_list(_get(obj, "months", "kev_changelog"), path)
    _check_month_series(rows, path)
    edits_sum = 0
    for i, row in enumerate(rows):
        p = f"{path}[{i}]"
        total = _get(row, "total", p)
        _check_int(total, f"{p}.total")
        cat_sum = 0
        for cat in HERO_CATEGORIES:
            n = _get(row, cat, p)
            _check_int(n, f"{p}.{cat}")
            cat_sum += n
        if cat_sum != total:
            _fail(p, f"category counts sum to {cat_sum}, total is {total}")
        edits_sum += total
    return edits_sum


def _check_flips(obj: Any, min_n: int, edits_total: int) -> int:
    path = "kev_changelog.flips"
    flips = _get(obj, "flips", "kev_changelog")
    total = _get(flips, "total", path)
    _check_int(total, f"{path}.total")
    _check_int(_get(flips, "reversals", path), f"{path}.reversals")
    if total > edits_total:
        _fail(f"{path}.total",
              f"{total} flips exceed catalog.edits_total {edits_total}")

    rows = _check_list(_get(flips, "by_month", path), f"{path}.by_month")
    _check_month_series(rows, f"{path}.by_month")
    running = 0
    for i, row in enumerate(rows):
        p = f"{path}.by_month[{i}]"
        n = _get(row, "flips", p)
        _check_int(n, f"{p}.flips")
        running += n
        cumulative = _get(row, "cumulative", p)
        _check_int(cumulative, f"{p}.cumulative")
        if cumulative != running:
            _fail(f"{p}.cumulative",
                  f"{cumulative} does not equal the running sum {running}")
    if running != total:
        _fail(f"{path}.by_month",
              f"monthly flips sum to {running}, total is {total}")

    def _check_lag(lag: Any, lpath: str) -> int:
        n = _get(lag, "n", lpath)
        _check_int(n, f"{lpath}.n")
        if n > total:
            _fail(f"{lpath}.n", f"{n} lags exceed {total} flips")
        stats = [_get(lag, k, lpath)
                 for k in ("p25_days", "median_days", "p75_days")]
        if n < min_n:
            if any(s is not None for s in stats):
                _fail(lpath, f"stats must be null below min_n={min_n} (n={n})")
        else:
            for key, v in zip(("p25_days", "median_days", "p75_days"), stats):
                # A flip can only be observed on or after the entry existed,
                # but capture-dated events tolerate slack; keep a sane range.
                _check_num(v, f"{lpath}.{key}", -366.0, 36600.0)
            if not stats[0] <= stats[1] <= stats[2]:
                _fail(lpath, "p25 <= median <= p75 must hold")
        return n

    n = _check_lag(_get(flips, "lag", path), f"{path}.lag")
    # Additive (editions before 2026-09-08 lack it): the lag over flips
    # observed after the step month, and that month.
    if "lag_post_step" in flips:
        post_n = _check_lag(flips["lag_post_step"], f"{path}.lag_post_step")
        if post_n > n:
            _fail(f"{path}.lag_post_step.n",
                  f"{post_n} post-step lags exceed {n} lags")
        step = flips.get("step_month")
        if step is not None:
            _check_str(step, f"{path}.step_month", MONTH_RE)
    # Additive (editions before 2026-09-20 lack them): the step month's
    # flips counted apart (schema initialization, not reassessments) and
    # the headline count without them. Both are derived from the same
    # ledger as ``total``/``by_month``, so they must reconcile with it.
    if "step_month_flips" in flips or "total_after_step" in flips:
        step_n = _get(flips, "step_month_flips", path)
        after_n = _get(flips, "total_after_step", path)
        _check_int(step_n, f"{path}.step_month_flips")
        _check_int(after_n, f"{path}.total_after_step")
        if step_n + after_n != total:
            _fail(f"{path}.total_after_step",
                  f"step_month_flips {step_n} + total_after_step {after_n} "
                  f"must equal total {total}")
        step = flips.get("step_month")
        if step is None:
            if step_n != 0:
                _fail(f"{path}.step_month_flips",
                      f"{step_n} step-month flips with no step_month")
        elif not rows or rows[0]["month"] != step \
                or step_n != rows[0]["flips"]:
            _fail(f"{path}.step_month_flips",
                  f"{step_n} does not equal the flips of step_month {step}, "
                  f"which must be the first month of by_month")
    return total


def _check_lag_stats(lag: Any, lpath: str, min_n: int) -> int:
    """n + p25/median/p75: stats null below min_n, ordered otherwise."""
    n = _get(lag, "n", lpath)
    _check_int(n, f"{lpath}.n")
    keys = ("p25_days", "median_days", "p75_days")
    stats = [_get(lag, k, lpath) for k in keys]
    if n < min_n:
        if any(s is not None for s in stats):
            _fail(lpath, f"stats must be null below min_n={min_n} (n={n})")
        return n
    for key, v in zip(keys, stats):
        _check_num(v, f"{lpath}.{key}", 0.0, 36600.0)
    if not stats[0] <= stats[1] <= stats[2]:
        _fail(lpath, "p25 <= median <= p75 must hold")
    return n


def _check_flag_lag(obj: Any, min_n: int) -> None:
    """Additive (editions before 2026-09-22 lack it): the ransomware-flag
    lag block. Reconciles with the flips block: the cohort is the flips
    outside the step month, each either bucketed or counted unusable."""
    path = "kev_changelog.flag_lag"
    block = obj["flag_lag"]
    flips = obj["flips"]
    step = _get(block, "step_month", path)
    if step != flips.get("step_month"):
        _fail(f"{path}.step_month",
              f"{step!r} differs from flips.step_month "
              f"{flips.get('step_month')!r}")
    for key in ("excluded_step", "n_capture", "n_daily", "unusable",
                "went_back"):
        _check_int(_get(block, key, path), f"{path}.{key}")
    step_n = flips.get("step_month_flips",
                       flips["by_month"][0]["flips"]
                       if step is not None and flips["by_month"] else 0)
    if block["excluded_step"] != step_n:
        _fail(f"{path}.excluded_step",
              f"{block['excluded_step']} differs from the step month's "
              f"{step_n} flips")
    n = block["n_capture"] + block["n_daily"]
    cohort = flips["total"] - block["excluded_step"]
    if n + block["unusable"] != cohort:
        _fail(path, f"n_capture + n_daily + unusable = "
                    f"{n + block['unusable']}, cohort (total - step) is "
                    f"{cohort}")
    if block["went_back"] > n:
        _fail(f"{path}.went_back", f"{block['went_back']} exceeds n={n}")
    if _check_lag_stats(_get(block, "overall", path), f"{path}.overall",
                        min_n) != n:
        _fail(f"{path}.overall.n", f"must equal n_capture + n_daily = {n}")

    rows = _check_list(_get(block, "buckets", path), f"{path}.buckets")
    grains = {"capture": 0, "daily": 0}
    prev_hi = -1
    for i, row in enumerate(rows):
        p = f"{path}.buckets[{i}]"
        _check_str(_get(row, "label", p), f"{p}.label")
        lo, hi = _get(row, "lo", p), _get(row, "hi", p)
        _check_int(lo, f"{p}.lo")
        if lo != prev_hi + 1:
            _fail(f"{p}.lo", f"{lo} does not follow the previous bucket's "
                             f"upper edge {prev_hi}")
        if hi is None:
            if i != len(rows) - 1:
                _fail(f"{p}.hi", "only the last bucket may be open-ended")
        else:
            _check_int(hi, f"{p}.hi", minimum=lo)
            prev_hi = hi
        for g in grains:
            _check_int(_get(row, g, p), f"{p}.{g}")
            grains[g] += row[g]
    if rows and rows[-1]["hi"] is not None:
        _fail(f"{path}.buckets", "the last bucket must be open-ended")
    if grains["capture"] != block["n_capture"] or \
            grains["daily"] != block["n_daily"]:
        _fail(f"{path}.buckets", f"bucket counts {grains} do not sum to "
                                 f"n_capture/n_daily")

    rows = _check_list(_get(block, "by_year", path), f"{path}.by_year")
    year_sum = 0
    for i, row in enumerate(rows):
        p = f"{path}.by_year[{i}]"
        year = _get(row, "year", p)
        _check_int(year, f"{p}.year", minimum=1990)
        if i and year != rows[i - 1]["year"] + 1:
            _fail(f"{p}.year", "listing years must be contiguous ascending")
        for g in ("capture", "daily"):
            _check_int(_get(row, g, p), f"{p}.{g}")
        if _check_lag_stats(row, p, min_n) != row["capture"] + row["daily"]:
            _fail(f"{p}.n", "must equal capture + daily")
        year_sum += row["n"]
    if year_sum != n:
        _fail(f"{path}.by_year", f"years sum to {year_sum}, n is {n}")


def _check_board(obj: Any, removed_total: int) -> None:
    path = "kev_changelog.board"
    board = _get(obj, "board", "kev_changelog")

    rows = _check_list(_get(board, "most_edited", path),
                       f"{path}.most_edited")
    edits = []
    cves = set()
    for i, row in enumerate(rows):
        p = f"{path}.most_edited[{i}]"
        cve = _get(row, "cve", p)
        _check_str(cve, f"{p}.cve", CVE_RE)
        if cve in cves:
            _fail(f"{p}.cve", f"duplicate {cve}")
        cves.add(cve)
        # vendor/product may be empty strings (the catalog's own labels).
        for key in ("vendor", "product"):
            if not isinstance(_get(row, key, p), str):
                _fail(f"{p}.{key}", "expected string")
        _check_int(_get(row, "edits", p), f"{p}.edits", minimum=1)
        edits.append(row["edits"])
        _check_str(_get(row, "last_change", p), f"{p}.last_change",
                   DATE_RE)
    _check_sorted(edits, f"{path}.most_edited (by edits)", descending=True)

    rows = _check_list(_get(board, "removals", path), f"{path}.removals")
    if len(rows) != removed_total:
        _fail(f"{path}.removals",
              f"{len(rows)} rows, catalog.removed_total is {removed_total}")
    keys = []
    for i, row in enumerate(rows):
        p = f"{path}.removals[{i}]"
        cve = _get(row, "cve", p)
        _check_str(cve, f"{p}.cve", CVE_RE)
        for key in ("vendor", "product"):
            if not isinstance(_get(row, key, p), str):
                _fail(f"{p}.{key}", "expected string")
        listed = _get(row, "listed", p)  # "" when dateAdded was unusable
        if listed != "":
            _check_str(listed, f"{p}.listed", DATE_RE)
        removed = _get(row, "removed", p)
        _check_str(removed, f"{p}.removed", DATE_RE)
        keys.append((removed, cve))
    _check_sorted(keys, f"{path}.removals (by removed date, cve)")
    if len(set(r["cve"] for r in rows)) != len(rows):
        _fail(f"{path}.removals", "duplicate CVEs")


def _check_catalog(obj: Any) -> dict:
    path = "kev_changelog.catalog"
    catalog = _get(obj, "catalog", "kev_changelog")
    for key in ("entries", "removed_total", "events_total", "edits_total",
                "additions_excluded", "backfill_captures"):
        _check_int(_get(catalog, key, path), f"{path}.{key}")
    if catalog["edits_total"] + catalog["additions_excluded"] != \
            catalog["events_total"]:
        _fail(path, "edits_total + additions_excluded must equal "
                    "events_total (every event is one or the other)")
    first = _get(catalog, "first_observed", path)
    last = _get(catalog, "last_observed", path)
    for key, v in (("first_observed", first), ("last_observed", last)):
        if v is not None:
            _check_str(v, f"{path}.{key}", DATE_RE)
    if first is not None and last is not None and first > last:
        _fail(f"{path}.first_observed",
              f"{first} is after last_observed {last}")
    if first is None and catalog["events_total"] > 0:
        _fail(f"{path}.first_observed",
              "events on record but no first_observed date")
    return catalog


def _check_headline(obj: Any, catalog: dict) -> None:
    path = "kev_changelog.headline"
    headline = _get(obj, "headline", "kev_changelog")
    if catalog["entries"] == 0 or catalog["edits_total"] == 0:
        if headline is not None:
            _fail(path, "must be null with no entries or no edits")
        return
    if headline is None:
        _fail(path, "must be present when entries and edits exist")
    if _get(headline, "edits_total", path) != catalog["edits_total"]:
        _fail(f"{path}.edits_total", "must equal catalog.edits_total")
    _check_num(_get(headline, "edits_per_100_entries", path),
               f"{path}.edits_per_100_entries", 0.0, 100000.0)
    _check_num(_get(headline, "pct_flag_flips", path),
               f"{path}.pct_flag_flips", 0.0, 100.0)


# ------------------------------------------------------- kev_changelog.json

def _validate_kev_changelog(obj: Any) -> None:
    _check_generated_at(obj, "kev_changelog")
    min_n = _get(obj, "min_n", "kev_changelog")
    _check_int(min_n, "kev_changelog.min_n", minimum=1)

    catalog = _check_catalog(obj)
    edits_sum = _check_months(obj)
    if edits_sum != catalog["edits_total"]:
        _fail("kev_changelog.months",
              f"month totals sum to {edits_sum}, catalog.edits_total is "
              f"{catalog['edits_total']}")
    _check_flips(obj, min_n, catalog["edits_total"])
    if "flag_lag" in obj:
        _check_flag_lag(obj, min_n)
    _check_board(obj, catalog["removed_total"])
    _check_headline(obj, catalog)


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "kev_changelog.json": _validate_kev_changelog,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the KEV Changelog contract for
    ``filename``.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no KEV Changelog contract.
    """
    VALIDATORS[filename](obj)
