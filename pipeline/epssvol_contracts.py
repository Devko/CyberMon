"""Contract for the EPSS Volatility output (epss_volatility.json).

Same philosophy as pipeline/contracts.py — a hand-rolled stdlib validator
that fails loudly — kept in its own module so this stage lands without
touching the core contracts file (the rescore_contracts / naming_contracts
precedent). The coordinator merges :data:`VALIDATORS` into the pipeline's
dispatch; failures raise the same
:class:`pipeline.contracts.ContractViolation`.

Two module-specific rules the shared helpers can't express:

* EPSS probabilities and percentiles are checked at 5-decimal precision,
  not CyberMon's usual 1 (:func:`_check_prob` / :func:`_check_delta`) — the
  documented EPSS exception, same as the EPSS Report Card, because the
  whole point is the movement of very small numbers.
* The internal-consistency checks are deliberately strong: churn, gap and
  catalog all derive from the same committed daily log, so their totals
  MUST agree, and the min-days gate must fire consistently across the gap
  block (a mismatch means the builder or the log broke).
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .contracts import (DATE_RE, _check_generated_at, _check_int, _check_list,
                        _check_num, _check_sorted, _check_str, _fail, _get)

WEEK_RE = re.compile(r"^\d{4}-W\d{2}$")

# Must match epss_volatility.THRESHOLDS. Hardcoded here on purpose (the
# calendar_contracts precedent): the contract states what the site may rely
# on, independently of the builder.
THRESHOLDS = {"lo": 0.001, "mid": 0.01, "hi": 0.05}


def _check_prob(v: Any, path: str) -> None:
    """An EPSS probability/percentile in [0, 1], at most 5 decimals."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        _fail(path, f"expected number, got {v!r}")
    if not 0.0 <= v <= 1.0:
        _fail(path, f"probability {v} outside [0, 1]")
    if abs(v * 1e5 - round(v * 1e5)) > 1e-4:
        _fail(path, f"probability {v} not rounded to 5 decimal places")


def _check_delta(v: Any, path: str) -> None:
    """A signed probability delta in [-1, 1], at most 5 decimals."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        _fail(path, f"expected number, got {v!r}")
    if not -1.0 <= v <= 1.0:
        _fail(path, f"delta {v} outside [-1, 1]")
    if abs(v * 1e5 - round(v * 1e5)) > 1e-4:
        _fail(path, f"delta {v} not rounded to 5 decimal places")


def _validate_epss_volatility(obj: Any) -> None:
    _check_generated_at(obj, "epss_volatility")

    thresholds = _get(obj, "thresholds", "epss_volatility")
    if thresholds != THRESHOLDS:
        _fail("epss_volatility.thresholds", f"must equal {THRESHOLDS}")

    # ---- catalog (audit block) --------------------------------------------
    catalog = _get(obj, "catalog", "epss_volatility")
    _check_str(_get(catalog, "state_model_version", "epss_volatility.catalog"),
               "epss_volatility.catalog.state_model_version")
    _check_str(_get(catalog, "state_score_date", "epss_volatility.catalog"),
               "epss_volatility.catalog.state_score_date", DATE_RE)
    _check_int(_get(catalog, "state_size", "epss_volatility.catalog"),
               "epss_volatility.catalog.state_size")
    days_observed = _get(catalog, "days_observed", "epss_volatility.catalog")
    trend_days = _get(catalog, "trend_days", "epss_volatility.catalog")
    resets = _get(catalog, "resets_quarantined", "epss_volatility.catalog")
    _check_int(days_observed, "epss_volatility.catalog.days_observed")
    _check_int(trend_days, "epss_volatility.catalog.trend_days")
    _check_int(resets, "epss_volatility.catalog.resets_quarantined")
    if trend_days + resets != days_observed:
        _fail("epss_volatility.catalog",
              f"trend_days ({trend_days}) + resets_quarantined ({resets}) "
              f"must equal days_observed ({days_observed})")
    totals = _get(catalog, "crossed_totals", "epss_volatility.catalog")
    if set(totals) != {"lo", "mid", "hi"}:
        _fail("epss_volatility.catalog.crossed_totals",
              "must carry exactly the keys ['hi', 'lo', 'mid']")
    for band in ("lo", "mid", "hi"):
        _check_int(totals[band],
                   f"epss_volatility.catalog.crossed_totals.{band}")
    first = _get(catalog, "first_observed", "epss_volatility.catalog")
    if (first is None) != (days_observed == 0):
        _fail("epss_volatility.catalog.first_observed",
              "must be null exactly when the log is empty")
    if first is not None:
        _check_str(first, "epss_volatility.catalog.first_observed", DATE_RE)

    gated = trend_days < 1  # refined below once min_days is read

    # ---- churn -------------------------------------------------------------
    churn = _get(obj, "churn", "epss_volatility")
    weeks = _check_list(_get(churn, "weeks", "epss_volatility.churn"),
                        "epss_volatility.churn.weeks")
    labels: list[str] = []
    week_sums = {"lo": 0, "mid": 0, "hi": 0}
    week_days = 0
    for i, w in enumerate(weeks):
        path = f"epss_volatility.churn.weeks[{i}]"
        label = _get(w, "week", path)
        _check_str(label, f"{path}.week", WEEK_RE)
        labels.append(label)
        for band in ("lo", "mid", "hi"):
            v = _get(w, f"crossed_{band}", path)
            _check_int(v, f"{path}.crossed_{band}")
            week_sums[band] += v
        d = _get(w, "days", path)
        _check_int(d, f"{path}.days")
        week_days += d
    _check_sorted(labels, "epss_volatility.churn.weeks")
    if len(set(labels)) != len(labels):
        _fail("epss_volatility.churn.weeks", "duplicate week labels")

    # ---- gap ---------------------------------------------------------------
    gap = _get(obj, "gap", "epss_volatility")
    min_days = _get(gap, "min_days", "epss_volatility.gap")
    _check_int(min_days, "epss_volatility.gap.min_days", minimum=1)
    gap_trend = _get(gap, "trend_days", "epss_volatility.gap")
    _check_int(gap_trend, "epss_volatility.gap.trend_days")
    if gap_trend != trend_days:
        _fail("epss_volatility.gap.trend_days",
              "must equal catalog.trend_days (same log)")
    gated = trend_days < min_days
    prob_pct = _get(gap, "prob_moved_pct", "epss_volatility.gap")
    pct_pct = _get(gap, "pct_moved_pct", "epss_volatility.gap")
    if (prob_pct is None) != gated:
        _fail("epss_volatility.gap.prob_moved_pct",
              "must be null exactly when trend_days is below min_days")
    if (pct_pct is None) != gated:
        _fail("epss_volatility.gap.pct_moved_pct",
              "must be null exactly when prob_moved_pct is")
    if not gated:
        _check_num(prob_pct, "epss_volatility.gap.prob_moved_pct", 0.0, 100.0)
        _check_num(pct_pct, "epss_volatility.gap.pct_moved_pct", 0.0, 100.0)
    days = _check_list(_get(gap, "days", "epss_volatility.gap"),
                       "epss_volatility.gap.days")
    if (len(days) == 0) != gated:
        _fail("epss_volatility.gap.days",
              "must be empty exactly when trend_days is below min_days")
    if not gated and len(days) != trend_days:
        _fail("epss_volatility.gap.days",
              f"must carry one entry per trend day ({trend_days}), got "
              f"{len(days)}")
    day_dates = []
    for i, d in enumerate(days):
        path = f"epss_volatility.gap.days[{i}]"
        dt = _get(d, "date", path)
        _check_str(dt, f"{path}.date", DATE_RE)
        day_dates.append(dt)
        _check_num(_get(d, "prob_moved", path), f"{path}.prob_moved",
                   0.0, 100.0)
        _check_num(_get(d, "pct_moved", path), f"{path}.pct_moved",
                   0.0, 100.0)
    _check_sorted(day_dates, "epss_volatility.gap.days (by date)")

    # ---- movers ------------------------------------------------------------
    movers = _get(obj, "movers", "epss_volatility")
    min_delta = _get(movers, "min_delta", "epss_volatility.movers")
    _check_prob(min_delta, "epss_volatility.movers.min_delta")
    entries = _check_list(_get(movers, "entries", "epss_volatility.movers"),
                          "epss_volatility.movers.entries")
    abs_deltas = []
    for i, m in enumerate(entries):
        path = f"epss_volatility.movers.entries[{i}]"
        _check_str(_get(m, "cve", path), f"{path}.cve")
        _check_str(_get(m, "observed_date", path), f"{path}.observed_date",
                   DATE_RE)
        old = _get(m, "old", path)
        new = _get(m, "new", path)
        delta = _get(m, "delta", path)
        _check_prob(old, f"{path}.old")
        _check_prob(new, f"{path}.new")
        _check_delta(delta, f"{path}.delta")
        if abs(delta - round(new - old, 5)) > 1e-4:
            _fail(f"{path}.delta", "must equal new - old")
        if abs(delta) + 1e-6 < min_delta:
            _fail(f"{path}.delta",
                  f"|delta| {abs(delta)} below min_delta {min_delta}")
        abs_deltas.append(abs(delta))
    _check_sorted(abs_deltas, "epss_volatility.movers.entries (by |delta|)",
                  descending=True)

    # ---- cross-section consistency (one log, one arithmetic) --------------
    if gated:
        if weeks:
            _fail("epss_volatility.churn.weeks",
                  "must be empty while trend_days is below min_days")
    else:
        for band in ("lo", "mid", "hi"):
            if week_sums[band] != totals[band]:
                _fail("epss_volatility.churn.weeks",
                      f"weekly crossed_{band} must sum to "
                      f"catalog.crossed_totals.{band}")
        if week_days != trend_days:
            _fail("epss_volatility.churn.weeks",
                  "weekly day counts must sum to catalog.trend_days")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "epss_volatility.json": _validate_epss_volatility,
}
