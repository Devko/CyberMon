"""Contract for the Hygiene Index output (dnssec_adoption.json).

Same philosophy as pipeline/contracts.py — hand-rolled stdlib validators
that fail loudly — kept in its own module so this stage lands without
touching the core contracts file (mirrors market/tier1/tier2 contracts).
Failures raise the same :class:`pipeline.contracts.ContractViolation`.

The core module's private checking helpers are reused read-only.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .contracts import (_check_generated_at, _check_int, _check_list,
                        _check_num, _check_sorted, _check_str, _fail, _get,
                        DATE_RE)

MONTH_RE = re.compile(r"^\d{4}-\d{2}$")
CC_RE = re.compile(r"^[A-Z]{2}$")

# Must match hygiene_metrics.SPREAD_BUCKETS / fetch_dnssec.ECONOMIES.
# Hardcoded on purpose (the tier1_contracts LAUNCH_CUTOFF precedent):
# the contract states what the site may rely on, independently of the
# builder's constants.
SPREAD_BUCKETS = ["<10%", "10-25%", "25-50%", "50-75%", "75%+"]
MAX_ECONOMIES = 10


def _check_month_series(entries: Any, path: str) -> list[str]:
    """A non-empty [{month, validating_pc}] series: months are YYYY-MM,
    sorted ascending, unique; rates are 0–100, 1 decimal."""
    series = _check_list(entries, path)
    if not series:
        _fail(path, "series must not be empty")
    months = []
    for i, entry in enumerate(series):
        p = f"{path}[{i}]"
        month = _get(entry, "month", p)
        _check_str(month, f"{p}.month", MONTH_RE)
        months.append(month)
        _check_num(_get(entry, "validating_pc", p),
                   f"{p}.validating_pc", 0.0, 100.0)
    _check_sorted(months, path)
    if len(set(months)) != len(months):
        _fail(path, "duplicate months")
    return months


def _validate_dnssec_adoption(obj: Any) -> None:
    _check_generated_at(obj, "dnssec_adoption")
    window = _get(obj, "window", "dnssec_adoption")
    if window != "30_day":
        _fail("dnssec_adoption.window", f"must be '30_day', got {window!r}")

    # ---- world ------------------------------------------------------------
    world = _get(obj, "world", "dnssec_adoption")
    _check_str(_get(world, "cc", "dnssec_adoption.world"),
               "dnssec_adoption.world.cc", CC_RE)
    months = _check_month_series(_get(world, "series", "dnssec_adoption.world"),
                                 "dnssec_adoption.world.series")

    latest = _get(world, "latest", "dnssec_adoption.world")
    date = _get(latest, "date", "dnssec_adoption.world.latest")
    _check_str(date, "dnssec_adoption.world.latest.date", DATE_RE)
    if date[:7] != months[-1]:
        _fail("dnssec_adoption.world.latest.date",
              f"latest date {date} must fall in the series' newest month "
              f"{months[-1]}")
    _check_num(_get(latest, "validating_pc", "dnssec_adoption.world.latest"),
               "dnssec_adoption.world.latest.validating_pc", 0.0, 100.0)
    _check_num(_get(latest, "partial_pc", "dnssec_adoption.world.latest"),
               "dnssec_adoption.world.latest.partial_pc", 0.0, 100.0)
    _check_int(_get(latest, "seen", "dnssec_adoption.world.latest"),
               "dnssec_adoption.world.latest.seen")

    baseline = _get(world, "baseline", "dnssec_adoption.world")
    bmonth = _get(baseline, "month", "dnssec_adoption.world.baseline")
    _check_str(bmonth, "dnssec_adoption.world.baseline.month", MONTH_RE)
    if bmonth not in months:
        _fail("dnssec_adoption.world.baseline.month",
              f"baseline month {bmonth} must be one of the series months")
    _check_num(_get(baseline, "validating_pc", "dnssec_adoption.world.baseline"),
               "dnssec_adoption.world.baseline.validating_pc", 0.0, 100.0)

    # ---- economies ----------------------------------------------------------
    economies = _check_list(_get(obj, "economies", "dnssec_adoption"),
                            "dnssec_adoption.economies")
    if len(economies) > MAX_ECONOMIES:
        _fail("dnssec_adoption.economies",
              f"more than {MAX_ECONOMIES} economies ({len(economies)})")
    ccs = []
    rates = []
    for i, economy in enumerate(economies):
        path = f"dnssec_adoption.economies[{i}]"
        cc = _get(economy, "cc", path)
        _check_str(cc, f"{path}.cc", CC_RE)
        ccs.append(cc)
        _check_str(_get(economy, "name", path), f"{path}.name")
        latest_pc = _get(economy, "latest_pc", path)
        _check_num(latest_pc, f"{path}.latest_pc", 0.0, 100.0)
        rates.append(latest_pc)
        _check_month_series(_get(economy, "series", path), f"{path}.series")
    if len(set(ccs)) != len(ccs):
        _fail("dnssec_adoption.economies", "duplicate economy codes")
    _check_sorted(rates, "dnssec_adoption.economies (by latest_pc)",
                  descending=True)

    # ---- spread -------------------------------------------------------------
    spread = _get(obj, "spread", "dnssec_adoption")
    _check_int(_get(spread, "min_seen", "dnssec_adoption.spread"),
               "dnssec_adoption.spread.min_seen", minimum=1)
    n_economies = _get(spread, "n_economies", "dnssec_adoption.spread")
    _check_int(n_economies, "dnssec_adoption.spread.n_economies")
    buckets = _check_list(_get(spread, "buckets", "dnssec_adoption.spread"),
                          "dnssec_adoption.spread.buckets")
    labels = []
    total = 0
    for i, bucket in enumerate(buckets):
        path = f"dnssec_adoption.spread.buckets[{i}]"
        labels.append(_get(bucket, "bucket", path))
        n = _get(bucket, "n", path)
        _check_int(n, f"{path}.n")
        total += n
    if labels != SPREAD_BUCKETS:
        _fail("dnssec_adoption.spread.buckets",
              f"bucket labels must be exactly {SPREAD_BUCKETS}, got {labels}")
    if total != n_economies:
        _fail("dnssec_adoption.spread",
              f"bucket counts sum to {total}, n_economies says {n_economies}")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "dnssec_adoption.json": _validate_dnssec_adoption,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the Hygiene Index contract.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no contract here.
    """
    VALIDATORS[filename](obj)
