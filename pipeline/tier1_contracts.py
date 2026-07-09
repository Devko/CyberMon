"""Contracts for the Tier-1 module outputs (kev_latency.json and
cna_concentration.json).

Same philosophy as pipeline/contracts.py — hand-rolled stdlib validators
that fail loudly — kept in their own module so the Tier-1 stage lands
without touching the core contracts file (mirrors market_contracts). The
coordinator merges :data:`VALIDATORS` into the pipeline's dispatch;
failures raise the same :class:`pipeline.contracts.ContractViolation`
type, so callers need only one except clause.

The core module's private checking helpers are reused read-only.
"""
from __future__ import annotations

from typing import Any, Callable

from .contracts import (DATE_RE, _check_generated_at, _check_int,
                        _check_list, _check_num, _check_sorted, _check_str,
                        _fail, _get)

# Must match kev_metrics.LAUNCH_CUTOFF / kev_metrics.BUCKETS. Hardcoded here
# on purpose (as market_contracts hardcodes SOURCES): the contract states
# what the site may rely on, independently of the builder's constants.
LAUNCH_CUTOFF = "2023-01-01"
LATENCY_BUCKETS = ["before_publish", "0-7d", "8-30d", "31-90d", "91-365d",
                   "1-3y", "3y+"]
# Day-count stats are bounded generously (~135 years); latency may be
# legitimately negative (CISA can list before the record publishes).
_DAYS_LO, _DAYS_HI = -50000.0, 50000.0
# HHI lives on the classic 0-10000 scale — the documented exception to the
# 0-100 percentage rule.
_HHI_HI = 10000.0


def _check_day_stats(entry: Any, path: str) -> int:
    """year/n/median_days/p25_days/p75_days common shape; returns year."""
    year = _get(entry, "year", path)
    _check_int(year, f"{path}.year", minimum=1990)
    _check_int(_get(entry, "n", path), f"{path}.n", minimum=1)
    for key in ("median_days", "p25_days", "p75_days"):
        _check_num(_get(entry, key, path), f"{path}.{key}",
                   _DAYS_LO, _DAYS_HI)
    return year


# ------------------------------------------------------------ kev_latency

def _validate_kev_latency(obj: Any) -> None:
    _check_generated_at(obj, "kev_latency")

    matched = _get(obj, "matched", "kev_latency")
    for key in ("total_kev", "matched_cve", "unmatched_cve"):
        _check_int(_get(matched, key, "kev_latency.matched"),
                   f"kev_latency.matched.{key}")
    if matched["matched_cve"] + matched["unmatched_cve"] != matched["total_kev"]:
        _fail("kev_latency.matched",
              f"matched_cve ({matched['matched_cve']}) + unmatched_cve "
              f"({matched['unmatched_cve']}) != total_kev "
              f"({matched['total_kev']})")

    backfill = _get(obj, "launch_backfill", "kev_latency")
    cutoff = _get(backfill, "date_added_before", "kev_latency.launch_backfill")
    _check_str(cutoff, "kev_latency.launch_backfill.date_added_before",
               DATE_RE)
    if cutoff != LAUNCH_CUTOFF:
        _fail("kev_latency.launch_backfill.date_added_before",
              f"must equal {LAUNCH_CUTOFF!r}, got {cutoff!r}")
    n = _get(backfill, "n", "kev_latency.launch_backfill")
    _check_int(n, "kev_latency.launch_backfill.n")
    median = _get(backfill, "median_days", "kev_latency.launch_backfill")
    if n == 0:
        if median is not None:  # an empty cohort has no median, not 0.0
            _fail("kev_latency.launch_backfill.median_days",
                  f"must be null when n == 0, got {median!r}")
    else:
        _check_num(median, "kev_latency.launch_backfill.median_days",
                   _DAYS_LO, _DAYS_HI)

    entries = _check_list(_get(obj, "latency_by_year", "kev_latency"),
                          "kev_latency.latency_by_year")
    years = []
    for i, e in enumerate(entries):
        path = f"kev_latency.latency_by_year[{i}]"
        years.append(_check_day_stats(e, path))
        for key in ("pct_negative", "pct_over_365d"):
            _check_num(_get(e, key, path), f"{path}.{key}", 0.0, 100.0)
    _check_sorted(years, "kev_latency.latency_by_year")
    if len(set(years)) != len(years):
        _fail("kev_latency.latency_by_year", "duplicate years")

    buckets = _check_list(_get(obj, "latency_buckets", "kev_latency"),
                          "kev_latency.latency_buckets")
    labels = []
    for i, b in enumerate(buckets):
        path = f"kev_latency.latency_buckets[{i}]"
        labels.append(_get(b, "bucket", path))
        _check_int(_get(b, "n", path), f"{path}.n")
        _check_num(_get(b, "pct", path), f"{path}.pct", 0.0, 100.0)
    if labels != LATENCY_BUCKETS:  # all 7, fixed order, always present
        _fail("kev_latency.latency_buckets",
              f"bucket labels must equal {LATENCY_BUCKETS}, got {labels}")

    spans = _check_list(_get(obj, "remediation_span_by_year", "kev_latency"),
                        "kev_latency.remediation_span_by_year")
    years = [_check_day_stats(e, f"kev_latency.remediation_span_by_year[{i}]")
             for i, e in enumerate(spans)]
    _check_sorted(years, "kev_latency.remediation_span_by_year")
    if len(set(years)) != len(years):
        _fail("kev_latency.remediation_span_by_year", "duplicate years")

    headline = _get(obj, "headline", "kev_latency")
    _check_int(_get(headline, "latest_year", "kev_latency.headline"),
               "kev_latency.headline.latest_year", minimum=1990)
    _check_int(_get(headline, "baseline_year", "kev_latency.headline"),
               "kev_latency.headline.baseline_year", minimum=1990)
    for key in ("median_days_latest", "median_days_baseline"):
        _check_num(_get(headline, key, "kev_latency.headline"),
                   f"kev_latency.headline.{key}", _DAYS_LO, _DAYS_HI)
    _check_num(_get(headline, "pct_over_365d_latest", "kev_latency.headline"),
               "kev_latency.headline.pct_over_365d_latest", 0.0, 100.0)


# -------------------------------------------------------- cna_concentration

def _validate_cna_concentration(obj: Any) -> None:
    _check_generated_at(obj, "cna_concentration")

    entries = _check_list(_get(obj, "years", "cna_concentration"),
                          "cna_concentration.years")
    years = []
    for i, e in enumerate(entries):
        path = f"cna_concentration.years[{i}]"
        year = _get(e, "year", path)
        _check_int(year, f"{path}.year", minimum=1990)
        years.append(year)
        _check_int(_get(e, "cna_count", path), f"{path}.cna_count")
        _check_int(_get(e, "newcomer_count", path), f"{path}.newcomer_count")
        if e["newcomer_count"] > e["cna_count"]:
            _fail(f"{path}.newcomer_count",
                  f"newcomer_count ({e['newcomer_count']}) exceeds "
                  f"cna_count ({e['cna_count']})")
        _check_num(_get(e, "top5_share", path), f"{path}.top5_share",
                   0.0, 100.0)
        _check_num(_get(e, "top10_share", path), f"{path}.top10_share",
                   0.0, 100.0)
        _check_num(_get(e, "hhi", path), f"{path}.hhi", 0.0, _HHI_HI)
    _check_sorted(years, "cna_concentration.years")
    if len(set(years)) != len(years):
        _fail("cna_concentration.years", "duplicate years")

    board = _get(obj, "rejection_leaderboard", "cna_concentration")
    _check_int(_get(board, "window_years",
                    "cna_concentration.rejection_leaderboard"),
               "cna_concentration.rejection_leaderboard.window_years",
               minimum=1)
    _check_int(_get(board, "min_total",
                    "cna_concentration.rejection_leaderboard"),
               "cna_concentration.rejection_leaderboard.min_total",
               minimum=1)
    cnas = _check_list(_get(board, "cnas",
                            "cna_concentration.rejection_leaderboard"),
                       "cna_concentration.rejection_leaderboard.cnas")
    rates = []
    for i, c in enumerate(cnas):
        path = f"cna_concentration.rejection_leaderboard.cnas[{i}]"
        _check_str(_get(c, "cna", path), f"{path}.cna")
        _check_int(_get(c, "total", path), f"{path}.total", minimum=1)
        _check_int(_get(c, "rejected", path), f"{path}.rejected")
        if c["rejected"] > c["total"]:
            _fail(f"{path}.rejected",
                  f"rejected ({c['rejected']}) exceeds total ({c['total']})")
        _check_num(_get(c, "rejected_rate_pct", path),
                   f"{path}.rejected_rate_pct", 0.0, 100.0)
        rates.append(c["rejected_rate_pct"])
    _check_sorted(rates,
                  "cna_concentration.rejection_leaderboard.cnas "
                  "(by rejected_rate_pct)", descending=True)

    headline = _get(obj, "headline", "cna_concentration")
    _check_int(_get(headline, "latest_year", "cna_concentration.headline"),
               "cna_concentration.headline.latest_year", minimum=1990)
    _check_int(_get(headline, "baseline_year", "cna_concentration.headline"),
               "cna_concentration.headline.baseline_year", minimum=1990)
    _check_int(_get(headline, "cna_count_latest",
                    "cna_concentration.headline"),
               "cna_concentration.headline.cna_count_latest")
    for key in ("top5_share_latest", "top5_share_baseline"):
        _check_num(_get(headline, key, "cna_concentration.headline"),
                   f"cna_concentration.headline.{key}", 0.0, 100.0)
    for key in ("hhi_latest", "hhi_baseline"):
        _check_num(_get(headline, key, "cna_concentration.headline"),
                   f"cna_concentration.headline.{key}", 0.0, _HHI_HI)


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "kev_latency.json": _validate_kev_latency,
    "cna_concentration.json": _validate_cna_concentration,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the Tier-1 contract for ``filename``.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no Tier-1 contract.
    """
    VALIDATORS[filename](obj)
