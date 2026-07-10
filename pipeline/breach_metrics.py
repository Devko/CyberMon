"""Breach disclosure ledger metrics (breach_ledger.json).

How long does a breach take to reach the public record? Lag =
``AddedDate - BreachDate`` in days, per calendar year of cataloguing.
A lag can be negative (a breach catalogued before its self-reported
breach date — BreachDate is usually rounded to the first of a month);
negative lags are KEPT, never floored to zero, the same rule the KEV
latency module applies: flooring would hide a date-quality signal.

Cohort rule (the ledger counts breaches of organizations):

* ``IsFabricated`` — excluded: the incident never happened;
* ``IsSpamList`` — excluded: address collections, no breached org;
* ``IsMalware`` / ``IsStealerLog`` — excluded: real credential theft,
  but harvested device-by-device from malware victims; there is no
  single breached organization, and the nominal ``BreachDate``
  describes the compilation of the corpus rather than an incident,
  which would poison the lag stats.

Each excluded entry is counted under the FIRST matching reason (the
order above), so ``catalog.cohort + sum(excluded) == catalog.total``
always holds — the emitted ``catalog`` block is the audit trail.

Import era: HIBP launched 2013-12-04 with an opening catalog of
already-public breaches — in the live feed, six of its seven December
2013 entries predate the service itself (median nominal lag 511 days),
while from the first full calendar year the catalog ran live (the 2014
median collapses to 5 days). Entries added before
:data:`IMPORT_CUTOFF` therefore measure the import of the back
catalog and are excluded from the lag trend and headline, reported
once as ``import_era`` (mirrors kev_metrics' launch backfill).
Pre-2014 *breaches* surfacing in later years stay in the trend on
purpose: a breach surfacing years late is the measured phenomenon;
only the opening import is an artifact of the catalog's own birthday.

Volume and data-class shares include ALL cohort years, import era too
(kev_ransomware reasoning: a catalogued breach is a catalogued breach;
only the lag stat is distorted by the import).
"""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from datetime import date
from typing import Iterable

from .fetch_hibp import HibpBreach
from .kev_metrics import _parse_date
from .metrics import _pct, _quartiles, _r1, pace_projection, year_elapsed

# HIBP launched 2013-12-04; December 2013 is the opening-import month.
# Anything added before this cutoff is the import-era cohort, not
# disclosure-speed signal (see module docstring for the data argument).
IMPORT_CUTOFF = "2014-01-01"

# Exclusion reasons, in precedence order (first match wins).
EXCLUSION_REASONS = ["fabricated", "spam_list", "malware", "stealer_log"]

# The "what leaks" chart tracks this many top data classes.
TOP_CLASSES = 6


def _exclusion_reason(b: HibpBreach) -> str | None:
    """First matching exclusion reason, or None for a cohort breach."""
    if b.is_fabricated:
        return "fabricated"
    if b.is_spam_list:
        return "spam_list"
    if b.is_malware:
        return "malware"
    if b.is_stealer_log:
        return "stealer_log"
    return None


def split_cohort(breaches: Iterable[HibpBreach]
                 ) -> tuple[list[HibpBreach], dict[str, int]]:
    """(cohort breaches, exclusion counts by first matching reason)."""
    cohort: list[HibpBreach] = []
    excluded = {reason: 0 for reason in EXCLUSION_REASONS}
    for b in breaches:
        reason = _exclusion_reason(b)
        if reason is None:
            cohort.append(b)
        else:
            excluded[reason] += 1
    return cohort, excluded


def build_breach_ledger(breaches: Iterable[HibpBreach], generated_at: str,
                        *, min_n: int = 10, top_k: int = TOP_CLASSES) -> dict:
    """Assemble the breach_ledger.json object.

    Per-year charts key off the ``AddedDate`` calendar year; entries with
    an unparseable ``AddedDate`` join no year but still count in the
    ``catalog`` block. Lag stats additionally need a parseable
    ``BreachDate``. Years with fewer than ``min_n`` cohort breaches never
    plot in the lag or class-share charts (a median of three breaches is
    an anecdote); the volume chart is unfiltered — counts are counts.
    """
    breaches = list(breaches)
    cohort, excluded = split_cohort(breaches)
    cutoff = date.fromisoformat(IMPORT_CUTOFF)

    import_lags: list[int] = []
    lags_by_year: dict[int, list[int]] = defaultdict(list)
    breaches_by_year: Counter[int] = Counter()
    records_by_year: Counter[int] = Counter()
    classes_by_year: dict[int, Counter[str]] = defaultdict(Counter)
    class_totals: Counter[str] = Counter()

    for b in cohort:
        added = _parse_date(b.added_date)
        if added is None:  # catalog block only: no year to join
            continue
        breaches_by_year[added.year] += 1
        records_by_year[added.year] += b.pwn_count
        classes = set(b.data_classes)  # at most once per breach
        classes_by_year[added.year].update(classes)
        class_totals.update(classes)
        breached = _parse_date(b.breach_date)
        if breached is None:
            continue
        lag = (added - breached).days
        if added < cutoff:
            import_lags.append(lag)
        else:
            lags_by_year[added.year].append(lag)

    # ---- hero: disclosure lag per catalog year (import era excluded) ----
    lag_by_year = []
    for year in sorted(lags_by_year):
        lags = lags_by_year[year]
        if len(lags) < min_n:
            continue
        p25, median, p75 = _quartiles([float(v) for v in lags])
        n = len(lags)
        lag_by_year.append({
            "year": year, "n": n,
            "median_days": _r1(median),
            "p25_days": _r1(p25), "p75_days": _r1(p75),
            "pct_negative": _pct(sum(1 for v in lags if v < 0), n),
            "pct_over_365d": _pct(sum(1 for v in lags if v > 365), n),
        })

    # ---- volume: breaches + records exposed per catalog year ------------
    volume_by_year = [{"year": year, "breaches": breaches_by_year[year],
                       "records": records_by_year[year]}
                      for year in sorted(breaches_by_year)]

    # ---- what leaks: top classes by all-time frequency, share per year --
    # Ties break alphabetically so the emitted list is deterministic.
    top_classes = [name for name, _ in
                   sorted(class_totals.items(),
                          key=lambda kv: (-kv[1], kv[0]))[:top_k]]
    class_years = []
    for year in sorted(breaches_by_year):
        n = breaches_by_year[year]
        if n < min_n:
            continue
        class_years.append({
            "year": year, "n": n,
            "shares": {name: _pct(classes_by_year[year].get(name, 0), n)
                       for name in top_classes},
        })

    # ---- headline: the pooled trend + the last complete plotted year ----
    # (kev_metrics current-year rule: never lean on the partial year; fall
    # back to it only when nothing else survived the filters.)
    trend_lags = [v for lags in lags_by_year.values() for v in lags]
    current_year = int(generated_at[:4])
    full_years = [row for row in lag_by_year if row["year"] < current_year]
    latest = full_years[-1] if full_years else \
        (lag_by_year[-1] if lag_by_year else None)
    headline = {
        "trend_n": len(trend_lags),
        "median_days": _r1(statistics.median(trend_lags))
                       if trend_lags else 0.0,
        "pct_over_365d": _pct(sum(1 for v in trend_lags if v > 365),
                              len(trend_lags)),
        "latest_year": latest["year"] if latest else 0,
        "median_days_latest": latest["median_days"] if latest else 0.0,
    }

    out = {
        "generated_at": generated_at,
        "min_n": min_n,
        "catalog": {
            "total": len(breaches),
            "cohort": len(cohort),
            "excluded": excluded,
        },
        "import_era": {
            "added_before": IMPORT_CUTOFF,
            "n": len(import_lags),
            "median_days": _r1(statistics.median(import_lags))
                           if import_lags else None,
        },
        "lag_by_year": lag_by_year,
        "volume_by_year": volume_by_year,
        "class_shares": {"classes": top_classes, "years": class_years},
        "headline": headline,
    }

    # Breaches catalogued per year are a flow, so the partial current year
    # gets a pace projection (docs/data-contracts.md, "Pace projections").
    # Records exposed are deliberately NOT projected: one mega-dump can
    # outweigh the rest of the year, so a records pace would present one
    # upload schedule as a forecast.
    projected = pace_projection(breaches_by_year.get(current_year, 0),
                                generated_at)
    if projected is not None:
        out["projection"] = {"year": current_year, "breaches": projected,
                             "elapsed": round(year_elapsed(generated_at), 3)}
    return out
