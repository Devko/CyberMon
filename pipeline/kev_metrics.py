"""KEV exploitation-latency metrics (kev_latency.json).

How long after a CVE record is published does CISA list it as Known
Exploited? Latency = ``dateAdded - datePublished`` in days. Negative
latency is KEPT, never floored to zero: CISA listing a vulnerability
before its CVE record publishes is real signal (exploitation observed
while the record was still reserved), not a data error.

Cohorts:

* **launch backfill** — KEV launched 2021-11-03 with a bulk back-catalog
  of old exploited CVEs; entries with ``dateAdded`` before
  :data:`LAUNCH_CUTOFF` say nothing about detection speed, so they are
  excluded from every trend stat and reported separately;
* **trend** — matched entries with ``dateAdded >=`` the cutoff; these
  feed ``latency_by_year``, ``latency_buckets`` and the headline.

Remediation span (``dueDate - dateAdded``) is a policy choice CISA makes
at listing time, real regardless of CVE age — it is grouped by dateAdded
year over ALL cohorts, including the 2021 launch.

KEV ids with no ``datePublished`` join in the aggregated corpus are
counted in ``matched.unmatched_cve`` and excluded from all stats.

Vintage (the KEV vintage section) reuses the same latency as an age at
listing: ``vintage_by_year`` splits each trend year's listings older than
a year into the 1-3y / 3-5y / 5-10y / 10y+ buckets, and
``oldest_recent`` names the oldest CVEs listed in the 365 days ending on
the edition date (any cohort; the window is recent by construction).

Ransomware share (kev_ransomware.json) needs no CVE join at all: it is the
catalog's own ``knownRansomwareCampaignUse`` flag grouped by ``dateAdded``
year. Like the remediation spans, ALL cohorts belong — the catalog snapshot
carries CISA's current assessment on every entry, seeding era included, so
a 2021 back-catalog import is as chartable as a fresh listing.
"""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from datetime import date, timedelta
from typing import Iterable

from .fetch_kev import KevEntry
from .metrics import Aggregator, _pct, _quartiles, _r1

# KEV launched 2021-11-03 with a bulk back-catalog, and the seeding waves
# ran through 2022 (real data: median nominal "latency" of 2022 additions
# is 1,436 days vs 12 days in 2023 — a regime change, not a trend).
# Anything dated before this cutoff is the seeding-era cohort, not
# detection-speed signal.
LAUNCH_CUTOFF = "2023-01-01"

# Fixed bucket order (lower edge inclusive): negative, 0-7, 8-30, 31-90,
# 91-365, 366-1095, 1096-1825, 1826-3650, >=3651 days (years of 365 days).
# Until 2026-11-05 the last three were one "3y+" bucket; splitting it shows
# how old the old tail is (the KEV vintage section).
BUCKETS = ["before_publish", "0-7d", "8-30d", "31-90d", "91-365d",
           "1-3y", "3-5y", "5-10y", "10y+"]
# The buckets past a year: the vintage section's per-year split.
OLD_BUCKETS = ["1-3y", "3-5y", "5-10y", "10y+"]
# "Last 12 months" for the oldest-recent-listings callout, and how many of
# the oldest listings in that window the callout names.
RECENT_WINDOW_DAYS = 365
OLDEST_SHOWN = 10
DECADE_DAYS = 3650


def latency_bucket(days: int) -> str:
    """Bucket label for a latency in days (lower edge inclusive)."""
    if days < 0:
        return "before_publish"
    if days <= 7:
        return "0-7d"
    if days <= 30:
        return "8-30d"
    if days <= 90:
        return "31-90d"
    if days <= 365:
        return "91-365d"
    if days <= 1095:
        return "1-3y"
    if days <= 1825:
        return "3-5y"
    if days <= DECADE_DAYS:
        return "5-10y"
    return "10y+"


def _parse_date(s: object) -> date | None:
    """Day-precision date from an ISO string, None when absent/malformed."""
    if not isinstance(s, str) or len(s) < 10:
        return None
    try:
        return date.fromisoformat(s[:10])
    except ValueError:
        return None


def _ransomware_known(entry: KevEntry) -> bool:
    """True only for an explicit "Known" flag; a missing or "Unknown"
    field never counts as ransomware use."""
    return (entry.ransomware_use or "").strip().lower() == "known"


def build_kev_ransomware(entries: Iterable[KevEntry],
                         generated_at: str, *, min_n: int = 10) -> dict:
    """Assemble the kev_ransomware.json object.

    Per ``dateAdded`` calendar year: entries added, entries flagged
    "Known" for ransomware campaign use, and the share. Entries with an
    unparseable ``dateAdded`` cannot join a year but still count in the
    catalog-wide totals. Years with fewer than ``min_n`` entries never
    plot (a share of three listings is an anecdote).
    """
    entries = list(entries)
    total_by_year: Counter[int] = Counter()
    known_by_year: Counter[int] = Counter()
    for entry in entries:
        added = _parse_date(entry.date_added)
        if added is None:
            continue
        total_by_year[added.year] += 1
        if _ransomware_known(entry):
            known_by_year[added.year] += 1

    years = []
    for year in sorted(total_by_year):
        total = total_by_year[year]
        if total < min_n:
            continue
        known = known_by_year.get(year, 0)
        years.append({"year": year, "total": total, "known": known,
                      "pct_known": _pct(known, total)})

    catalog_known = sum(1 for e in entries if _ransomware_known(e))
    return {
        "generated_at": generated_at,
        "min_n": min_n,
        "years": years,
        "catalog": {"total": len(entries), "known": catalog_known,
                    "pct_known": _pct(catalog_known, len(entries))},
    }


def build_kev_latency(agg: Aggregator, entries: Iterable[KevEntry],
                      generated_at: str, *, min_n: int = 10) -> dict:
    """Assemble the kev_latency.json object.

    ``agg.kev_published_dates`` provides the CVE-id -> datePublished join
    (populated during the corpus pass for the ids in ``agg.kev_ids``).
    Years with fewer than ``min_n`` data points never plot — a median of
    three latencies is an anecdote, not a trend.
    """
    entries = list(entries)
    cutoff = date.fromisoformat(LAUNCH_CUTOFF)
    edition = date.fromisoformat(generated_at[:10])
    window_start = edition - timedelta(days=RECENT_WINDOW_DAYS - 1)
    unmatched = 0
    backfill_latencies: list[int] = []
    trend_by_year: dict[int, list[int]] = defaultdict(list)
    spans_by_year: dict[int, list[int]] = defaultdict(list)
    recent: list[tuple[int, str, date, date]] = []

    for entry in entries:
        published = _parse_date(agg.kev_published_dates.get(entry.cve_id))
        if published is None:
            unmatched += 1
            continue
        added = _parse_date(entry.date_added)
        if added is None:  # matched but undated: cannot contribute stats
            continue
        latency = (added - published).days
        if window_start <= added <= edition:
            recent.append((latency, entry.cve_id, added, published))
        if added < cutoff:
            backfill_latencies.append(latency)
        else:
            trend_by_year[added.year].append(latency)
        due = _parse_date(entry.due_date)  # missing/blank dueDate skipped
        if due is not None:
            spans_by_year[added.year].append((due - added).days)

    latency_by_year = []
    for year in sorted(trend_by_year):
        latencies = trend_by_year[year]
        if len(latencies) < min_n:
            continue
        p25, median, p75 = _quartiles([float(v) for v in latencies])
        n = len(latencies)
        latency_by_year.append({
            "year": year, "n": n,
            "median_days": _r1(median),
            "p25_days": _r1(p25), "p75_days": _r1(p75),
            "pct_negative": _pct(sum(1 for v in latencies if v < 0), n),
            "pct_over_365d": _pct(sum(1 for v in latencies if v > 365), n),
        })

    trend_all = [v for latencies in trend_by_year.values() for v in latencies]
    bucket_counts: Counter[str] = Counter(latency_bucket(v) for v in trend_all)
    latency_buckets = [{"bucket": b, "n": bucket_counts.get(b, 0),
                        "pct": _pct(bucket_counts.get(b, 0), len(trend_all))}
                       for b in BUCKETS]

    # Vintage: per trend year, the listings whose CVE was more than a year
    # old, split by the old-tail buckets (the same edges as above).
    vintage_by_year = []
    for row in latency_by_year:
        latencies = trend_by_year[row["year"]]
        n = len(latencies)
        counts = Counter(latency_bucket(v) for v in latencies)
        over = sum(counts.get(b, 0) for b in OLD_BUCKETS)
        vintage_by_year.append({
            "year": row["year"], "n": n,
            "over_1y": over, "pct_over_1y": _pct(over, n),
            "buckets": [{"bucket": b, "n": counts.get(b, 0),
                         "pct": _pct(counts.get(b, 0), n)}
                        for b in OLD_BUCKETS],
        })

    # Oldest CVEs listed in the RECENT_WINDOW_DAYS ending on the edition
    # date: oldest first, ties by id so the list is stable.
    recent.sort(key=lambda r: (-r[0], r[1]))
    oldest_recent = {
        "window_days": RECENT_WINDOW_DAYS,
        "since": window_start.isoformat(),
        "until": edition.isoformat(),
        "n_listed": len(recent),
        "n_over_10y": sum(1 for r in recent if r[0] > DECADE_DAYS),
        "entries": [{"cve_id": cve_id, "date_added": added.isoformat(),
                     "date_published": published.isoformat(),
                     "age_days": latency}
                    for latency, cve_id, added, published
                    in recent[:OLDEST_SHOWN]],
    }

    remediation_span_by_year = []
    for year in sorted(spans_by_year):
        spans = spans_by_year[year]
        if len(spans) < min_n:
            continue
        p25, median, p75 = _quartiles([float(v) for v in spans])
        remediation_span_by_year.append({
            "year": year, "n": len(spans),
            "median_days": _r1(median),
            "p25_days": _r1(p25), "p75_days": _r1(p75),
        })

    # Headline mirrors metrics.build_severity_inflation's current-year rule:
    # never lean on the partial current year; fall back to the earliest year
    # that survived the filters. Baseline = latest - 3 when present.
    current_year = int(generated_at[:4])
    full_years = [row for row in latency_by_year
                  if row["year"] < current_year]
    latest = full_years[-1] if full_years else \
        (latency_by_year[-1] if latency_by_year else None)
    latest_year = latest["year"] if latest else 0
    by_year = {row["year"]: row for row in latency_by_year}
    baseline = by_year.get(latest_year - 3,
                           latency_by_year[0] if latency_by_year else None)

    return {
        "generated_at": generated_at,
        "matched": {
            "total_kev": len(entries),
            "matched_cve": len(entries) - unmatched,
            "unmatched_cve": unmatched,
        },
        "launch_backfill": {
            "date_added_before": LAUNCH_CUTOFF,
            "n": len(backfill_latencies),
            "median_days": _r1(statistics.median(backfill_latencies))
                           if backfill_latencies else None,
        },
        "latency_by_year": latency_by_year,
        "latency_buckets": latency_buckets,
        "vintage_by_year": vintage_by_year,
        "oldest_recent": oldest_recent,
        "remediation_span_by_year": remediation_span_by_year,
        "headline": {
            "latest_year": latest_year,
            "median_days_latest": latest["median_days"] if latest else 0.0,
            "pct_over_365d_latest":
                latest["pct_over_365d"] if latest else 0.0,
            "baseline_year": baseline["year"] if baseline else 0,
            "median_days_baseline":
                baseline["median_days"] if baseline else 0.0,
        },
    }
