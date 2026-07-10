"""Hygiene Index metrics (dnssec_adoption.json).

DNSSEC validation is the module's boring-hygiene proxy: the fix is two
decades old, free to enable, and measurably not deployed. Everything
here reads APNIC Labs' 30-day smoothed window (see fetch_dnssec).

Three blocks, one per chart:

* **world** — the world aggregate (XA) sampled to one point per
  calendar month (the last published day of each month), plus the exact
  newest day and a payload-authoritative decade-ago baseline: the point
  120 months before the newest month when APNIC's record reaches back
  that far, else the record's first month. Consumers never derive the
  baseline themselves.
* **economies** — the fixed ten-economy set (fetch_dnssec.ECONOMIES),
  each sampled to quarter-end months (Mar/Jun/Sep/Dec, last published
  day of each) plus the newest available month, ranked by current rate.
* **spread** — the one-economy-one-vote distribution from the world-map
  snapshot: economies with at least ``min_seen`` samples in the current
  30-day window, bucketed by validation rate. The sample floor exists
  because a rate measured on a few hundred ad impressions is an
  anecdote; 10,000 keeps ~200 of ~240 measured economies.

APNIC's percentages arrive with 6 decimals; everything emitted here is
rounded to 1 (the house float rule).
"""
from __future__ import annotations

import time
from pathlib import Path

from .fetch_dnssec import ECONOMIES, DnssecData, DnssecPoint, EconomySnapshot

FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures"

# Spread histogram, fixed order, lower edge inclusive.
SPREAD_BUCKETS = ["<10%", "10-25%", "25-50%", "50-75%", "75%+"]

# Minimum 30-day sample count for an economy to join the spread.
MIN_SEEN = 10_000

_QUARTER_END_MONTHS = {"03", "06", "09", "12"}


def _r1(v: float) -> float:
    return round(float(v), 1)


def spread_bucket(validating_pc: float) -> str:
    """Bucket label for a validation rate (lower edge inclusive)."""
    if validating_pc < 10:
        return SPREAD_BUCKETS[0]
    if validating_pc < 25:
        return SPREAD_BUCKETS[1]
    if validating_pc < 50:
        return SPREAD_BUCKETS[2]
    if validating_pc < 75:
        return SPREAD_BUCKETS[3]
    return SPREAD_BUCKETS[4]


def _last_per_month(points: list[DnssecPoint]) -> dict[str, DnssecPoint]:
    """month (YYYY-MM) -> that month's last (newest) point.

    Input is sorted ascending by date (parse_series guarantees it), so
    a plain overwrite keeps the newest.
    """
    by_month: dict[str, DnssecPoint] = {}
    for p in points:
        by_month[p.date[:7]] = p
    return by_month


def monthly_series(points: list[DnssecPoint]) -> list[dict]:
    """One {month, validating_pc} sample per calendar month."""
    by_month = _last_per_month(points)
    return [{"month": month, "validating_pc": _r1(p.validating_pc)}
            for month, p in sorted(by_month.items())]


def quarterly_series(points: list[DnssecPoint]) -> list[dict]:
    """Quarter-end months (Mar/Jun/Sep/Dec) plus the newest month.

    Ten economies at monthly density would triple the payload for no
    visible change in a decade-scale line; quarter-end sampling keeps
    the shape. The newest month always joins so the line ends today.
    """
    by_month = _last_per_month(points)
    if not by_month:
        return []
    newest = max(by_month)
    months = {m for m in by_month if m[5:7] in _QUARTER_END_MONTHS}
    months.add(newest)
    return [{"month": month, "validating_pc": _r1(by_month[month].validating_pc)}
            for month in sorted(months)]


def _decade_baseline(monthly: list[dict]) -> dict:
    """The point 120 months before the newest month, else the first.

    Month arithmetic on the YYYY-MM strings; no calendar edge cases
    because months are whole.
    """
    newest = monthly[-1]["month"]
    year, month = int(newest[:4]), int(newest[5:7])
    target = f"{year - 10:04d}-{month:02d}"
    for entry in monthly:
        if entry["month"] == target:
            return dict(entry)
    return dict(monthly[0])


def build_spread(snapshot: list[EconomySnapshot],
                 *, min_seen: int = MIN_SEEN) -> dict:
    """The one-economy-one-vote distribution block."""
    kept = [row for row in snapshot if row.seen >= min_seen]
    counts = {bucket: 0 for bucket in SPREAD_BUCKETS}
    for row in kept:
        counts[spread_bucket(row.validating_pc)] += 1
    return {
        "min_seen": min_seen,
        "n_economies": len(kept),
        "buckets": [{"bucket": bucket, "n": counts[bucket]}
                    for bucket in SPREAD_BUCKETS],
    }


def build_dnssec_adoption(data: DnssecData, generated_at: str,
                          *, min_seen: int = MIN_SEEN) -> dict:
    """Assemble the dnssec_adoption.json object."""
    world_monthly = monthly_series(data.world.points)
    latest_point = data.world.points[-1]

    economies = []
    for cc, name in ECONOMIES:
        series = data.economies.get(cc)
        if series is None or not series.points:
            # Fixture subsets carry fewer series than the fixed set
            # (market's "terms the state covers" precedent); a live run
            # always fetches all ten or fails in the fetcher.
            continue
        economies.append({
            "cc": cc,
            "name": name,
            "latest_pc": _r1(series.points[-1].validating_pc),
            "series": quarterly_series(series.points),
        })
    economies.sort(key=lambda e: (-e["latest_pc"], e["cc"]))

    return {
        "generated_at": generated_at,
        "window": "30_day",
        "world": {
            "cc": data.world.cc,
            "series": world_monthly,
            "latest": {
                "date": latest_point.date,
                "validating_pc": _r1(latest_point.validating_pc),
                "partial_pc": _r1(latest_point.partial_pc),
                "seen": latest_point.seen,
            },
            "baseline": _decade_baseline(world_monthly),
        },
        "economies": economies,
        "spread": build_spread(data.snapshot, min_seen=min_seen),
    }


def _load_fixtures() -> DnssecData:
    """The hand-written fixture set under tests/fixtures/dnssec/.

    World (XA) plus whichever economy series exist as <CC>.json —
    the fixture set deliberately covers a subset of ECONOMIES.
    """
    from .fetch_dnssec import load_index_file, load_series_file

    fixtures = FIXTURES_DIR / "dnssec"
    world = load_series_file(fixtures / "XA.json", "XA")
    economies = {}
    for cc, _label in ECONOMIES:
        path = fixtures / f"{cc}.json"
        if path.exists():
            economies[cc] = load_series_file(path, cc)
    snapshot = load_index_file(fixtures / "index.html", min_rows=5)
    return DnssecData(world=world, economies=economies, snapshot=snapshot)


def run_stage(generated_at: str, *, offline_fixtures: bool,
              session=None, sleep=time.sleep, log=print
              ) -> tuple[dict, dict]:
    """(dnssec_adoption.json object, meta.sources.apnic object).

    No skip flag and no cache: upstream publishes its full history, so
    every night rebuilds from scratch (the KEV/EPSS pattern, not the
    NVD one). A fetch or parse failure raises and fails the run — the
    house failure mode is a loud workflow, never a quietly stale chart.
    """
    if offline_fixtures:
        data = _load_fixtures()
    else:
        from .fetch_dnssec import fetch_dnssec

        log("fetching APNIC DNSSEC validation series ...")
        data = fetch_dnssec(session=session, sleep=sleep, log=log)
    obj = build_dnssec_adoption(data, generated_at)
    source = {"fetched_at": generated_at,
              "economy_count": len(obj["economies"]),
              "spread_economy_count": obj["spread"]["n_economies"]}
    return obj, source
