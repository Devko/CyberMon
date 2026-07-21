"""Botnet Weather: the C2 count history Feodo Tracker never keeps
(botnet_weather.json).

abuse.ch's Feodo Tracker publishes the live blocklist of botnet
command-and-control servers — only today's picture. This stage makes
CyberMon the series: every night it snapshots the blocklist (from
``fetch_feodo``), appends per-family daily counts to a committed,
append-only CSV, and emits three sections:

* ``c2_weather`` — active C2s over time by family, drawn from the
  committed count history. Launch-thin by design: the record starts at
  first deploy and deepens one night at a time (the CNA-roster / Silent
  Rescores honesty rule; the page note is data-driven from the record's
  first date). Takedowns show as cliffs; a flat zero is a reading, not a
  gap.
* ``c2_today`` — tonight's snapshot composition: families, hosting
  countries and networks of the listed C2s, online vs dark. Fully real
  from day one. AGGREGATES ONLY — the module renders the weather, never
  the blocklist; no address reaches the emitted JSON.
* ``c2_age`` — the age distribution of tonight's listed C2s (days since
  Feodo Tracker first saw each server) with the median as the headline
  stat. Also meaningful from day one.

Committed history (under ``site/data/history/``, the nvd_backlog.csv
discipline — an original dataset this project accumulates and CANNOT be
regenerated, since the upstream keeps only the current blocklist):

* ``botnet_c2.csv`` — append-only daily counts, long format (columns
  ``date,family,online,listed``): one row per malware family with at
  least one listed C2 that day, PLUS one ``_total`` row per day. The
  ``_total`` row is always written — on an empty-blocklist day it is the
  only row, because the zero IS the weather (the tracker's FAQ documents
  the empty state as the result of takedowns). ``online`` counts entries
  with status ``online`` (answered like a C2 on the tracker's last
  probe); ``listed`` counts everything on the blocklist for that family.
  Per-day family rows must sum to the day's ``_total`` row; the contract
  enforces it. A same-day re-run replaces that day's block rather than
  appending duplicates.

There is NO separate state file: counts are absolute snapshots, not
diffs, so the CSV itself is the whole memory.

Broken-fetch guard (deliberately different from the roster's shrink
guard): single-digit — even zero — counts are NORMAL here, so a count
collapse is never refused; refusing it would censor exactly the takedown
cliffs the module exists to record. The guard is structural instead and
lives in ``fetch_feodo``: malformed documents/entries raise, transient
network errors exhaust a bounded retry and then raise, and a failed run
appends nothing (this stage's CSV write is deferred by ``__main__.run()``
until every output validates, like the other history files).
"""
from __future__ import annotations

import csv
from collections import Counter
from datetime import date as _date
from pathlib import Path
from statistics import median
from typing import Callable

from .fetch_feodo import C2Snapshot

FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures"

CSV_FILENAME = "botnet_c2.csv"
CSV_COLUMNS = ("date", "family", "online", "listed")
TOTAL_KEY = "_total"  # cannot collide with a real family name

# Fixed age buckets (label, min_days inclusive, max_days exclusive).
AGE_BUCKETS = (
    ("under 30 days", 0, 30),
    ("30–90 days", 30, 90),
    ("90 days – 1 year", 90, 365),
    ("1–2 years", 365, 730),
    ("over 2 years", 730, None),
)
AGE_BUCKET_LABELS = tuple(label for label, _lo, _hi in AGE_BUCKETS)


# ----------------------------------------------------------------- CSV I/O

def csv_path(out_dir: Path) -> Path:
    return out_dir / "history" / CSV_FILENAME


def _row_key(row: dict) -> tuple:
    """Deterministic file order: by date, families alphabetically, the
    day's ``_total`` row last (sum after parts)."""
    return (row["date"], row["family"] == TOTAL_KEY, row["family"])


def read_rows(path: Path) -> list[dict]:
    """Read the count history, oldest first. Missing file -> empty.
    Malformed rows fail loudly: this file is the irreplaceable historical
    record, and silent data loss would be worse than a crash."""
    if not path.exists():
        return []
    rows: list[dict] = []
    with path.open("r", newline="", encoding="utf-8") as f:
        for lineno, raw in enumerate(csv.DictReader(f), start=2):
            try:
                row = {"date": raw["date"], "family": raw["family"],
                       "online": int(raw["online"]),
                       "listed": int(raw["listed"])}
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"{path}:{lineno}: malformed botnet row "
                                 f"{raw!r}") from exc
            if len(row["date"]) != 10 or not row["family"] or \
                    row["online"] < 0 or row["listed"] < 0 or \
                    row["online"] > row["listed"]:
                raise ValueError(f"{path}:{lineno}: malformed botnet row "
                                 f"{raw!r}")
            rows.append(row)
    return rows


def write_rows(path: Path, rows: list[dict]) -> None:
    """Rewrite the CSV atomically (temp file, then ``replace``) — an
    interrupted run must leave either the old file or the new one, never
    a truncation (the nvd_backlog.csv pattern)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    tmp.replace(path)


def rows_for_snapshot(snapshot: C2Snapshot, day: str) -> list[dict]:
    """Tonight's CSV rows: one per family present, plus the ``_total``
    row — which is always present, so an empty blocklist still records
    its zero (the zero is the weather)."""
    listed: Counter = Counter()
    online: Counter = Counter()
    for e in snapshot.entries:
        listed[e.family] += 1
        if e.online:
            online[e.family] += 1
    rows = [{"date": day, "family": fam, "online": online.get(fam, 0),
             "listed": n} for fam, n in sorted(listed.items())]
    rows.append({"date": day, "family": TOTAL_KEY,
                 "online": sum(online.values()),
                 "listed": sum(listed.values())})
    return rows


def merge_day(rows: list[dict], day_rows: list[dict]) -> list[dict]:
    """Merge one day's rows into the record: the last run of a given date
    wins (a same-day re-run replaces that day's block, never duplicates
    it). Returns a new, deterministically ordered list."""
    day = day_rows[0]["date"]
    merged = [r for r in rows if r["date"] != day] + list(day_rows)
    merged.sort(key=_row_key)
    return merged


def persist(out_dir: Path, rows: list[dict],
            log: Callable[[str], None] = print) -> None:
    """Write the count history — called by ``__main__.run()`` only after
    every pipeline output has validated."""
    write_rows(csv_path(out_dir), rows)
    days = len({r["date"] for r in rows})
    log(f"  botnet-weather: {days} day(s) on record in {csv_path(out_dir)}")


# ----------------------------------------------------------------- metrics

def _breakdown(counter: Counter) -> list[dict]:
    """A ``[{label, n}]`` list sorted by count descending, ties by label
    ascending — the roster_mix shape."""
    items = [{"label": label, "n": n} for label, n in counter.items()]
    items.sort(key=lambda d: (-d["n"], d["label"]))
    return items


def _age_days(first_seen: str, day: str) -> int:
    """Whole days between a C2's first_seen date and the snapshot date,
    clamped at zero (a stamp from the future is upstream noise, not a
    negative age)."""
    delta = (_date.fromisoformat(day) - _date.fromisoformat(first_seen)).days
    return max(0, delta)


def build_weather_series(rows: list[dict]) -> tuple[list[str], list[dict]]:
    """(family union sorted, per-day series) from the committed record.
    Totals come from each day's ``_total`` row — a day without one means
    the record is corrupt, and the loud failure is deliberate."""
    by_day: dict[str, list[dict]] = {}
    for r in rows:
        by_day.setdefault(r["date"], []).append(r)
    families = sorted({r["family"] for r in rows if r["family"] != TOTAL_KEY})
    series = []
    for day in sorted(by_day):
        day_rows = by_day[day]
        totals = [r for r in day_rows if r["family"] == TOTAL_KEY]
        if len(totals) != 1:
            raise ValueError(f"botnet-weather: day {day} has {len(totals)} "
                             f"_total rows in the count history")
        fam_rows = [r for r in day_rows if r["family"] != TOTAL_KEY]
        series.append({
            "date": day,
            "online": {r["family"]: r["online"] for r in fam_rows},
            "listed": {r["family"]: r["listed"] for r in fam_rows},
            "online_total": totals[0]["online"],
            "listed_total": totals[0]["listed"],
        })
    return families, series


def build_c2_today(snapshot: C2Snapshot, day: str) -> dict:
    """Tonight's composition — aggregates only, fully real from day one.
    Empty blocklist -> empty breakdowns with zero totals (honest empty)."""
    listed: Counter = Counter()
    online: Counter = Counter()
    countries: Counter = Counter()
    asns: Counter = Counter()
    for e in snapshot.entries:
        listed[e.family] += 1
        if e.online:
            online[e.family] += 1
        countries[e.country] += 1
        asns[e.as_name] += 1
    families = [{"label": fam, "listed": n, "online": online.get(fam, 0)}
                for fam, n in listed.items()]
    families.sort(key=lambda d: (-d["listed"], d["label"]))
    return {
        "snapshot_date": day,
        "listed_total": snapshot.entry_count,
        "online_total": snapshot.online_count,
        "families": families,
        "countries": _breakdown(countries),
        "asns": _breakdown(asns),
    }


def build_c2_age(snapshot: C2Snapshot, day: str) -> dict:
    """The age distribution of tonight's listed C2s: days since Feodo
    Tracker first saw each server, in fixed buckets, with the median (and
    the oldest) as headline stats — null when the list is empty."""
    ages = sorted(_age_days(e.first_seen, day) for e in snapshot.entries)
    counts = dict.fromkeys(AGE_BUCKET_LABELS, 0)
    for age in ages:
        for label, lo, hi in AGE_BUCKETS:
            if age >= lo and (hi is None or age < hi):
                counts[label] += 1
                break
    return {
        "snapshot_date": day,
        "n": len(ages),
        "median_age_days": int(round(median(ages))) if ages else None,
        "oldest_age_days": ages[-1] if ages else None,
        "buckets": [{"label": label, "n": counts[label]}
                    for label in AGE_BUCKET_LABELS],
    }


def build_botnet_weather(rows: list[dict], snapshot: C2Snapshot,
                         generated_at: str) -> dict:
    """Assemble botnet_weather.json from the merged count history (which
    already includes tonight's rows) and tonight's snapshot."""
    day = generated_at[:10]
    families, series = build_weather_series(rows)
    today = build_c2_today(snapshot, day)
    catalog_families = sorted({e.family for e in snapshot.entries})
    return {
        "generated_at": generated_at,
        "c2_weather": {
            "first_observed": series[0]["date"],
            "families": families,
            "series": series,
            "current_online": series[-1]["online_total"],
            "current_listed": series[-1]["listed_total"],
        },
        "c2_today": today,
        "c2_age": build_c2_age(snapshot, day),
        "catalog": {
            "snapshot_size": snapshot.entry_count,
            "online_now": snapshot.online_count,
            "families": catalog_families,
            "family_count": len(catalog_families),
            "first_date": series[0]["date"],
            "last_date": series[-1]["date"],
            "days_observed": len(series),
        },
    }


def _source(fetched_at: str, snapshot: C2Snapshot) -> dict:
    return {"fetched_at": fetched_at, "listed": snapshot.entry_count,
            "online": snapshot.online_count}


# --------------------------------------------------------------- the stage

def run_stage(out_dir: Path, generated_at: str, *, snapshot: C2Snapshot,
              offline_fixtures: bool, log: Callable[[str], None] = print
              ) -> tuple[dict, dict, list[dict]]:
    """(botnet_weather.json object, meta.sources.feodo, merged CSV rows
    for run() to persist after validation).

    * ``offline_fixtures`` — when no committed history exists yet, the
      run seeds prior days from fixtures/botnet_c2.csv so the hero series
      has depth to exercise; a second run then hits the committed file
      (idempotent same-day merge). No network either way.
    * live — tonight's counts merge into the committed record (same-day
      re-run replaces, never duplicates). First ever run = a one-day
      record: the series honestly starts as a single point.
    """
    today = generated_at[:10]
    rows = read_rows(csv_path(out_dir))
    if offline_fixtures and not rows:
        rows = read_rows(FIXTURES_DIR / CSV_FILENAME)
        log(f"  botnet-weather: seeded prior history from fixtures "
            f"({len({r['date'] for r in rows})} day(s))")
    rows = merge_day(rows, rows_for_snapshot(snapshot, today))
    obj = build_botnet_weather(rows, snapshot, generated_at)
    log(f"  botnet-weather: {snapshot.entry_count} C2(s) listed "
        f"({snapshot.online_count} online), "
        f"{obj['catalog']['days_observed']} day(s) on record")
    return obj, _source(generated_at, snapshot), rows
