"""EPSS Report Card metrics: grading the forecast against the outcome.

Per-entry day-before facts arrive as sync state maintained by
``fetch_epss_history`` (``{"entries": {"CVE|dateAdded": {score_date, epss,
percentile, model, reason}}}``); this module is the assembly layer plus
stage orchestration:

* :func:`build_epss_report` — classifies every current KEV entry against
  the state and emits the epss_report.json object. The ``entries[]`` in
  the output are EXACTLY the state's per-entry records plus the key fields
  (cve, date_added) — that identity is a designed guarantee:
  ``fetch_epss_history.reconstruct_state`` rebuilds the full sync state
  from the published file, so a lost CI cache never re-triggers the
  historical backfill (docs/data-contracts.md documents the round-trip);
* :func:`run_stage` — the __main__-facing stage: offline fixtures,
  --skip-epss-report carry-forward, or a live sync via
  ``fetch_epss_history``.

Honesty rules encoded here (the site methodology quotes them):

* An entry counts as **graded** only when a day-before score existed.
  Entries with no possible prior score are never misses: a KEV entry
  listed before (or on the day of) its CVE's publication could not have
  been scored — those are classified ``listed_before_publication`` using
  the CVE corpus's datePublished join and reported separately.
* KEV pairs not yet looked up are **pending backfill** — published as
  counts (whole-catalog and per-year) so a partially backfilled state
  renders honestly rather than masquerading as a complete grade.
* Grade bands use the day-before probability: below 1%, 1–10%, at or
  above 10% (lower edges inclusive, matching score_vs_reality's bucket
  arithmetic). The distribution splits by model era because EPSS versions
  differ materially — mixing them silently would be the CVSS-v2-vs-v3
  landmine all over again. Percentiles are comparable across model
  versions in a way raw probabilities are not (each day's percentile
  ranks that day's scored corpus), which is the percentile section's job.
"""
from __future__ import annotations

import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Callable, Iterable

from .fetch_epss_history import (MODEL_LABELS, entry_key, known_model_version,
                                 live_fetcher, load_state, model_eras_block,
                                 reconstruct_state, save_state, sync_state)
from .fetch_kev import KevEntry
from .metrics import _pct, _r1

FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures"

# Log-ish probability buckets, identical to score_vs_reality's EPSS axis
# (contracts.EPSS_BUCKETS); lower edges inclusive.
DIST_BUCKETS = ["<0.1%", "0.1-1%", "1-10%", ">10%"]

# Day-before percentile buckets (percentiles are 0-1 upstream, presented
# 0-100); lower edges inclusive.
PERCENTILE_BUCKETS = ["0-25", "25-50", "50-75", "75-90", "90-99", "99-100"]

# Ungradeable classification (refines the state's fetch-time reasons with
# the CVE corpus's publication dates — exactly these three keys ship).
UNGRADEABLE_REASONS = ("pre_epss", "listed_before_publication",
                       "no_prior_score")


def dist_bucket(epss: float) -> str:
    """score_vs_reality's EPSS bucket arithmetic, applied to the
    day-before probability."""
    if epss < 0.001:
        return "<0.1%"
    if epss < 0.01:
        return "0.1-1%"
    if epss < 0.1:
        return "1-10%"
    return ">10%"


def percentile_bucket(percentile: float) -> str:
    """Bucket label for a 0-1 percentile (lower edges inclusive)."""
    pct = percentile * 100.0
    if pct < 25.0:
        return "0-25"
    if pct < 50.0:
        return "25-50"
    if pct < 75.0:
        return "50-75"
    if pct < 90.0:
        return "75-90"
    if pct < 99.0:
        return "90-99"
    return "99-100"


def _classify_ungradeable(reason: str, date_added: str,
                          published: str | None) -> str:
    """Refine a fetch-time null-score reason with the corpus join: an
    entry whose CVE published on or after its listing day could not have
    had a day-before score (same-day publications included — the day
    before, the record did not exist). Unmatched CVEs (no publication
    date in the corpus) stay ``no_prior_score`` — unknown is unknown."""
    if reason == "pre_epss":
        return "pre_epss"
    if published is not None and published[:10] >= date_added:
        return "listed_before_publication"
    return "no_prior_score"


# ------------------------------------------------------------------- builder

def build_epss_report(state: dict, kev_entries: Iterable[KevEntry],
                      published_dates: dict[str, str], generated_at: str,
                      *, min_n: int = 10) -> dict:
    """Assemble the full epss_report.json object.

    ``published_dates`` is the CVE-id -> datePublished join from the
    corpus pass (``Aggregator.kev_published_dates``), used only to
    classify ungradeable entries. Years group by KEV ``dateAdded``; a
    year charts only with at least ``min_n`` graded entries (fixture
    mode 1) but its ungradeable/pending counts are always in ``catalog``.
    """
    state_entries: dict[str, dict] = state.get("entries") or {}

    entries_out: list[dict] = []
    pending_total = 0
    pending_by_year: dict[int, int] = defaultdict(int)
    graded_by_year: dict[int, list[dict]] = defaultdict(list)
    ungradeable_by_year: dict[int, int] = defaultdict(int)
    ungradeable = dict.fromkeys(UNGRADEABLE_REASONS, 0)
    total = 0

    for kev in kev_entries:
        total += 1
        date_added = (kev.date_added or "")[:10]
        year = None
        if len(date_added) == 10 and date_added[:4].isdigit():
            year = int(date_added[:4])
        entry = state_entries.get(entry_key(kev.cve_id, date_added))
        if entry is None:
            pending_total += 1
            if year is not None:
                pending_by_year[year] += 1
            continue
        entries_out.append({"cve": kev.cve_id, "date_added": date_added,
                            **entry})
        if entry["epss"] is None:
            reason = _classify_ungradeable(
                entry["reason"], date_added,
                published_dates.get(kev.cve_id))
            ungradeable[reason] += 1
            if year is not None:
                ungradeable_by_year[year] += 1
        elif year is not None:
            graded_by_year[year].append(entry)

    entries_out.sort(key=lambda e: (e["date_added"], e["cve"]))

    # ---- section 1: the grade, per KEV year -------------------------------
    grade_by_year = []
    for year in sorted(set(graded_by_year) | set(pending_by_year)
                       | set(ungradeable_by_year)):
        graded = graded_by_year.get(year, [])
        n = len(graded)
        if n < min_n:
            continue
        below = sum(1 for e in graded if e["epss"] < 0.01)
        above = sum(1 for e in graded if e["epss"] >= 0.10)
        mid = n - below - above
        grade_by_year.append({
            "year": year, "graded": n,
            "n_below_1pct": below, "n_1_to_10pct": mid,
            "n_above_10pct": above,
            "pct_below_1pct": _pct(below, n),
            "pct_1_to_10pct": _pct(mid, n),
            "pct_above_10pct": _pct(above, n),
            "ungradeable": ungradeable_by_year.get(year, 0),
            "pending": pending_by_year.get(year, 0),
        })

    # ---- section 2: probability distribution, split by model era ----------
    graded_all = [e for entries in graded_by_year.values() for e in entries]
    by_model: dict[str, list[dict]] = defaultdict(list)
    for e in graded_all:
        by_model[e["model"]].append(e)
    distribution = {
        "buckets": list(DIST_BUCKETS),
        "by_model": [
            {"model": label, "n": len(group),
             "counts": {b: sum(1 for e in group
                               if dist_bucket(e["epss"]) == b)
                        for b in DIST_BUCKETS}}
            for label in MODEL_LABELS
            if (group := by_model.get(label))
        ],
    }

    # ---- section 3: day-before percentiles --------------------------------
    pctls = [e["percentile"] for e in graded_all
             if e["percentile"] is not None]
    n_pct = len(pctls)
    bottom = sum(1 for p in pctls if p < 0.5)
    percentiles = {
        "buckets": [
            {"bucket": b,
             "n": (nb := sum(1 for p in pctls
                             if percentile_bucket(p) == b)),
             "pct": _pct(nb, n_pct)}
            for b in PERCENTILE_BUCKETS
        ],
        "n": n_pct,
        "bottom_half": {"n": bottom, "pct": _pct(bottom, n_pct)},
        "median_percentile": _r1(statistics.median(pctls) * 100.0)
                             if pctls else None,
    }

    # ---- catalog + headline ------------------------------------------------
    graded_total = len(graded_all)
    catalog = {
        "total": total,
        "graded": graded_total,
        "ungradeable": ungradeable,
        "pending_backfill": pending_total,
    }

    # Headline mirrors kev_metrics: never lean on the partial current year;
    # fall back to the newest charted year only when nothing else survived.
    headline = None
    if graded_total:
        below_all = sum(1 for e in graded_all if e["epss"] < 0.01)
        current_year = int(generated_at[:4])
        full_years = [row for row in grade_by_year
                      if row["year"] < current_year]
        latest = full_years[-1] if full_years else \
            (grade_by_year[-1] if grade_by_year else None)
        headline = {
            "graded": graded_total,
            "pct_below_1pct": _pct(below_all, graded_total),
            "latest_year": latest["year"] if latest else 0,
            "graded_latest": latest["graded"] if latest else 0,
            "pct_below_1pct_latest":
                latest["pct_below_1pct"] if latest else 0.0,
        }

    return {
        "generated_at": generated_at,
        "min_n": min_n,
        "model_eras": model_eras_block(),
        "grade_by_year": grade_by_year,
        "distribution": distribution,
        "percentiles": percentiles,
        "catalog": catalog,
        "headline": headline,
        "entries": entries_out,
    }


def _source(fetched_at: str, obj: dict) -> dict:
    return {"fetched_at": fetched_at,
            "graded": obj["catalog"]["graded"],
            "pending_backfill": obj["catalog"]["pending_backfill"]}


# --------------------------------------------------------------------- stage

def _kev_pairs(kev_entries: Iterable[KevEntry]) -> list[tuple[str, str]]:
    """(cve_id, dateAdded) pairs for every dated KEV entry."""
    return [(kev.cve_id, (kev.date_added or "")[:10])
            for kev in kev_entries
            if len((kev.date_added or "")[:10]) == 10]


def run_stage(out_dir: Path, cache_dir: Path, generated_at: str, *,
              kev_entries: list[KevEntry],
              published_dates: dict[str, str],
              current_model_version: str,
              skip: bool, offline_fixtures: bool, backfill_batch: int = 30,
              min_n: int | None = None, session=None,
              log: Callable[[str], None] = print
              ) -> tuple[dict | None, dict | None]:
    """(epss_report.json object or None, meta.sources.epss_history or None).

    Mirrors the attack stage's handling:

    * ``skip`` — carry the previous run's ``out_dir/epss_report.json``
      forward untouched, marked ``"stale": true``, with ``fetched_at``
      kept at its old value; (None, None) plus a warning when no prior
      file exists. Checked first: skipping must win even in an
      offline-fixtures run;
    * ``offline_fixtures`` — sync from
      pipeline/tests/fixtures/epss_history/ (verbatim-shaped FIRST API
      envelopes, one file per score date), exercising the real
      parse/state/build path with no network and no disk-state writes;
    * live — load the sync state from ``cache_dir`` (a lost cache is
      first reconstructed from the previously published
      ``out_dir``/epss_report.json), sync missing KEV pairs batch-capped
      through the FIRST API, persist the state, and build. When the
      current EPSS feed's model version is one the era table does not
      know, a loud warning is logged (new scores would otherwise be
      silently labeled with the previous era).
    """
    if skip:
        prior_path = out_dir / "epss_report.json"
        if not prior_path.exists():
            log("warning: --skip-epss-report with no previous "
                "epss_report.json; omitting epss_report.json and "
                "meta.sources.epss_history this run")
            return None, None
        prior = json.loads(prior_path.read_text(encoding="utf-8"))
        fetched_at = prior.get("generated_at", generated_at)
        carried = dict(prior)
        carried["generated_at"] = generated_at
        carried["stale"] = True
        log(f"  --skip-epss-report: carrying forward epss_report.json "
            f"from {fetched_at}")
        return carried, {**_source(fetched_at, carried), "stale": True}

    if min_n is None:
        min_n = 1 if offline_fixtures else 10

    if offline_fixtures:
        fixture_dir = FIXTURES_DIR / "epss_history"

        def _local_fetch(cves: list[str], score_date: str) -> dict:
            return json.loads((fixture_dir / f"{score_date}.json")
                              .read_text(encoding="utf-8"))

        state = sync_state(None, _kev_pairs(kev_entries), _local_fetch,
                           backfill_batch=backfill_batch,
                           last_sync=generated_at, log=log)
        obj = build_epss_report(state, kev_entries, published_dates,
                                generated_at, min_n=min_n)
        return obj, _source(generated_at, obj)

    # Live sync. requests is imported lazily so the offline/skip paths
    # (and this module's unit tests) never require it to be importable.
    if session is None:
        import requests

        session = requests.Session()
    if not known_model_version(current_model_version):
        log(f"WARNING: EPSS feed reports model_version "
            f"{current_model_version!r}, which fetch_epss_history.MODEL_ERAS "
            f"does not know — a new model has shipped; add its era row so "
            f"fresh day-before scores are not labeled with the previous "
            f"model.")
    log("syncing EPSS day-before scores for KEV entries ...")
    state = load_state(cache_dir, log=log)
    if state is None:
        state = reconstruct_state(out_dir, log=log)
    state = sync_state(state, _kev_pairs(kev_entries),
                       live_fetcher(session, log=log),
                       backfill_batch=backfill_batch,
                       last_sync=generated_at,
                       save=lambda s: save_state(cache_dir, s), log=log)
    save_state(cache_dir, state)
    obj = build_epss_report(state, kev_entries, published_dates,
                            generated_at, min_n=min_n)
    return obj, _source(generated_at, obj)
