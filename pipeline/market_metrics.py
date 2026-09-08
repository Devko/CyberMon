"""Security Market metrics: per-term interest series across five sources.

Monthly hit counts arrive as sync state maintained by ``fetch_market``
(``{"series": {term_id: {source: {month: count}}}, "pending": [...]}``);
this module is pure math plus stage orchestration on top of it:

* :func:`index_series` — a term/source month->count map, normalized to an
  index-to-peak (100 = the series' own busiest month) so a 40k-article
  GDELT series and a 30-paper arXiv series share one 0-100 y-axis;
* :func:`yoy` — year-over-year change on *raw* counts, latest 12 populated
  months vs the 12 populated months before those;
* :func:`divergence` — is research (arXiv) running ahead of the media
  narrative (GDELT) for a term, on recent index levels;
* :func:`build_market_hype` — assembles the market_hype.json object;
* :func:`run_stage` — the __main__-facing stage: offline fixtures,
  --skip carry-forward, or a live sync via ``fetch_market``.

A "populated month" is a month present in the state (fetched, possibly
with a zero count). Missing months are unknown, not zero — they are never
invented. Likewise every computed stat is None when its eligibility bar
is not met, and headline entries are None when no term qualifies: the
site renders "not enough history yet" rather than a fabricated mover.

Freshness: the sync state stamps each source lane's ``last_success``
(see ``fetch_market``). A lane whose last successful pass is older than
``STALE_AFTER_DAYS`` at build time is published in ``stale_sources``, its
YoY entries are null for every term and it drops out of the divergence
call — the movers board never ranks a dead lane's ever-older data. A lane
whose last success predates the current month also has its previous-month
cell withheld from the series: that month closed while the lane was
down, so what the cache holds is a partial fetch, never a closed month.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from .market_terms import TERMS, TermDef

# Order is the published contract order (market_hype.json "sources").
# Divergence stays gdelt-vs-arxiv: those two remain the cleanest
# media-vs-research pair — Wikipedia mixes both audiences and EDGAR
# tracks filings, so neither side of that comparison gains anything.
SOURCES = ("gdelt", "hn", "arxiv", "wiki", "edgar")
WINDOW_MONTHS = 60
# |research_vs_media_index| must clear this before a direction is called;
# a few index points of drift on 3-month averages is noise, not a signal.
DIVERGENCE_DEAD_ZONE = 10.0
# A (term, source) pair needs at least this many raw hits across the two
# compared years before it may post a YoY percentage — 11 hits shrinking
# to 4 is not a -63.6% market move, it's noise wearing a percent sign.
MIN_YOY_VOLUME = 30
# Each source feeding a divergence call needs at least this many raw hits
# across the three averaged months — two papers against a two-paper peak
# is an index of 100 and a fabricated "research leads by 50" headline.
MIN_DIVERGENCE_VOLUME = 10
# A lane with no successful pass for longer than this is stale: its YoY
# and divergence contributions are withheld rather than computed from
# whatever the cache last saw. Three nights covers a weekend outage of
# the upstream (or of the runner) without crying wolf.
STALE_AFTER_DAYS = 3
FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures"


def _r1(x: float) -> float:
    return round(float(x), 1)


def _parse_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ") \
                   .replace(tzinfo=timezone.utc)


def _previous_month(month: str) -> str:
    year, mon = int(month[:4]), int(month[5:7])
    year, mon = (year - 1, 12) if mon == 1 else (year, mon - 1)
    return f"{year:04d}-{mon:02d}"


def lane_freshness(state: dict, generated_at: str
                   ) -> tuple[list[str], set[str]]:
    """``(stale_sources, partial_previous_month)`` from the state's
    ``last_success`` stamps, judged at ``generated_at``.

    A source is stale when its stamp is older than ``STALE_AFTER_DAYS``
    (or unparseable: a stamp we cannot read is a stamp we cannot vouch
    for). A source is in the second set when its stamp predates the first
    day of the generation month — the previous month closed while the
    lane was failing, so its cell is a partial fetch. A source with no
    stamp at all is in neither: the sync stamps every lane it holds data
    for (seeding pre-freshness states from ``last_sync``), so a missing
    stamp means the lane has no cached months to be stale about, or a
    hand-built/fixture state that predates freshness tracking.
    """
    generated = _parse_iso(generated_at)
    month_start = generated.replace(day=1, hour=0, minute=0, second=0,
                                    microsecond=0)
    stamps = state.get("last_success") or {}
    stale: list[str] = []
    partial: set[str] = set()
    for source in SOURCES:
        raw = stamps.get(source)
        if raw is None:
            continue
        try:
            last = _parse_iso(str(raw))
        except ValueError:
            stale.append(source)
            partial.add(source)
            continue
        if generated - last > timedelta(days=STALE_AFTER_DAYS):
            stale.append(source)
        if last < month_start:
            partial.add(source)
    return stale, partial


# ---------------------------------------------------------------- pure math

def index_series(monthly: dict[str, int]) -> list[dict]:
    """Sorted ``[{month, n, index}]`` where index = 100 * n / series peak,
    rounded to 1 decimal. All indexes are 0.0 when the peak itself is 0
    (a flat-zero series has no meaningful peak to normalize against)."""
    peak = max(monthly.values(), default=0)
    return [{"month": month, "n": monthly[month],
             "index": _r1(100.0 * monthly[month] / peak) if peak else 0.0}
            for month in sorted(monthly)]


def yoy(monthly: dict[str, int]) -> dict | None:
    """Year-over-year change on raw counts: the latest 12 populated months
    vs the 12 populated months before those.

    None (never 0) when fewer than 24 months are populated, when the prior
    window sums to zero (a YoY against an empty baseline would be an
    invented number), or when the two windows together carry fewer than
    ``MIN_YOY_VOLUME`` raw hits (a percentage of almost nothing is a
    rumor, not a rate).
    """
    months = sorted(monthly)
    if len(months) < 24:
        return None
    n_prior = sum(monthly[m] for m in months[-24:-12])
    n_latest = sum(monthly[m] for m in months[-12:])
    if n_prior <= 0 or n_prior + n_latest < MIN_YOY_VOLUME:
        return None
    return {"latest_month": months[-1],
            "pct_change": _r1(100.0 * (n_latest - n_prior) / n_prior),
            "n_latest_12m": n_latest,
            "n_prior_12m": n_prior}


def divergence(gdelt_series: list[dict],
               arxiv_series: list[dict]) -> dict | None:
    """Research-vs-media divergence from the two *index* series (one entry
    per populated month, as built by :func:`index_series`).

    Averages each source's index over its 3 most recent populated months;
    ``research_vs_media_index`` = arXiv average minus GDELT average, so
    positive means research runs closer to its own peak than the media
    narrative does. None when either source has fewer than 3 populated
    months, or fewer than ``MIN_DIVERGENCE_VOLUME`` raw hits across the
    three averaged months (an index built on a couple of papers is an
    artifact, not a divergence). Direction is "aligned" inside the
    +/-``DIVERGENCE_DEAD_ZONE``.
    """
    if len(gdelt_series) < 3 or len(arxiv_series) < 3:
        return None
    if (sum(p["n"] for p in gdelt_series[-3:]) < MIN_DIVERGENCE_VOLUME
            or sum(p["n"] for p in arxiv_series[-3:]) < MIN_DIVERGENCE_VOLUME):
        return None
    gdelt_avg = _r1(sum(p["index"] for p in gdelt_series[-3:]) / 3.0)
    arxiv_avg = _r1(sum(p["index"] for p in arxiv_series[-3:]) / 3.0)
    rvm = _r1(arxiv_avg - gdelt_avg)
    if rvm > DIVERGENCE_DEAD_ZONE:
        direction = "research_leads"
    elif rvm < -DIVERGENCE_DEAD_ZONE:
        direction = "media_leads"
    else:
        direction = "aligned"
    return {"gdelt_index_avg3m": gdelt_avg, "arxiv_index_avg3m": arxiv_avg,
            "research_vs_media_index": rvm, "direction": direction}


# ------------------------------------------------------------------ builder

def _headline(term_objs: list[dict]) -> dict:
    """Top riser/faller (single term+source pair by eligible YoY) and top
    divergence (largest |research_vs_media_index|). Candidates are sorted
    by term id first, so ties break deterministically to the lowest id;
    each entry is None when nothing is eligible — never fabricated."""
    movers = sorted(((t["id"], t["label"], source,
                      t["yoy"][source]["pct_change"])
                     for t in term_objs for source in SOURCES
                     if t["yoy"][source] is not None),
                    key=lambda e: (e[0], e[2]))
    diverged = sorted(((t["id"], t["label"], t["divergence"])
                       for t in term_objs if t["divergence"] is not None),
                      key=lambda e: e[0])

    def _mover(entry: tuple | None) -> dict | None:
        if entry is None:
            return None
        term_id, label, source, pct = entry
        return {"term_id": term_id, "label": label, "source": source,
                "pct_change": pct}

    top_div = max(diverged, default=None,
                  key=lambda e: abs(e[2]["research_vs_media_index"]))
    # A "riser" must actually rise and a "faller" actually fall: in a
    # uniformly rising market the faller slot stays null rather than
    # presenting the least-rising term as a faller (and vice versa).
    risers = [e for e in movers if e[3] > 0]
    fallers = [e for e in movers if e[3] < 0]
    return {
        "top_riser": _mover(max(risers, key=lambda e: e[3], default=None)),
        "top_faller": _mover(min(fallers, key=lambda e: e[3], default=None)),
        "top_divergence": None if top_div is None else {
            "term_id": top_div[0], "label": top_div[1],
            "research_vs_media_index": top_div[2]["research_vs_media_index"],
            "direction": top_div[2]["direction"]},
    }


def build_market_hype(state: dict, terms: list[TermDef],
                      generated_at: str) -> dict:
    """Assemble the full market_hype.json object from sync state, for the
    given terms (in the given order). A term/source absent from the state
    simply yields an empty series and null stats. The generation month is
    excluded everywhere (series, YoY, divergence) until it completes, and
    the lane freshness rules of :func:`lane_freshness` apply: stale lanes
    publish their series (flagged in ``stale_sources``) but no YoY or
    divergence; a lane down since before the month rolled over also
    withholds its previous-month cell."""
    all_series = state.get("series", {})
    # The month in progress is collected (the sync must keep refreshing it)
    # but never published: ten days of a month charted next to complete
    # months reads as a cliff, sits inside every "latest twelve months" YoY
    # window, and skews the divergence averages. It joins the charts only
    # once it closes. Trimming here, at build time, keeps the sync state
    # untouched.
    current_month = generated_at[:7]
    previous_month = _previous_month(current_month)
    stale_sources, partial = lane_freshness(state, generated_at)
    stale = set(stale_sources)
    term_objs = []
    for term in terms:
        per_source = {
            src: {m: n for m, n in (all_series.get(term.id, {})
                                    .get(src, {}) or {}).items()
                  if m < current_month
                  and not (src in partial and m == previous_month)}
            for src in SOURCES}
        series = {s: index_series(per_source.get(s, {})) for s in SOURCES}
        term_objs.append({
            "id": term.id,
            "label": term.label,
            "series": series,
            "yoy": {s: None if s in stale else yoy(per_source.get(s, {}))
                    for s in SOURCES},
            "divergence": (None if stale & {"gdelt", "arxiv"} else
                           divergence(series["gdelt"], series["arxiv"])),
        })
    return {
        "generated_at": generated_at,
        "window_months": WINDOW_MONTHS,
        "sources": list(SOURCES),
        "stale_sources": stale_sources,
        "backfill_remaining": len(state.get("pending", [])),
        "terms": term_objs,
        "headline": _headline(term_objs),
    }


# -------------------------------------------------------------------- stage

def run_stage(out_dir: Path, cache_dir: Path, generated_at: str, *,
              skip: bool, offline_fixtures: bool, backfill_batch: int,
              session=None, sleep: Callable[[float], None] = time.sleep,
              log: Callable[[str], None] = print
              ) -> tuple[dict | None, dict | None]:
    """(market_hype.json object or None, meta.sources.market object or None).

    Mirrors __main__'s NVD stage handling:

    * ``offline_fixtures`` — build from pipeline/tests/fixtures/market/
      state.json, restricted to the terms that state covers; no network,
      no disk-state writes (the CI smoke test path);
    * ``skip`` — carry the previous run's ``out_dir/market_hype.json``
      forward untouched, marked ``"stale": true``, with ``fetched_at``
      kept at its old value; (None, None) plus a warning when no prior
      file exists (a duplicated-but-relabeled snapshot would fake data);
    * live — load the sync state from ``cache_dir`` (a lost cache is first
      reconstructed from the previously published ``out_dir``/
      market_hype.json so the HN backfill doesn't restart from zero),
      sync at most ``backfill_batch`` pending (source, term, month) cells
      via ``fetch_market``, persist the state, and build for all of
      ``TERMS``.
    """
    if offline_fixtures:
        state = json.loads((FIXTURES_DIR / "market" / "state.json")
                           .read_text(encoding="utf-8"))
        terms = [t for t in TERMS if t.id in state["series"]]
        obj = build_market_hype(state, terms, generated_at)
        return obj, _market_source(obj, generated_at, len(terms))

    if skip:
        prior_path = out_dir / "market_hype.json"
        if not prior_path.exists():
            log("warning: --skip-market with no previous market_hype.json; "
                "omitting market_hype.json and meta.sources.market this run")
            return None, None
        prior = json.loads(prior_path.read_text(encoding="utf-8"))
        fetched_at = prior.get("generated_at", generated_at)
        carried = dict(prior)
        carried["generated_at"] = generated_at
        carried["stale"] = True
        log(f"  --skip-market: carrying forward market_hype.json "
            f"from {fetched_at}")
        # meta.sources.market must stay contract-complete even when stale.
        return carried, {**_market_source(carried, fetched_at,
                                          len(carried.get("terms", []))),
                         "stale": True}

    # Live sync. fetch_market is imported lazily so the offline/skip paths
    # (and this module's unit tests) never require it to be importable.
    from .fetch_market import (load_state, reconstruct_state, save_state,
                               sync_state)

    state = load_state(cache_dir)
    if state is None:
        state = reconstruct_state(out_dir, log=log)
    state = sync_state(state, TERMS, window_months=WINDOW_MONTHS,
                       backfill_batch=backfill_batch, session=session,
                       sleep=sleep, log=log)
    save_state(cache_dir, state)
    obj = build_market_hype(state, TERMS, generated_at)
    if obj["stale_sources"]:
        log(f"  market: stale source lane(s) — no successful pass in "
            f"{STALE_AFTER_DAYS} days, YoY/divergence withheld: "
            f"{', '.join(obj['stale_sources'])}")
    return obj, _market_source(obj, generated_at, len(TERMS))


def _market_source(obj: dict, fetched_at: str, term_count: int) -> dict:
    """The ``meta.sources.market`` block for a built (or carried) payload;
    ``stale_sources`` travels with it so the footer can name a dead lane
    without opening market_hype.json (a carried pre-freshness file has
    none to report)."""
    return {"fetched_at": fetched_at, "term_count": term_count,
            "backfill_remaining": obj.get("backfill_remaining", 0),
            "stale_sources": list(obj.get("stale_sources") or [])}
