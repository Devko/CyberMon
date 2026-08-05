"""The AI Alibi metrics (ai_alibi.json).

Does the exploitation clock bend at any AI milestone? This module answers
that with CyberMon's OWN nightly series and nothing else — the committed
AI timeline (``ai_timeline_data.py``) is only the overlay a reader checks
the series against.

**No new fetch, and no recomputation.** Every number here is lifted from
payloads other stages already built and validated this run: the
publication->first-public-PoC series from ``time_to_poc.json`` (module
19) and the AI-attention lanes from ``market_hype.json`` (module 02).
Lifting rather than recomputing is deliberate — it makes it structurally
impossible for this page to disagree with the module it quotes.

Three sections:

* **clock** — three annual speed metrics, all drawn from the same
  matched cohort so they share one denominator and one set of caveats:
  the median gap in days, the share armed within a week of publication,
  and the share whose public exploit code predates the CVE record. All
  three reach back to 1999, which is the whole point: a metric whose
  history starts inside the era under test (KEV latency begins at the
  2023 seeding cutoff) cannot test that era, and is deliberately absent.
* **banked** — the inflection test. For each metric and each candidate
  era cutoff, the record's starting level, the level just before the
  cutoff, and the level since — plus the share of the total distance
  travelled that was already banked before the cutoff. Levels are means
  over multi-year windows, never single years: the early corpus is thin
  and wild (1999 is 109 CVEs at a -800-day median), and an endpoint
  ratio anchored there would be exactly the cherry-pick this module
  exists to refute.
* **attention** — the AI-security hype lanes against the same clock,
  over the market module's 60-month window. Attention is monthly and
  indexed to its own peak; the clock is annual and plotted as a step, so
  the two are shown on separate axes and the caption says so.

Nothing in ``ai_timeline_data.EXTERNAL_CONTEXT`` is ever emitted: those
vendor figures are not reproducible from this pipeline, so they stay
prose. The contract has no field for them.
"""
from __future__ import annotations

from datetime import date

from .ai_timeline_data import (DEFAULT_ERA, ERAS, MILESTONES, Era, Milestone)
from .metrics import _pct, _r1

# Window length, in complete years, for every era level. Five years is
# long enough to drown single-year noise (the PoC cohort runs a few
# hundred CVEs a year lately) and short enough that "just before the
# cutoff" still means just before it.
WINDOW_YEARS = 5

# A metric's post-era level must differ from its pre-era level by more
# than this share of the record's full travelled distance before the
# module will call it an inflection rather than noise. Deliberately
# generous to the AI-caused thesis: at 10%, a real acceleration is easy
# to detect and the finding still comes back flat.
#
# THIS IS THE MODULE'S ONE EDITORIAL KNOB — see the note in
# docs/data-contracts.md before changing it, and re-run the claims audit
# (pipeline/tests/test_claims_ai.py) after you do.
INFLECTION_THRESHOLD_PCT = 10.0

# Complete years required AFTER a cutoff before the module will judge
# that era at all. One year is not an era: the 2025 cohort alone swings
# the gap median by double digits (a batch of old CVEs picking up PoC
# references drags the p25 to -4452 days), and a verdict resting on it
# would be an artifact with a headline. Eras younger than this report
# "insufficient" and say so on the page — a judgment this module earns
# back as the record accumulates, not one it fakes now.
MIN_POST_YEARS = 2

# Below this much total travelled distance, the "share banked" ratio is
# division by noise and is emitted as None instead. Units are the
# metric's own (days for the gap, percentage points for the shares).
MIN_TRAVEL = {"days": 5.0, "percent": 5.0}

# The three clock metrics, all read from time_to_poc.hero.years. `faster`
# names the direction that means "the attacker's window got tighter", so
# the verdict copy never has to hard-code which way is bad per metric.
#
# These are NOT three independent tests, and the page says so: all three
# are summary statistics of the SAME gap distribution over the SAME
# cohort, and `poc_negative` is a strict subset of `poc_week` (every
# negative gap is also <= 7 days). They are three views of one
# distribution, which is worth having — a median can hold still while a
# tail moves — but a reader who counts them as independent evidence is
# counting wrong.
#
# `poc_week`'s label is deliberately one-sided. The upstream field is
# `gap <= 7`, which includes every NEGATIVE gap, so a PoC published 800
# days before its CVE counts. "Within a week of publication" would imply
# a +/-7 day window and badly misdescribe the early years, where the
# figure is ~98% because code predated the records entirely.
CLOCK_METRICS = (
    {"id": "poc_gap", "field": "median_days", "unit": "days",
     "label": "Median days, CVE publication to first public exploit",
     "faster": "down"},
    {"id": "poc_week", "field": "pct_within_week", "unit": "percent",
     "label": "Share with public code no later than a week after publication",
     "faster": "up"},
    {"id": "poc_negative", "field": "pct_negative", "unit": "percent",
     "label": "Share whose exploit code predates the CVE record",
     "faster": "up"},
)

# Market-module term ids that carry the AI-security narrative. Both are
# already curated in pipeline/market_terms.py; this module never invents
# a term, it selects from that reviewable list.
ATTENTION_TERMS = ("ai_security", "agentic_ai")


def cut_year_for(era: Era) -> int:
    """Last calendar year ending entirely BEFORE the era's date.

    No charted year may straddle a cutoff — a year that contains the
    cutoff belongs to neither side, so it is excluded from both. For
    ChatGPT (2022-11-30) that is 2021; a reader who thinks 2022 should
    count as pre-AI can say so, but they cannot say the split is rigged.
    """
    return date.fromisoformat(era.date).year - 1


def _plot_date(m: Milestone) -> str:
    """Day-precision date for plotting. Month rows land mid-month, which
    the tooltip discloses — the chart never implies a day it lacks."""
    return m.date if m.precision == "day" else f"{m.date}-15"


def _mean(values: list[float]) -> float | None:
    return _r1(sum(values) / len(values)) if values else None


def _window(rows: list[dict], field: str, *, start: int, end: int) -> \
        tuple[float | None, int, int]:
    """Mean of ``field`` over charted years in [start, end], plus the
    number of years and matched CVEs behind it (the audit trail — a
    level built on two thin years is reported as such, never hidden)."""
    picked = [r for r in rows if start <= r["year"] <= end]
    return (_mean([float(r[field]) for r in picked]),
            len(picked), sum(int(r["n"]) for r in picked))


def _level(value: float | None, years: int, n: int) -> dict:
    return {"value": value, "years": years, "n": n}


def _verdict(early: float | None, pre: float | None, post: float | None,
             *, unit: str, faster: str, post_years: int) -> \
        tuple[str, float | None, float | None]:
    """(verdict, pct_banked, shift_share_pct) for one metric at one era.

    ``pct_banked`` is the share of the record's total travelled distance
    (early level -> post level) that was already travelled by the pre-era
    level. It is None when the total travel is too small to divide by,
    in which case the verdict alone carries the finding. Values above 100
    are legal and meaningful: the pre-era level had already gone further
    than the era ever did.

    ``shift_share_pct`` is the same movement seen from the other end —
    what the era itself moved, as a share of the total travel — and it
    is SIGNED so a chart never has to know which way is bad for which
    metric: **positive means the era moved the metric toward faster
    exploitation**, negative toward slower. That sign is the module's
    whole finding, so it is computed here, once, rather than in three
    chart files.

    Verdicts:
      ``no_inflection``  — the era changed the level by less than
                           INFLECTION_THRESHOLD_PCT of the total travel;
      ``accelerated``    — the era moved the metric toward faster;
      ``decelerated``    — the era moved it toward slower;
      ``insufficient``   — a level is missing, or the era is younger than
                           MIN_POST_YEARS complete years.
    """
    if early is None or pre is None or post is None:
        return "insufficient", None, None
    if post_years < MIN_POST_YEARS:
        return "insufficient", None, None

    total_travel = post - early
    era_shift = post - pre
    floor = MIN_TRAVEL[unit]
    toward_faster = (era_shift < 0) if faster == "down" else (era_shift > 0)

    if abs(total_travel) < floor:
        # The record barely moved at all across its whole span; a ratio
        # here would be noise over noise. The era shift still decides.
        pct_banked = shift_share = None
    else:
        pct_banked = _r1(100.0 * (pre - early) / total_travel)
        magnitude = 100.0 * abs(era_shift) / abs(total_travel)
        shift_share = _r1(magnitude if toward_faster else -magnitude)

    if abs(total_travel) >= floor and \
            abs(era_shift) < abs(total_travel) * INFLECTION_THRESHOLD_PCT / 100.0:
        return "no_inflection", pct_banked, shift_share
    if abs(era_shift) < floor:
        return "no_inflection", pct_banked, shift_share
    return ("accelerated" if toward_faster else "decelerated"), \
        pct_banked, shift_share


def _build_like_for_like(poc: dict) -> dict:
    """The censoring-free clock, lifted from time_to_poc's `arming`.

    Kept OUT of ``clock.metrics`` deliberately. Those three share one
    cohort and one span, and the contract enforces that. This is a
    different instrument on a different span — it starts later (the
    window needs a populated cohort) and ends LATER, because a
    like-for-like statistic can measure a part-finished year that the
    raw series cannot. Structuring the difference rather than hiding it
    is what stops a reader treating four numbers as four equal numbers:
    this one is immune to the bias the other three carry, and the page
    says which is which.
    """
    arming = poc.get("arming") or {}
    rows = arming.get("years") or []
    return {
        "id": "poc_like_for_like",
        "label": "Median days to first public exploit, like-for-like",
        "unit": "days", "faster": "down",
        "horizon_days": arming.get("horizon_days", 0),
        "observed_through": arming.get("observed_through", ""),
        "first_year": rows[0]["year"] if rows else 0,
        "last_year": rows[-1]["year"] if rows else 0,
        "years": [{"year": r["year"], "value": _r1(float(r["median_days"])),
                   "n": int(r["n"]),
                   "provisional": bool(r.get("provisional", False))}
                  for r in rows],
    }


def _build_clock(poc: dict, current_year: int) -> dict:
    """The three annual speed metrics, complete years only.

    The generation year is dropped outright rather than marked: this
    module's whole argument is about where a series bends, and a partial
    year is a fake bend at the right-hand edge.
    """
    rows = [r for r in poc.get("hero", {}).get("years", [])
            if r["year"] < current_year]
    metrics = []
    for spec in CLOCK_METRICS:
        metrics.append({
            "id": spec["id"], "label": spec["label"], "unit": spec["unit"],
            "faster": spec["faster"],
            "years": [{"year": r["year"], "value": _r1(float(r[spec["field"]])),
                       "n": int(r["n"])} for r in rows],
        })
    return {"source_file": "time_to_poc.json",
            "first_year": rows[0]["year"] if rows else 0,
            "last_year": rows[-1]["year"] if rows else 0,
            "metrics": metrics}


def _build_banked(clock: dict, eras: list[dict],
                  like_for_like: dict) -> dict:
    """The inflection test: three levels per metric per era cutoff.

    The like-for-like metric goes FIRST and is flagged ``primary`` — it
    is the only one of the four immune to cohort-maturity bias, so the
    page leads with it and keeps the other three as corroboration rather
    than presenting four equal votes.
    """
    metrics = []
    candidates = ([like_for_like] if like_for_like["years"] else []) \
        + list(clock["metrics"])
    for m in candidates:
        rows = m["years"]
        if not rows:
            continue
        first_year, last_year = rows[0]["year"], rows[-1]["year"]
        early_v, early_y, early_n = _window(
            rows, "value", start=first_year,
            end=first_year + WINDOW_YEARS - 1)

        era_blocks = []
        for era in eras:
            cut = era["cut_year"]
            pre_v, pre_y, pre_n = _window(
                rows, "value", start=cut - WINDOW_YEARS + 1, end=cut)
            post_v, post_y, post_n = _window(
                rows, "value", start=cut + 1, end=last_year)
            # A verdict standing entirely on cohorts the trackers have
            # not finished indexing is not a verdict. Those years read
            # slower than they will finally prove to be, so publishing
            # one would print a "slowdown" that is an artifact — and on
            # this page, any spurious movement inside the AI band is the
            # single most likely thing to be misread.
            settled_post = [r for r in rows
                            if cut < r["year"] <= last_year
                            and not r.get("provisional")]
            if post_y and not settled_post:
                verdict, pct_banked, shift_share = "insufficient", None, None
            else:
                verdict, pct_banked, shift_share = _verdict(
                    early_v, pre_v, post_v, unit=m["unit"],
                    faster=m["faster"], post_years=post_y)
            era_blocks.append({
                "era": era["id"], "cut_year": cut,
                "early": _level(early_v, early_y, early_n),
                "pre": _level(pre_v, pre_y, pre_n),
                "post": _level(post_v, post_y, post_n),
                "era_shift": (None if pre_v is None or post_v is None
                              else _r1(post_v - pre_v)),
                "pct_banked": pct_banked,
                "shift_share_pct": shift_share,
                "verdict": verdict,
            })
        metrics.append({"id": m["id"], "label": m["label"], "unit": m["unit"],
                        "faster": m["faster"],
                        "primary": m["id"] == like_for_like["id"],
                        "eras": era_blocks})

    return {"window_years": WINDOW_YEARS,
            "inflection_threshold_pct": INFLECTION_THRESHOLD_PCT,
            "metrics": metrics}


def _build_attention(market: dict | None, clock: dict) -> dict:
    """AI-security attention (module 02's lanes) against the clock.

    The composite per term is the mean of that term's per-source indexes
    for the month, over the sources that HAVE a value there — module 02
    already normalized each lane to its own peak, so the mean is a mean
    of comparable 0-100 series, and a term whose Wikipedia lane starts
    late is not punished for it. ``sources`` travels with every month so
    a reader can see how many lanes back each point.
    """
    if market is None:
        return {"available": False, "window_months": 0, "terms": [],
                "clock": [], "headline": None}

    by_id = {t["id"]: t for t in market.get("terms", [])}
    terms = []
    for term_id in ATTENTION_TERMS:
        term = by_id.get(term_id)
        if term is None:
            continue
        per_month: dict[str, list[float]] = {}
        for series in term.get("series", {}).values():
            for point in series:
                per_month.setdefault(point["month"], []).append(
                    float(point["index"]))
        months = [{"month": month, "index": _r1(sum(vals) / len(vals)),
                   "sources": len(vals)}
                  for month, vals in sorted(per_month.items()) if vals]
        if months:
            terms.append({"id": term_id, "label": term["label"],
                          "months": months})

    # The clock, restricted to the attention window and carrying its own
    # unit so the chart can label the second axis honestly.
    window_years = sorted({int(p["month"][:4])
                           for t in terms for p in t["months"]})
    gap = next((m for m in clock["metrics"] if m["id"] == "poc_gap"), None)
    clock_rows = [] if gap is None else [
        {"year": r["year"], "value": r["value"]}
        for r in gap["years"] if r["year"] in set(window_years)]

    headline = None
    if terms and clock_rows:
        # Lead with the biggest RISE in index points, not the highest
        # final level: the chart's subject is how far attention travelled
        # over the window. (A ratio would divide by zero — Agentic AI
        # starts the window at a flat 0 across every lane.)
        lead = max(terms,
                   key=lambda t: t["months"][-1]["index"] -
                   t["months"][0]["index"])
        values = [r["value"] for r in clock_rows]
        headline = {
            "term_id": lead["id"], "label": lead["label"],
            "index_first": lead["months"][0]["index"],
            "index_last": lead["months"][-1]["index"],
            "month_first": lead["months"][0]["month"],
            "month_last": lead["months"][-1]["month"],
            # The clock over the same window as a BAND, never as
            # endpoints: one anomalous cohort year at either end would
            # otherwise write the headline (2025's median swings to -12
            # on a batch of old CVEs picking up PoC references).
            "clock_min": min(values), "clock_max": max(values),
            "clock_mean": _r1(sum(values) / len(values)),
            "clock_year_first": clock_rows[0]["year"],
            "clock_year_last": clock_rows[-1]["year"],
        }

    return {"available": True,
            "window_months": int(market.get("window_months", 0)),
            "terms": terms, "clock": clock_rows,
            "clock_unit": "days", "headline": headline}


def build_ai_alibi(poc: dict, generated_at: str,
                   *, market: dict | None = None) -> dict:
    """Assemble the ai_alibi.json object (contract:
    pipeline/ai_contracts.py; doc: docs/data-contracts.md).

    ``poc`` is the built time_to_poc.json payload and ``market`` the
    built market_hype.json payload (None when that upstream degraded —
    the attention section then reports itself unavailable and the other
    two sections are unaffected).
    """
    current_year = int(generated_at[:4])

    eras = [{"id": e.id, "label": e.label, "date": e.date,
             "caption": e.caption, "cut_year": cut_year_for(e),
             "default": e.id == DEFAULT_ERA} for e in ERAS]

    milestones = [{"date": m.date, "plot_date": _plot_date(m),
                   "precision": m.precision, "kind": m.kind,
                   "label": m.label, "note": m.note, "source": m.source}
                  for m in sorted(MILESTONES, key=_plot_date)]

    clock = _build_clock(poc, current_year)
    like_for_like = _build_like_for_like(poc)
    banked = _build_banked(clock, eras, like_for_like)
    attention = _build_attention(market, clock)

    # Headline: the default era's verdict on the headline metric, plus
    # the scoreboard across every judgeable metric-by-era cell. The
    # scoreboard is the module's actual claim — "nothing accelerated" is
    # a statement about all of them, not a cherry-picked one — and
    # ``judged`` is reported alongside so a reader can see how much of
    # the grid was thin enough to withhold.
    # The headline quotes the PRIMARY metric when there is one — the
    # censoring-free clock — falling back to the raw median otherwise.
    default_era = next(e for e in eras if e["default"])
    gap = next((m for m in banked["metrics"] if m.get("primary")),
               next((m for m in banked["metrics"] if m["id"] == "poc_gap"),
                    None))
    block = None if gap is None else next(
        (b for b in gap["eras"] if b["era"] == default_era["id"]), None)
    cells = [b for m in banked["metrics"] for b in m["eras"]]
    judged = [b for b in cells if b["verdict"] != "insufficient"]
    tally = {v: sum(1 for b in judged if b["verdict"] == v)
             for v in ("accelerated", "decelerated", "no_inflection")}
    headline = {
        "era": default_era["id"], "era_label": default_era["label"],
        "cut_year": default_era["cut_year"],
        "verdict": block["verdict"] if block else "insufficient",
        "pct_banked": block["pct_banked"] if block else None,
        "pre": block["pre"]["value"] if block else None,
        "post": block["post"]["value"] if block else None,
        "milestones": len(milestones),
        "no_uplift_reports": sum(1 for m in milestones
                                 if m["kind"] == "no_uplift"),
        "cells": len(cells),
        "judged": len(judged),
        "accelerated": tally["accelerated"],
        "decelerated": tally["decelerated"],
        "no_inflection": tally["no_inflection"],
        "pct_accelerated": _pct(tally["accelerated"], len(judged)),
    }

    return {
        "generated_at": generated_at,
        "eras": eras,
        "milestones": milestones,
        "clock": clock,
        "like_for_like": like_for_like,
        "banked": banked,
        "attention": attention,
        "headline": headline,
    }
