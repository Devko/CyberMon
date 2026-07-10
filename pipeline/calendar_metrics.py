"""CVE Calendar metrics (cve_calendar.json).

All three charts read aggregates the core streaming pass already collects
(:class:`pipeline.metrics.Aggregator`); this module adds no second sweep
over the corpus.

* **Reservation aging (hero)** — per publication year, how old the CVE ID
  itself was when the record published: the ID's year prefix against the
  publication year. Buckets: same-year ID, one-year-old ID, two-plus-year-
  old ID. An ID minted after its own publication year (a late-December
  reservation published under January's clock) clamps to age 0; the clamp
  count ships so the choice is auditable. Records with no ``datePublished``
  take their publication year FROM the ID and are age 0 by construction.

* **The weekly beat** — per publication year, the weekday distribution of
  ``datePublished``. Day-of-week is computed on the UTC date the record
  carries; a CNA filing late on a Tuesday in California lands on Wednesday
  UTC, so the skew direction is toward the *next* day, never the previous
  one (stated in the chart methodology, not hidden).

* **Patch Tuesday** — per publication year, the share of dated records
  published on the month's second Tuesday (the Tuesday falling on day
  8-14, UTC). Twelve such days exist every year: 12/365 ≈ 3.3% of the
  calendar (3.28% in a leap year — the same 3.3 at one decimal), shipped
  as ``calendar_pct`` so the chart can draw the honest baseline. The top
  single publication day per year rides along for tooltips only.

Only records with a day-precision ``datePublished`` join the weekday and
patch-Tuesday tallies (the ID-age chart needs only the year), so those two
sections' ``n`` can sit below the hero's. Years under ``min_n`` records
(per section, on that section's own denominator) never plot. The partial
current year plots when it clears ``min_n`` — the site labels it — but
never feeds a headline or comparison year.
"""
from __future__ import annotations

from collections import Counter
from datetime import date

from .metrics import Aggregator, _pct

# Monday-first, matching datetime.date.weekday(); the site renders labels.
WEEKDAY_COUNT = 7

# Second Tuesdays per year (every month has exactly one) over days per
# common year: the uniform-calendar share a "no release calendar" world
# would put on those days. 12/365 = 3.29%, 12/366 = 3.28% — both 3.3 at
# the corpus's 1-decimal grain.
PATCH_TUESDAYS_PER_YEAR = 12
CALENDAR_PCT = round(100.0 * PATCH_TUESDAYS_PER_YEAR / 365, 1)


def is_patch_tuesday(d: date) -> bool:
    """True on the second Tuesday of ``d``'s month (UTC dates in, so the
    judgment is UTC too): the only Tuesday whose day-of-month is 8-14."""
    return d.weekday() == 1 and 8 <= d.day <= 14


def _parse_day(s: str) -> date | None:
    try:
        return date.fromisoformat(s)
    except ValueError:
        return None


def _latest_complete(years: list[int], current_year: int) -> int | None:
    """The newest charted year that isn't the partial current one; falls
    back to the newest charted year (fixture corpora may end early)."""
    full = [y for y in years if y < current_year]
    if full:
        return full[-1]
    return years[-1] if years else None


def _baseline(years: list[int], latest: int) -> int:
    """Ten-year lookback when charted, else the earliest charted year —
    payload-authoritative, consumers never derive it."""
    return latest - 10 if latest - 10 in years else years[0]


def build_cve_calendar(agg: Aggregator, generated_at: str, *,
                       min_n: int = 500) -> dict:
    """cve_calendar.json: reservation aging, weekday beat, patch Tuesday."""
    current_year = int(generated_at[:4])

    # ---- hero: reservation aging ------------------------------------------
    age_years = []
    for year in sorted(agg.calendar_id_age):
        ages = agg.calendar_id_age[year]
        n = sum(ages.values())
        if n < min_n:
            continue
        same = ages.get(0, 0)
        one = ages.get(1, 0)
        two_plus = n - same - one
        age_years.append({
            "year": year, "n": n,
            "same_year": same, "one_year": one, "two_plus": two_plus,
            "pct_same_year": _pct(same, n),
            "pct_one_year": _pct(one, n),
            "pct_two_plus": _pct(two_plus, n),
            # prior-year share computed on counts, not by summing rounded
            # percentages — the headline claim must not inherit rounding.
            "pct_prior_year": _pct(n - same, n),
        })
    kept = [row["year"] for row in age_years]
    headline = None
    latest = _latest_complete(kept, current_year)
    if latest is not None:
        by_year = {row["year"]: row for row in age_years}
        base = _baseline(kept, latest)
        headline = {
            "latest_year": latest,
            "pct_prior_year_latest": by_year[latest]["pct_prior_year"],
            "baseline_year": base,
            "pct_prior_year_baseline": by_year[base]["pct_prior_year"],
        }
    id_age = {
        "years": age_years,
        "clamped_negative": sum(agg.calendar_negative_ages.values()),
        "headline": headline,
    }

    # ---- per-day derivations (weekday + patch Tuesday share one tally) ----
    weekday_years = []
    pt_years = []
    for year in sorted(agg.calendar_days):
        counts = [0] * WEEKDAY_COUNT
        on_pt = 0
        n = 0
        top_day: tuple[str, int] | None = None
        # Counter iteration order is insertion order; sort so the top-day
        # tie-break (earliest date wins) is deterministic.
        for day_str, day_n in sorted(agg.calendar_days[year].items()):
            d = _parse_day(day_str)
            if d is None:  # unparseable datePublished: no calendar facts
                continue
            n += day_n
            counts[d.weekday()] += day_n
            if is_patch_tuesday(d):
                on_pt += day_n
            if top_day is None or day_n > top_day[1]:
                top_day = (day_str, day_n)
        if n < min_n:
            continue
        weekday_years.append({
            "year": year, "n": n,
            "counts": counts,
            "pct": [_pct(c, n) for c in counts],
        })
        pt_years.append({
            "year": year, "n": n,
            "on_pt": on_pt,
            "pct": _pct(on_pt, n),
            "top_day": {"date": top_day[0], "n": top_day[1]},
        })

    kept = [row["year"] for row in weekday_years]
    comparison = None
    latest = _latest_complete(kept, current_year)
    if latest is not None:
        comparison = {"latest_year": latest,
                      "baseline_year": _baseline(kept, latest)}

    pt_headline = None
    latest = _latest_complete([row["year"] for row in pt_years], current_year)
    if latest is not None:
        pt_headline = {
            "latest_year": latest,
            "pct_latest": next(r["pct"] for r in pt_years
                               if r["year"] == latest),
        }

    return {
        "generated_at": generated_at,
        "min_n": min_n,
        "id_age": id_age,
        "weekday": {"years": weekday_years, "comparison": comparison},
        "patch_tuesday": {
            "calendar_pct": CALENDAR_PCT,
            "years": pt_years,
            "headline": pt_headline,
        },
    }
