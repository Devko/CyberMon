"""CNA concentration metrics (cna_concentration.json).

Who actually mints CVEs? Per publication year: how many CNAs were active,
how many were brand new, how concentrated the output was (top-5/top-10
share and a Herfindahl-Hirschman index), plus a rejection-rate
leaderboard over a recent window.

Every year in ``agg.year_span()`` plots, gap-filled with NO minimum-volume
filter: a 1999 single-CNA hhi of 10000.0 is history, not noise. Years with
zero published records take cna_count/newcomer_count from the data (a year
can have rejections only) and 0.0 for the share/hhi stats.

``hhi`` is 10000 * sum(share_i^2) over per-CNA published shares expressed
as fractions — the classic 0-10000 HHI scale, a documented exception to
this codebase's 0-100 percentage rule.

The rejection leaderboard uses ``rejected / (published + rejected)`` —
bounded 0-100 by construction — deliberately NOT the unbounded
``rejected / published`` (a CNA whose rejections outnumber its
publications would post a >100% "rate").
"""
from __future__ import annotations

from .metrics import Aggregator, _pct, _r1


def _year_row(agg: Aggregator, year: int,
              first_activity: dict[str, int]) -> dict:
    published = agg.cna_year_published.get(year) or {}
    rejected = agg.cna_year_rejected.get(year) or {}
    active = set(published) | set(rejected)
    total_published = sum(published.values())
    if total_published:
        counts = sorted(published.values(), reverse=True)
        top5 = _pct(sum(counts[:5]), total_published)
        top10 = _pct(sum(counts[:10]), total_published)
        hhi = _r1(10000.0 * sum((n / total_published) ** 2 for n in counts))
    else:
        top5 = top10 = hhi = 0.0
    return {
        "year": year,
        "cna_count": len(active),
        "newcomer_count": sum(1 for cna in active
                              if first_activity[cna] == year),
        "top5_share": top5,
        "top10_share": top10,
        "hhi": hhi,
    }


def _rejection_leaderboard(agg: Aggregator, *, window_years: int,
                           min_total: int) -> dict:
    """Rejection-rate leaderboard over the last ``window_years`` calendar
    years ending at the newest published year. CNAs with fewer than
    ``min_total`` records (published + rejected) in the window are noise
    and excluded."""
    as_of_year = max(agg.published_by_year, default=0)
    window = range(as_of_year - window_years + 1, as_of_year + 1)
    cnas = set()
    for year in window:
        cnas |= set(agg.cna_year_published.get(year) or {})
        cnas |= set(agg.cna_year_rejected.get(year) or {})

    rows = []
    for cna in cnas:
        published = sum((agg.cna_year_published.get(y) or {}).get(cna, 0)
                        for y in window)
        rejected = sum((agg.cna_year_rejected.get(y) or {}).get(cna, 0)
                       for y in window)
        total = published + rejected
        if total < min_total:
            continue
        rows.append({"cna": cna, "total": total, "rejected": rejected,
                     "rejected_rate_pct": _pct(rejected, total)})
    rows.sort(key=lambda r: (-r["rejected_rate_pct"], -r["total"], r["cna"]))
    return {"window_years": window_years, "min_total": min_total,
            "cnas": rows}


def build_cna_concentration(agg: Aggregator, generated_at: str, *,
                            window_years: int = 5,
                            min_total: int = 50) -> dict:
    """Assemble the cna_concentration.json object."""
    # First-ever activity year per CNA (published or rejected).
    first_activity: dict[str, int] = {}
    activity_years = sorted(set(agg.cna_year_published)
                            | set(agg.cna_year_rejected))
    for year in activity_years:
        for cna in (set(agg.cna_year_published.get(year) or {})
                    | set(agg.cna_year_rejected.get(year) or {})):
            first_activity.setdefault(cna, year)

    years = [_year_row(agg, year, first_activity)
             for year in agg.year_span()]

    # Headline: the last complete year (never the partial current one,
    # mirroring metrics.build_severity_inflation); baseline ten years back
    # when the span reaches, else the earliest year.
    current_year = int(generated_at[:4])
    full_years = [row for row in years if row["year"] < current_year]
    latest = full_years[-1] if full_years else (years[-1] if years else None)
    latest_year = latest["year"] if latest else 0
    by_year = {row["year"]: row for row in years}
    baseline = by_year.get(latest_year - 10, years[0] if years else None)

    return {
        "generated_at": generated_at,
        "years": years,
        "rejection_leaderboard": _rejection_leaderboard(
            agg, window_years=window_years, min_total=min_total),
        "headline": {
            "latest_year": latest_year,
            "cna_count_latest": latest["cna_count"] if latest else 0,
            "top5_share_latest": latest["top5_share"] if latest else 0.0,
            "hhi_latest": latest["hhi"] if latest else 0.0,
            "baseline_year": baseline["year"] if baseline else 0,
            "top5_share_baseline":
                baseline["top5_share"] if baseline else 0.0,
            "hhi_baseline": baseline["hhi"] if baseline else 0.0,
        },
    }
