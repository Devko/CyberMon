"""CVSS 4.0 adoption metrics (cvss_v4.json) — a section of module 01.

CVSS 4.0 was published in November 2023. This stage reads, from the core
streaming pass (pipeline/metrics.py, ``Aggregator._add_v4``), which newly
published records carry a v4.0 base score and who put it there. No new
upstream.

Coverage is read from the CNA container only — the question is what the
CNA of record scored. CISA's ADP container adds CVSS v3.1 scores to many
records the CNA left unscored; those are NOT counted as v3 coverage here
(the 9.8 flood's effective-score rule does count them, because that chart
asks what severity a record carries, not who scored it). How many "neither"
records carry an ADP score ships as ``neither_adp`` so the gap is visible.

Every PUBLISHED record falls in exactly one class:

* ``v4_only`` — a CNA v4.0 score and no v3.x score;
* ``both`` — CNA v3.x (3.0 or 3.1) and v4.0 scores;
* ``v3_only`` — a CNA v3.x score and no v4.0 score;
* ``neither`` — no CNA v3.x or v4.0 score (a v2-only record lands here).

Views: monthly shares by publication month from ``V4_SINCE_MONTH``; yearly
shares from 2023; the adopters board (CNAs by v4-scored volume since
``V4_SINCE_MONTH``, with their v4 and v4-only shares); and, on records the
CNA scored under both versions, the distribution of v4.0 minus v3.x base
score and whether the severity band agrees.
"""
from __future__ import annotations

import statistics
from collections import Counter

from .adp_metrics import _month_range
from .metrics import V4_SINCE_MONTH, Aggregator, _pct, _r1

CLASSES = ("v4_only", "both", "v3_only", "neither")
FIRST_YEAR = 2023  # the yearly table starts in the release year
# Adopters board: CNAs with at least this many v4-scored records since
# V4_SINCE_MONTH, top ADOPTERS_TOP by that volume.
ADOPTERS_MIN_V4 = 50
ADOPTERS_TOP = 15
# Delta histogram: v4 - v3 in half-point bins centred on -3.0 .. +3.0; the
# two end bins collect everything beyond (down to -10.0 / up to +10.0).
DELTA_EDGE_TENTHS = 30
# Per-CNA comparison rows: the largest dual scorers with at least this many
# dual-scored records.
DUAL_MIN_N = 100
DUAL_TOP = 8


def _class_row(counter: Counter[str]) -> dict:
    return {k: int(counter.get(k, 0)) for k in CLASSES}


def _median_tenths(counter: Counter[int]) -> float:
    values = sorted(counter.elements())
    return _r1(statistics.median(values) / 10) if values else 0.0


def _delta_bins(delta: Counter[int]) -> list[dict]:
    """Half-point bins: a delta of d tenths lands in the bin centred on
    round(d / 5) * 0.5, clamped to the open end bins."""
    edge = DELTA_EDGE_TENTHS // 5
    bins: Counter[int] = Counter()
    for tenths, n in delta.items():
        # round half away from zero so bins are symmetric about 0
        half = int(abs(tenths) / 5 + 0.5) * (1 if tenths >= 0 else -1)
        bins[max(-edge, min(edge, half))] += n
    # A bin centred on c covers c-0.2 .. c+0.2 (scores are 0.1-granular);
    # the end bins run out to the +/-10.0 a delta can reach.
    return [{"center": _r1(k * 0.5),
             "lo": -10.0 if k == -edge else _r1(k * 0.5 - 0.2),
             "hi": 10.0 if k == edge else _r1(k * 0.5 + 0.2),
             "n": bins.get(k, 0)}
            for k in range(-edge, edge + 1)]


def build_cvss_v4(agg: Aggregator, generated_at: str, *,
                  adopters_min_v4: int = ADOPTERS_MIN_V4,
                  dual_min_n: int = DUAL_MIN_N) -> dict:
    """Assemble the cvss_v4.json object."""
    current_year = int(generated_at[:4])
    current_month = generated_at[:7]

    months = []
    if agg.v4_month:
        last = max(max(agg.v4_month), V4_SINCE_MONTH)
        for month in _month_range(V4_SINCE_MONTH, last):
            row = _class_row(agg.v4_month.get(month) or Counter())
            months.append({"month": month,
                           "published": sum(row.values()), **row})

    years = []
    last_year = max(agg.published_by_year, default=0)
    for year in range(FIRST_YEAR, last_year + 1):
        counter = agg.v4_year.get(year) or Counter()
        row = _class_row(counter)
        years.append({"year": year, "published": sum(row.values()), **row,
                      "neither_adp": int(counter.get("neither_adp", 0)),
                      "v4_cnas": len(agg.v4_year_cna.get(year) or {})})

    adopters = []
    for cna, c in agg.v4_window_cna.items():
        if c["v4"] < adopters_min_v4:
            continue
        adopters.append({"cna": cna, "published": c["n"], "v4": c["v4"],
                         "v4_only": c["v4_only"],
                         "v4_share_pct": _pct(c["v4"], c["n"]),
                         "v4_only_share_pct": _pct(c["v4_only"], c["n"])})
    adopters.sort(key=lambda r: (-r["v4"], r["cna"]))
    window_published = sum(c["n"] for c in agg.v4_window_cna.values())
    window_v4 = sum(c["v4"] for c in agg.v4_window_cna.values())
    top = adopters[:ADOPTERS_TOP]

    n_dual = sum(agg.v4_delta_tenths.values())
    dual_cnas = []
    for cna, delta in agg.v4_delta_cna.items():
        n = sum(delta.values())
        if n < dual_min_n:
            continue
        band = agg.v4_band_cna[cna]
        dual_cnas.append({"cna": cna, "n": n,
                          "median_delta": _median_tenths(delta),
                          "same_band_pct": _pct(band["same"], n),
                          "v4_higher_pct": _pct(band["v4_higher"], n),
                          "v4_lower_pct": _pct(band["v4_lower"], n)})
    dual_cnas.sort(key=lambda r: (-r["n"], r["cna"]))

    by_year = {r["year"]: r for r in years}
    cur = by_year.get(current_year)
    full = [r for r in years if r["year"] < current_year and r["published"]]
    latest = full[-1] if full else None

    def share(row: dict | None) -> float:
        if not row or not row["published"]:
            return 0.0
        return _pct(row["v4_only"] + row["both"], row["published"])

    return {
        "generated_at": generated_at,
        "since_month": V4_SINCE_MONTH,
        "container": "cna",
        "classes": list(CLASSES),
        "months": months,
        "years": years,
        "adopters": {
            "window_from": V4_SINCE_MONTH,
            "min_v4": adopters_min_v4,
            "window_published": window_published,
            "window_v4": window_v4,
            "adopter_count": sum(1 for c in agg.v4_window_cna.values()
                                 if c["v4"]),
            "top_share_pct": _pct(sum(r["v4"] for r in top), window_v4),
            "cnas": top,
        },
        "compare": {
            "n": n_dual,
            "median_delta": _median_tenths(agg.v4_delta_tenths),
            "same_band": agg.v4_band.get("same", 0),
            "v4_higher": agg.v4_band.get("v4_higher", 0),
            "v4_lower": agg.v4_band.get("v4_lower", 0),
            "same_band_pct": _pct(agg.v4_band.get("same", 0), n_dual),
            "v4_higher_pct": _pct(agg.v4_band.get("v4_higher", 0), n_dual),
            "v4_lower_pct": _pct(agg.v4_band.get("v4_lower", 0), n_dual),
            "bins": _delta_bins(agg.v4_delta_tenths),
            "min_n": dual_min_n,
            "cnas": dual_cnas[:DUAL_TOP],
        },
        "headline": {
            "current_year": current_year,
            "current_month": current_month,
            "v4_share_current_pct": share(cur),
            "v4_current": (cur["v4_only"] + cur["both"]) if cur else 0,
            "published_current": cur["published"] if cur else 0,
            "latest_year": latest["year"] if latest else 0,
            "v4_share_latest_pct": share(latest),
            "v4_cnas_current": cur["v4_cnas"] if cur else 0,
        },
    }
