"""CWE Top 25 vs reality (cwe_top25.json).

The official worst-bugs list against what actually ships and what actually
gets exploited. Three views of the same 25 CWE ids:

* **OFFICIAL** — MITRE's published annual CWE Top 25 (``cwe_top25_data``), a
  static hand-committed rank order. The latest committed year is the cut we
  compare against.
* **MEASURED** — raw first-listed-CWE prevalence over the last
  ``window_years`` complete calendar years (``agg.cwe_year_counts``, summed).
  Every CWE-tagged published record contributes one class, so this is "what
  ships", ranked across *all* CWEs — an official pick can rank anywhere.
* **EXPLOITED** — the first-listed CWE of every KEV-listed published record
  (``agg.kev_cwe_counts``): which classes actually get weaponized.

Like the rest of the codebase this reads aggregates the core streaming pass
already collects; it adds no second sweep over the corpus.

Honesty note (also in the site methodology): MITRE's own Top-25 formula is
derived from NVD CVEs joined to CISA KEV, so it is not an independent
oracle — there is partial circularity with our KEV cut. Our measured cut is
plain first-listed-CWE prevalence and our exploited cut is plain KEV
membership; the DIVERGENCE from the official *rank* is the story, and the
measured window is stated explicitly (``window`` in the payload).
"""
from __future__ import annotations

from collections import Counter

from .cwe_top25_data import cwe_name
from .metrics import Aggregator, _pct


def _cwe_number(cwe_id: str) -> int:
    """Numeric part of a CWE id, for deterministic tie-breaking."""
    try:
        return int(cwe_id.split("-", 1)[1])
    except (IndexError, ValueError):
        return 1 << 30


def build_cwe_top25(agg: Aggregator, generated_at: str, *,
                    official_lists: dict[int, list[str]],
                    window_years: int = 5, min_n: int = 2000) -> dict:
    """Assemble cwe_top25.json.

    ``official_lists`` maps year -> ranked CWE ids (rank 1 first); the
    newest committed year is the official cut. Measured prevalence is summed
    over the last ``window_years`` COMPLETE calendar years (ending the year
    before ``generated_at`` — the partial current year cannot rank a
    ranking). ``measured_rank`` is a CWE's position among *all* observed
    CWEs by that windowed prevalence (ties broken by CWE number, ascending),
    or ``null`` when the class never appears in the window.

    ``headline`` is ``null`` when the windowed corpus carries fewer than
    ``min_n`` CWE-tagged records — a divergence summary computed on a handful
    of records would be noise (the offline fixtures pass ``min_n=1`` so the
    tiny corpus still exercises the full path).
    """
    official_year = max(official_lists)
    official = official_lists[official_year]

    end_year = int(generated_at[:4]) - 1
    start_year = end_year - window_years + 1
    measured: Counter[str] = Counter()
    for year in range(start_year, end_year + 1):
        measured.update(agg.cwe_year_counts.get(year, Counter()))
    measured_total = sum(measured.values())

    # Rank ALL observed CWEs by windowed prevalence — an official pick can
    # land anywhere in (or fall off) this ranking. Ties break by CWE number
    # so the order is deterministic, matching the bug-class chart.
    ranked = sorted(measured.items(),
                    key=lambda kv: (-kv[1], _cwe_number(kv[0]), kv[0]))
    measured_rank = {cwe: i + 1 for i, (cwe, _n) in enumerate(ranked)}

    kev = agg.kev_cwe_counts
    kev_total = sum(kev.values())

    ranks = []
    for i, cwe in enumerate(official):
        n = measured.get(cwe, 0)
        ranks.append({
            "cwe": cwe,
            "name": cwe_name(cwe),
            "official_rank": i + 1,
            "measured_rank": measured_rank.get(cwe),  # None iff n == 0
            "measured_n": n,
            "measured_share": _pct(n, measured_total),
            "kev_n": kev.get(cwe, 0),
        })

    headline = None
    if measured_total >= min_n:
        in_top25 = sum(1 for r in ranks
                       if r["measured_rank"] is not None
                       and r["measured_rank"] <= len(official))
        in_kev = sum(1 for r in ranks if r["kev_n"] > 0)
        kev_covered = sum(r["kev_n"] for r in ranks)
        headline = {
            "official_year": official_year,
            "window_start": start_year,
            "window_end": end_year,
            "official_top_cwe": official[0],
            "measured_top_cwe": ranked[0][0],
            "in_measured_top25": in_top25,
            "outside_measured_top25": len(official) - in_top25,
            "in_kev": in_kev,
            "kev_coverage_pct": _pct(kev_covered, kev_total),
        }

    return {
        "generated_at": generated_at,
        "official_year": official_year,
        "official_years": sorted(official_lists),
        "window": {"start": start_year, "end": end_year},
        "window_years": window_years,
        "min_n": min_n,
        "measured_total": measured_total,
        "kev_total": kev_total,
        "ranks": ranks,
        "headline": headline,
    }
