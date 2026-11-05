"""CNA profiles (cna_profiles.json, the last section of concentration.html).

One CNA set against its peers. For every CNA with at least
``min_published`` published records in the last ``window_years`` COMPLETE
calendar years (the partial current year never counts), eight metrics:

* ``score_median`` — median CNA-assigned CVSS base score of its records
  (the newest CVSS version the CNA container carries, the same score
  ``cna_leaderboard.json`` reads). Ranked only with at least
  ``min_scored`` scored records; the per-CNA ``score_bins`` histogram is
  shipped either way, next to the pooled histogram of every CNA's records
  (``all``), so the site can draw the distribution against all CNAs.
* ``cwe_pct`` / ``scored_pct`` / ``affected_pct`` — share of its published
  records whose CNA container names a CWE, carries a CVSS base score, or
  carries usable affected-version data (``metrics._has_usable_affected``).
  CNA container only: ADP enrichment added later by CISA or others is
  not the CNA's own data, and counting it would rank CNAs partly on
  CISA's choices.
* ``rejected_pct`` — rejected / (published + rejected) by original
  publication year, the rejection board's bounded definition.
* ``rescores`` — same-version CNA score changes on the committed rescore
  log (``site/data/history/rescore_log.csv``, change_type ``rescore``),
  any record of the CNA, since the log began. Observation time, not
  publication time: the log starts on its ``first_observed`` date and has
  no earlier history. A count, not scaled by the CNA's size.
* ``kev_pct`` / ``exploit_pct`` — share of its published records in
  CISA's KEV catalog, and with tracked public exploit code (an Exploit-DB
  entry or a Metasploit exploit module: ``PocData.exploit_ids``).

Ranks: 1 is the highest value; ties share the best rank (1, 2, 2, 4),
computed on the rounded values as shipped. ``summary`` gives each
metric's spread over the ranked CNAs — the median CNA, quartiles
(``metrics._quartiles``, inclusive method) and the extremes.

Every tally is read from the shared corpus pass
(``Aggregator.cna_year_profile`` plus the published/rejected/score
tallies other modules already keep); no second pass, no fetch.
"""
from __future__ import annotations

import statistics
from collections import Counter
from typing import Iterable, Mapping

from .metrics import Aggregator, _pct, _quartiles, _r1

METRICS = ("score_median", "cwe_pct", "scored_pct", "affected_pct",
           "rejected_pct", "rescores", "kev_pct", "exploit_pct")
# Whole-point CVSS bins; a 10.0 falls in the last one.
SCORE_BINS = ("0.0-0.9", "1.0-1.9", "2.0-2.9", "3.0-3.9", "4.0-4.9",
              "5.0-5.9", "6.0-6.9", "7.0-7.9", "8.0-8.9", "9.0-10.0")

DEFAULT_WINDOW_YEARS = 5
DEFAULT_MIN_PUBLISHED = 100
DEFAULT_MIN_SCORED = 30


def score_bin(score: float) -> int:
    """Index into SCORE_BINS for a base score (10.0 -> the 9.0-10.0 bin)."""
    return max(0, min(int(score), len(SCORE_BINS) - 1))


def _bins(scores: Iterable[float]) -> list[int]:
    counts = [0] * len(SCORE_BINS)
    for s in scores:
        counts[score_bin(s)] += 1
    return counts


def competition_ranks(values: Mapping[str, float | int | None]
                      ) -> dict[str, int | None]:
    """Rank 1 = highest; ties share the best rank (1, 2, 2, 4); None
    values are unranked."""
    ranked = sorted(v for v in values.values() if v is not None)
    out: dict[str, int | None] = {}
    for key, v in values.items():
        if v is None:
            out[key] = None
            continue
        # count of values strictly greater than v, via the sorted list
        lo, hi = 0, len(ranked)
        while lo < hi:  # first index with ranked[i] > v
            mid = (lo + hi) // 2
            if ranked[mid] <= v:
                lo = mid + 1
            else:
                hi = mid
        out[key] = 1 + (len(ranked) - lo)
    return out


def _summary(values: list[float | int]) -> dict:
    if not values:
        return {"n": 0, "median": None, "p25": None, "p75": None,
                "min": None, "max": None}
    p25, median, p75 = _quartiles(sorted(values))
    return {"n": len(values), "median": _r1(median), "p25": _r1(p25),
            "p75": _r1(p75), "min": _r1(min(values)),
            "max": _r1(max(values))}


def _rescore_log_block(rows: list[dict]) -> tuple[Counter[str], dict]:
    counts = Counter(row["cna"] for row in rows
                     if row["change_type"] == "rescore")
    dates = [row["observed_date"] for row in rows]
    return counts, {
        "first_observed": min(dates, default=None),
        "last_observed": max(dates, default=None),
        "rescores": sum(counts.values()),
    }


def build_cna_profiles(agg: Aggregator, generated_at: str, *,
                       rescore_rows: Iterable[dict] = (),
                       window_years: int = DEFAULT_WINDOW_YEARS,
                       min_published: int = DEFAULT_MIN_PUBLISHED,
                       min_scored: int = DEFAULT_MIN_SCORED) -> dict:
    """Assemble cna_profiles.json (see the module docstring)."""
    to_year = int(generated_at[:4]) - 1  # last complete year
    from_year = to_year - window_years + 1
    window = range(from_year, to_year + 1)

    published: Counter[str] = Counter()
    rejected: Counter[str] = Counter()
    for year in window:
        published.update(agg.cna_year_published.get(year) or {})
        rejected.update(agg.cna_year_rejected.get(year) or {})

    def window_tally(cna: str) -> Counter[str]:
        per_year = agg.cna_year_profile.get(cna) or {}
        tally: Counter[str] = Counter()
        for year in window:
            tally.update(per_year.get(year) or {})
        return tally

    def window_scores(cna: str) -> list[float]:
        per_year = agg.cna_year_scores.get(cna) or {}
        return [s for year in window for s in per_year.get(year, ())]

    all_scores = [s for cna in published for s in window_scores(cna)]
    rescores, log_block = _rescore_log_block(list(rescore_rows))

    eligible = sorted((cna for cna, n in published.items()
                       if n >= min_published),
                      key=lambda cna: (-published[cna], cna))
    rows = []
    for cna in eligible:
        n = published[cna]
        tally = window_tally(cna)
        scores = window_scores(cna)
        counts = {"scored": len(scores), "cwe": tally["cwe"],
                  "affected": tally["affected"], "kev": tally["kev"],
                  "exploit": tally["exploit"]}
        values = {
            "score_median": (_r1(statistics.median(scores))
                             if len(scores) >= min_scored else None),
            "cwe_pct": _pct(counts["cwe"], n),
            "scored_pct": _pct(counts["scored"], n),
            "affected_pct": _pct(counts["affected"], n),
            "rejected_pct": _pct(rejected[cna], n + rejected[cna]),
            "rescores": rescores.get(cna, 0),
            "kev_pct": _pct(counts["kev"], n),
            "exploit_pct": _pct(counts["exploit"], n),
        }
        rows.append({"cna": cna, "published": n, "rejected": rejected[cna],
                     "counts": counts, "score_bins": _bins(scores),
                     "values": values})

    summary = {}
    for metric in METRICS:
        ranks = competition_ranks({r["cna"]: r["values"][metric]
                                   for r in rows})
        for r in rows:
            r.setdefault("ranks", {})[metric] = ranks[r["cna"]]
        summary[metric] = _summary([r["values"][metric] for r in rows
                                    if r["values"][metric] is not None])

    return {
        "generated_at": generated_at,
        "window": {"from": from_year, "to": to_year, "years": window_years},
        "min_published": min_published,
        "min_scored": min_scored,
        "metrics": list(METRICS),
        "score_bins": list(SCORE_BINS),
        "all": {
            "cna_count": len(published),
            "published": sum(published.values()),
            "scored": len(all_scores),
            "score_bins": _bins(all_scores),
            "score_median": (_r1(statistics.median(all_scores))
                             if all_scores else None),
        },
        "rescore_log": log_block,
        "summary": summary,
        "cnas": rows,
    }
