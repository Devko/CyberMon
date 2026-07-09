"""Advisory-quality and bug-class metrics (advisory_quality.json and
cwe_distribution.json).

Both charts read aggregates the core streaming pass already collects
(:class:`pipeline.metrics.Aggregator`); this module adds no second sweep
over the corpus.

* **Advisory quality** — per publication year, the share of published
  records missing each of three machine-readable fields: a CWE (no
  problemTypes description with a ``cweId`` in any container), a CVSS base
  score (no score in any metrics container — the same definition as the
  flood chart's "unscored"), and structured affected-version data (no
  affected[] entry with a concrete versions[] item or a definite
  defaultStatus; see ``metrics._has_usable_affected``).

* **Bug-class inertia** — each CWE-tagged published record contributes its
  first-listed CWE (one class per record, so shares sum to ~100). The top
  ``top_k`` classes by total volume over the last ``window_years`` complete
  calendar years get their own series; everything else folds into
  ``"other"``. Shares are of the year's *tagged* records only — coverage
  varies wildly by year, so every row also carries ``pct_tagged``.

Honesty filters mirror the rest of the codebase: a year plots only with at
least ``min_n`` records (published for chart 7, tagged for chart 8);
chart 8's window ends at the last complete year, so the partial current
year never distorts a decade ranking.
"""
from __future__ import annotations

from collections import Counter

from .metrics import Aggregator, _pct

# Human-readable names for common CWE ids (chart labels only — unmapped ids
# fall back to the bare id). Deliberately tiny: this is not a CWE database.
CWE_NAMES = {
    "CWE-20": "Improper input validation",
    "CWE-22": "Path traversal",
    "CWE-78": "OS command injection",
    "CWE-79": "Cross-site scripting",
    "CWE-89": "SQL injection",
    "CWE-94": "Code injection",
    "CWE-119": "Buffer errors",
    "CWE-125": "Out-of-bounds read",
    "CWE-306": "Missing authentication",
    "CWE-352": "Cross-site request forgery",
    "CWE-416": "Use after free",
    "CWE-434": "Unrestricted file upload",
    "CWE-476": "NULL pointer dereference",
    "CWE-502": "Deserialization of untrusted data",
    "CWE-787": "Out-of-bounds write",
    "CWE-862": "Missing authorization",
    "CWE-863": "Incorrect authorization",
}


def cwe_name(cwe_id: str) -> str:
    """Display name for a CWE id, the bare id when unmapped."""
    return CWE_NAMES.get(cwe_id, cwe_id)


def _cwe_number(cwe_id: str) -> int:
    """Numeric part of a CWE id, for deterministic tie-breaking."""
    try:
        return int(cwe_id.split("-", 1)[1])
    except (IndexError, ValueError):
        return 1 << 30


def build_advisory_quality(agg: Aggregator, generated_at: str, *,
                           min_n: int = 500) -> dict:
    """Chart 7: share of published records missing CWE / CVSS / affected
    data per publication year. Years with fewer than ``min_n`` published
    records never plot — a percentage of a handful of records is noise."""
    years = []
    for year in sorted(agg.published_by_year):
        n = agg.published_by_year[year]
        if n < min_n:
            continue
        missing = agg.quality_missing.get(year, Counter())
        row: dict = {"year": year, "n": n}
        for key in ("cwe", "cvss", "affected"):
            row[f"missing_{key}"] = missing.get(key, 0)
            row[f"pct_missing_{key}"] = _pct(missing.get(key, 0), n)
        years.append(row)
    return {"generated_at": generated_at, "min_n": min_n, "years": years}


def build_cwe_distribution(agg: Aggregator, generated_at: str, *,
                           top_k: int = 8, window_years: int = 10,
                           min_n: int = 500) -> dict:
    """Chart 8: per-year share of each top-``top_k`` CWE among CWE-tagged
    published records, plus ``"other"``, over the last ``window_years``
    complete calendar years (the partial current year is excluded — it
    cannot rank a decade). Ranking ties break by CWE number, ascending."""
    end_year = int(generated_at[:4]) - 1
    start_year = end_year - window_years + 1

    totals: Counter[str] = Counter()
    for year in range(start_year, end_year + 1):
        totals.update(agg.cwe_year_counts.get(year, Counter()))
    ranked = sorted(totals.items(),
                    key=lambda kv: (-kv[1], _cwe_number(kv[0]), kv[0]))
    top_ids = [cwe_id for cwe_id, _n in ranked[:top_k]]

    years = []
    for year in range(start_year, end_year + 1):
        counts = agg.cwe_year_counts.get(year, Counter())
        n_tagged = sum(counts.values())
        if n_tagged < min_n:
            continue
        n_published = agg.published_by_year.get(year, 0)
        shares = {cwe_id: _pct(counts.get(cwe_id, 0), n_tagged)
                  for cwe_id in top_ids}
        in_top = sum(counts.get(cwe_id, 0) for cwe_id in top_ids)
        shares["other"] = _pct(n_tagged - in_top, n_tagged)
        years.append({"year": year, "n_tagged": n_tagged,
                      "n_published": n_published,
                      "pct_tagged": _pct(n_tagged, n_published),
                      "shares": shares})

    return {
        "generated_at": generated_at,
        "min_n": min_n,
        "window": {"start_year": start_year, "end_year": end_year},
        "top_cwes": [{"id": cwe_id, "name": cwe_name(cwe_id)}
                     for cwe_id in top_ids],
        "years": years,
    }
