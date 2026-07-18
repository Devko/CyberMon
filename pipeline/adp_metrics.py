"""Vulnrichment / CISA-ADP handoff metrics (adp_coverage.json).

When NVD's analysis pipeline stalled through 2024, CISA's Vulnrichment
program — the CISA-ADP container bolted onto the CVE record — became the
de-facto enricher of the CVE stream. This stage reads that handoff straight
off the corpus the core streaming pass already parsed
(pipeline/metrics.py): no new upstream, no separate fetch.

Three views, all over PUBLISHED records:

* the monthly enrichment curve, bucketed by the CISA-ADP container's own
  ``dateUpdated`` month — NOT the CVE's ``datePublished``. CISA back-fills
  legacy records (a 2019 CVE's CISA-ADP block is stamped 2025), so a
  publication-date axis would smear a false pre-2024 signal. A month whose
  enrichments are mostly legacy back-fills (the CVE ID's vintage at least
  ``ADP_LEGACY_GAP_YEARS`` older than the enrichment year) is flagged as a
  back-fill sweep.
* what the enrichment adds: the share of CISA-ADP records carrying an SSVC
  decision, a CVSS score, a CWE — SSVC is near-universal, CVSS/CWE are
  selective patch-ins added where the CNA left a gap.
* the sole-enricher board: every ADP provider by how many records it
  substantively enriches (adds an SSVC decision, a CVSS score, or a CWE).
  CISA-ADP dominates; the CVE Program's own root container rides on most
  records but adds only reference tags, so it never tops the board.

Monthly granularity is new to this codebase: the contract validates a
``"YYYY-MM"`` month key, sorted ascending and unique.

Honest limit (stated in the site methodology): CyberMon's own NVD backlog
record only begins at launch, so there is no 2024 NVD flow to overlay as a
line here — NVD's documented slowdown is referenced in prose, and the
current backlog figure is read client-side from ``nvd_decay.json`` for
scale, never charted as a fabricated trend.
"""
from __future__ import annotations

from .metrics import Aggregator, _pct

# The site charts the three additions in this order (SSVC first — it is the
# near-universal contribution). Kept here so builder and contract agree.
ADD_FIELDS = ("ssvc", "cvss", "cwe")

# A month is a back-fill sweep when at least this share of its enrichments
# are legacy back-fills (see metrics.ADP_LEGACY_GAP_YEARS). Documented in the
# hero's methodology footnote — change both together.
BACKFILL_LEGACY_SHARE = 0.5


def _month_range(first: str, last: str) -> list[str]:
    """Every ``"YYYY-MM"`` from ``first`` to ``last`` inclusive, gap-filled,
    so the monthly axis never silently skips a month."""
    year, month = int(first[:4]), int(first[5:7])
    last_year, last_month = int(last[:4]), int(last[5:7])
    months: list[str] = []
    while (year, month) <= (last_year, last_month):
        months.append(f"{year:04d}-{month:02d}")
        month += 1
        if month > 12:
            year, month = year + 1, 1
    return months


def build_adp_coverage(agg: Aggregator, generated_at: str, *,
                       min_n: int = 50) -> dict:
    """Assemble adp_coverage.json from the aggregator's CISA-ADP tallies.

    ``min_n`` gates the monthly curve's start: the series begins at the
    first month clearing ``min_n`` enrichments (so a stray pre-launch
    dateUpdated stamp can't open the chart on a lone bar) and runs
    gap-filled to the last month observed. On a tiny corpus (fixtures,
    ``min_n=1``) the single enriched month emits. A month is flagged
    ``backfill`` when it clears ``min_n`` and a majority of its enrichments
    landed on legacy CVEs.
    """
    all_months = sorted(agg.adp_month_enriched)
    months: list[dict] = []
    if all_months:
        qualifying = [m for m in all_months
                      if agg.adp_month_enriched[m] >= min_n]
        if qualifying:
            for month in _month_range(qualifying[0], all_months[-1]):
                enriched = agg.adp_month_enriched.get(month, 0)
                legacy = agg.adp_month_legacy.get(month, 0)
                added = agg.adp_month_added.get(month) or {}
                months.append({
                    "month": month,
                    "enriched": enriched,
                    "ssvc": added.get("ssvc", 0),
                    "cvss": added.get("cvss", 0),
                    "cwe": added.get("cwe", 0),
                    "legacy": legacy,
                    # A sweep needs real volume (>= min_n) and a legacy
                    # majority — not one stray old stamp in a quiet month.
                    "backfill": (enriched >= min_n
                                 and legacy >= BACKFILL_LEGACY_SHARE * enriched
                                 and enriched > 0),
                })

    total_cisa = agg.adp_cisa_total
    adds = {"total": total_cisa}
    for key in ADD_FIELDS:
        n = agg.adp_add_counts.get(key, 0)
        adds[key] = n
        adds[f"pct_{key}"] = _pct(n, total_cisa)

    published = agg.adp_published_total
    # The board ranks ADP providers by SUBSTANTIVE enrichment — records where
    # they added an SSVC decision, a CVSS score, or a CWE, not merely a
    # reference tag. The CVE Program's own root container rides on most
    # records but enriches none, so it never crowns the board.
    providers = [
        {"provider": name, "n": n, "pct": _pct(n, published)}
        for name, n in sorted(agg.adp_provider_substantive.items(),
                              key=lambda kv: (-kv[1], kv[0]))
        if n > 0
    ]

    # Peak = the busiest enrichment month; ties keep the earliest (months is
    # ascending, so the first max wins).
    peak_month: str | None = None
    peak_enriched = 0
    for row in months:
        if row["enriched"] > peak_enriched:
            peak_enriched, peak_month = row["enriched"], row["month"]

    headline = {
        "total_published": published,
        "total_cisa": total_cisa,
        "pct_cisa": _pct(total_cisa, published),
        "first_month": months[0]["month"] if months else None,
        "last_month": months[-1]["month"] if months else None,
        "peak_month": peak_month,
        "peak_enriched": peak_enriched,
        "sole_enricher": providers[0]["provider"] if providers else None,
        "backfill_month_count": sum(1 for r in months if r["backfill"]),
    }
    return {
        "generated_at": generated_at,
        "min_n": min_n,
        "months": months,
        "adds": adds,
        "providers": providers,
        "headline": headline,
    }
