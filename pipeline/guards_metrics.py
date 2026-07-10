"""Security Products metrics (kev_guards.json).

The products sold to protect networks keep appearing in CISA's Known
Exploited Vulnerabilities catalog. This stage classifies every KEV entry
with the curated, versioned classifier in
:mod:`pipeline.security_products` (the decision rule and every judgment
call live in THAT module's docstring — the classification is the
methodological landmine here, and it is defused in writing, in one
place) and emits three views plus a whole-catalog audit block:

* **years** — per ``dateAdded`` calendar year, the share of new listings
  that are security products. ALL cohorts belong, the 2021–22 seeding
  era included: like the ransomware flag, "what kind of product is
  this?" rides on the entry itself, so a back-catalog import answers the
  question as well as a fresh listing does (kev_metrics'
  build_kev_ransomware states the same reasoning).
* **vendors** — the recidivism board: every vendor with at least
  ``min_vendor_entries`` catalog entries, with its security-classified
  entry count, first/last listing dates, and the median gap in days
  between consecutive listings. Vendor names are the catalog's own
  labels, whitespace-normalized but never merged (Pulse Secure stays
  distinct from Ivanti: the catalog's attribution is the record).
* **ransomware** — the ``knownRansomwareCampaignUse`` split: security
  products vs the rest of the catalog. No CVE join; a missing flag never
  counts as "Known" (same rule as kev_metrics).

Entries with an unparseable ``dateAdded`` join no year and no gap math
but still count in the catalog, ransomware and vendor totals.
"""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from typing import Iterable

from .fetch_kev import KevEntry
from .kev_metrics import _parse_date, _ransomware_known
from .metrics import _pct, _r1
from .security_products import (CLASSIFIER_VERSION, is_security_product,
                                normalize_vendor, rule_count)


def _split_block(entries: list[tuple[KevEntry, bool]], want: bool) -> dict:
    """total/known/pct_known over the entries whose security flag == want."""
    picked = [e for e, flag in entries if flag is want]
    known = sum(1 for e in picked if _ransomware_known(e))
    return {"total": len(picked), "known": known,
            "pct_known": _pct(known, len(picked))}


def build_kev_guards(entries: Iterable[KevEntry], generated_at: str, *,
                     min_n: int = 10, min_vendor_entries: int = 5) -> dict:
    """Assemble the kev_guards.json object.

    Years with fewer than ``min_n`` entries never plot (a share of three
    listings is an anecdote); vendors with fewer than
    ``min_vendor_entries`` catalog entries stay off the board (a median
    gap needs a history to be a cadence).
    """
    flagged = [(e, is_security_product(e.vendor_project, e.product))
               for e in entries]

    # ---- guard share per dateAdded year -----------------------------------
    total_by_year: Counter[int] = Counter()
    security_by_year: Counter[int] = Counter()
    for entry, is_sec in flagged:
        added = _parse_date(entry.date_added)
        if added is None:
            continue
        total_by_year[added.year] += 1
        if is_sec:
            security_by_year[added.year] += 1

    years = []
    for year in sorted(total_by_year):
        total = total_by_year[year]
        if total < min_n:
            continue
        security = security_by_year.get(year, 0)
        years.append({"year": year, "total": total, "security": security,
                      "pct_security": _pct(security, total)})

    # ---- recidivism board ---------------------------------------------------
    by_vendor: dict[str, list[tuple[KevEntry, bool]]] = defaultdict(list)
    for entry, is_sec in flagged:
        by_vendor[normalize_vendor(entry.vendor_project)].append(
            (entry, is_sec))
    by_vendor.pop("", None)  # entries with no vendorProject at all

    vendors = []
    for vendor, ventries in by_vendor.items():
        if len(ventries) < min_vendor_entries:
            continue
        dates = sorted(d for e, _ in ventries
                       if (d := _parse_date(e.date_added)) is not None)
        if not dates:  # undatable vendor block: no board row without dates
            continue
        gaps = [(b - a).days for a, b in zip(dates, dates[1:])]
        security = sum(1 for _, is_sec in ventries if is_sec)
        vendors.append({
            "vendor": vendor,
            "entries": len(ventries),
            "security_entries": security,
            "pct_security": _pct(security, len(ventries)),
            "first_added": dates[0].isoformat(),
            "last_added": dates[-1].isoformat(),
            "median_gap_days": _r1(statistics.median(gaps)) if gaps else None,
        })
    vendors.sort(key=lambda r: (-r["entries"], r["vendor"].casefold()))

    # ---- ransomware overlap + catalog audit block ---------------------------
    security_n = sum(1 for _, is_sec in flagged if is_sec)
    return {
        "generated_at": generated_at,
        "min_n": min_n,
        "min_vendor_entries": min_vendor_entries,
        "years": years,
        "vendors": vendors,
        "ransomware": {
            "security": _split_block(flagged, True),
            "other": _split_block(flagged, False),
        },
        "catalog": {
            "total": len(flagged),
            "security": security_n,
            "pct_security": _pct(security_n, len(flagged)),
            "classifier_version": CLASSIFIER_VERSION,
            "classifier_rules": rule_count(),
        },
    }
