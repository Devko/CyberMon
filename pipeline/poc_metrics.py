"""Time-to-PoC metrics (time_to_poc.json).

The attacker's clock: for every CVE that any public exploit tracker
references, the gap in days from the CVE record's publication to the
FIRST dated public PoC — the minimum over the dated sources (Exploit-DB
``date_published``, Metasploit ``disclosure_date``; Nuclei carries no
dates and contributes coverage only, see pipeline/fetch_poc.py).

Three sections:

* **hero** — median/IQR of the gap per CVE publication year over the
  matched cohort (a dated PoC AND a publication date in the corpus).
  Negative gaps are KEPT, never floored: a PoC that predates the CVE
  record is real (exploit code published while the id was reserved, or
  an old exploit assigned a CVE years later) — the KEV-latency
  precedent. Honesty: this measures PUBLIC PoC code in three trackers —
  a lower bound on tooling and an undercount of private exploits — and
  recent cohorts are right-censored (a 2025 CVE has had months, not
  years, to attract a PoC), which the methodology owns.
* **kev_preempt** — the share of KEV entries whose first public PoC
  predates their KEV ``dateAdded``. The 2021-22 seeding era is reported
  separately from the trend cohort (kev_metrics.LAUNCH_CUTOFF): a
  back-catalog import of years-old CVEs is trivially preempted by
  equally old exploit code, which measures backlog age, not the race.
* **coverage** — share of the latest complete year's published records
  that any of the three sources references, per CVSS severity bucket
  (the effective score the Score-vs-Reality chart uses, same bucketing
  as ``Aggregator.flood`` — coverage reuses that tally, never rebuckets).

Years/buckets below ``min_n`` never plot (a median of three gaps is an
anecdote). ``catalog`` is the audit block: per-source totals, extraction
and dating counts, and the corpus join coverage.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date
from typing import Iterable

from .fetch_kev import KevEntry
from .fetch_poc import PocData
from .kev_metrics import LAUNCH_CUTOFF, _parse_date
from datetime import timedelta

from .metrics import Aggregator, _pct, _quartiles, _r1

# Half-width, in days, of the like-for-like arming window (see
# _build_arming). A quarter: long enough that almost all arming that
# happens near disclosure is inside it, short enough that every cohort
# in the corpus — including a part-finished current year — has had the
# full window to produce it.
ARMING_HORIZON_DAYS = 90

# Severity-bucket key (Aggregator.flood) -> grid CVSS bucket label, in
# chart order (metrics.cvss_bucket's mapping, spelled once here).
_SEVERITY_TO_BUCKET = (("low", "0.1-3.9"), ("medium", "4.0-6.9"),
                       ("high", "7.0-8.9"), ("critical", "9.0-10.0"))


def _share_block(with_poc: int, preempted: int) -> dict:
    return {"with_poc_date": with_poc, "preempted": preempted,
            "pct_preempted": _pct(preempted, with_poc)}


def _build_arming(agg: Aggregator, first_poc: dict[str, str],
                  generated_at: str, min_n: int) -> dict:
    """The like-for-like clock: median gap inside a SYMMETRIC +/-horizon
    window, over cohorts old enough to have had the whole window.

    The hero series above is the honest raw record, but it is not
    comparable across years, for two reasons this section removes:

    * **Cohort maturity (right-censoring).** The hero's cohort is "CVEs
      that have a public PoC", so a 2019 record has had years to qualify
      and a record published last month has had weeks. Here every cohort
      is cut at ``generated_at - horizon``, so all of them have had
      exactly the same time to arm, and a part-finished current year is
      as comparable as a finished one. This is what lets the current
      year appear at all.
    * **Back-catalogued exploits.** Bounding the window BELOW as well as
      above is the other half. A gap of -4,452 days is an old exploit
      finally receiving a CVE id — a cataloguing event, not a fast one —
      and it drags a one-sided median arbitrarily negative (it is why
      the raw 2025 median reads -12d off a p25 of -4,452). Inside
      +/-horizon the statistic measures arming near disclosure, which is
      the thing the word "window" is supposed to mean.

    What it deliberately does NOT do is divide by all published CVEs.
    That rate collapses from ~45% to under 1% across the record, but
    almost entirely because annual CVE volume grew from ~5,700 to
    ~40,000 — a coverage story (which the coverage chart already tells)
    masquerading as a speed one.

    Remaining honesty note, carried in the page copy: this fixes cohort
    maturity, not tracker INGESTION lag. Exploit-DB and Metasploit add
    entries for older disclosures over time, so the newest cohort is
    still missing arming that will appear later, and reads slightly slow.
    """
    horizon = ARMING_HORIZON_DAYS
    observed_through = date.fromisoformat(generated_at[:10]) - \
        timedelta(days=horizon)

    gaps_by_year: dict[int, list[int]] = defaultdict(list)
    for cve, poc_date_s in first_poc.items():
        published = _parse_date(agg.poc_published_dates.get(cve))
        poc_date = _parse_date(poc_date_s)
        if published is None or poc_date is None:
            continue
        if published > observed_through:
            continue  # cohort has not had the full window yet
        gap = (poc_date - published).days
        if -horizon <= gap <= horizon:
            gaps_by_year[published.year].append(gap)

    years = []
    for year in sorted(gaps_by_year):
        gaps = gaps_by_year[year]
        n = len(gaps)
        if n < min_n:
            continue
        _p25, median, _p75 = _quartiles([float(v) for v in gaps])
        years.append({
            "year": year, "n": n,
            "median_days": _r1(median),
            "pct_within_week": _pct(sum(1 for v in gaps if v <= 7), n),
            "pct_negative": _pct(sum(1 for v in gaps if v < 0), n),
        })

    return {
        "horizon_days": horizon,
        "observed_through": observed_through.isoformat(),
        "years": years,
    }


def build_time_to_poc(agg: Aggregator, poc: PocData,
                      kev_entries: Iterable[KevEntry], generated_at: str,
                      *, min_n: int = 10) -> dict:
    """Assemble the time_to_poc.json object (contract:
    pipeline/poc_contracts.py; doc: docs/data-contracts.md)."""
    first_poc = poc.first_poc_dates

    # ---- hero: publication -> first public PoC ---------------------------
    gaps_by_year: dict[int, list[int]] = defaultdict(list)
    matched = unmatched = 0
    for cve, poc_date_s in first_poc.items():
        published = _parse_date(agg.poc_published_dates.get(cve))
        poc_date = _parse_date(poc_date_s)
        if published is None or poc_date is None:
            unmatched += 1
            continue
        matched += 1
        gaps_by_year[published.year].append((poc_date - published).days)

    years = []
    for year in sorted(gaps_by_year):
        gaps = gaps_by_year[year]
        if len(gaps) < min_n:
            continue
        p25, median, p75 = _quartiles([float(v) for v in gaps])
        n = len(gaps)
        years.append({
            "year": year, "n": n,
            "median_days": _r1(median),
            "p25_days": _r1(p25), "p75_days": _r1(p75),
            "pct_negative": _pct(sum(1 for v in gaps if v < 0), n),
            "pct_within_week": _pct(sum(1 for v in gaps if v <= 7), n),
        })

    # Headline never leans on the partial current year (house rule); the
    # baseline prefers a ten-year lookback, else the earliest surviving year.
    current_year = int(generated_at[:4])
    full_years = [row for row in years if row["year"] < current_year]
    latest = full_years[-1] if full_years else (years[-1] if years else None)
    latest_year = latest["year"] if latest else 0
    by_year = {row["year"]: row for row in years}
    baseline = by_year.get(latest_year - 10, years[0] if years else None)

    hero = {
        "matched": {"dated_cves": len(first_poc), "matched_cves": matched,
                    "unmatched_cves": unmatched},
        "years": years,
        "headline": {
            "latest_year": latest_year,
            "median_days_latest": latest["median_days"] if latest else 0.0,
            "pct_negative_latest": latest["pct_negative"] if latest else 0.0,
            "baseline_year": baseline["year"] if baseline else 0,
            "median_days_baseline":
                baseline["median_days"] if baseline else 0.0,
        },
    }

    # ---- PoC before the government confirms ------------------------------
    cutoff = date.fromisoformat(LAUNCH_CUTOFF)
    entries = list(kev_entries)
    trend_with = trend_pre = seed_with = seed_pre = 0
    year_total: dict[int, int] = defaultdict(int)
    year_with: dict[int, int] = defaultdict(int)
    year_pre: dict[int, int] = defaultdict(int)
    for entry in entries:
        added = _parse_date(entry.date_added)
        if added is None:
            continue
        year_total[added.year] += 1
        poc_date = _parse_date(first_poc.get(entry.cve_id))
        if poc_date is None:
            continue
        preempted = poc_date < added
        year_with[added.year] += 1
        year_pre[added.year] += preempted
        if added < cutoff:
            seed_with += 1
            seed_pre += preempted
        else:
            trend_with += 1
            trend_pre += preempted

    preempt_years = []
    for year in sorted(year_total):
        if year_with[year] < min_n:
            continue
        preempt_years.append({
            "year": year, "total_added": year_total[year],
            **_share_block(year_with[year], year_pre[year]),
        })

    kev_preempt = {
        "cutoff": LAUNCH_CUTOFF,
        "total_kev": len(entries),
        "trend": _share_block(trend_with, trend_pre),
        "seeding": _share_block(seed_with, seed_pre),
        "years": preempt_years,
    }

    # ---- coverage by CVSS bucket, latest complete year -------------------
    # Latest complete year with published records; if the corpus ends
    # earlier (frozen fixtures), the newest year it has.
    candidates = [y for y in agg.published_by_year if y < current_year]
    window_year = max(candidates) if candidates else \
        max(agg.published_by_year, default=0)
    totals = agg.flood.get(window_year, {})
    covered = agg.poc_flood.get(window_year, {})
    buckets = []
    for severity, bucket in _SEVERITY_TO_BUCKET:
        total = totals.get(severity, 0)
        if total < min_n:
            continue
        with_poc = covered.get(severity, 0)
        buckets.append({"bucket": bucket, "total": total,
                        "with_poc": with_poc,
                        "pct": _pct(with_poc, total)})
    unscored_total = totals.get("unscored", 0)
    coverage = {
        "window_year": window_year,
        "buckets": buckets,
        "unscored": {"total": unscored_total,
                     "with_poc": covered.get("unscored", 0),
                     "pct": _pct(covered.get("unscored", 0),
                                 unscored_total)},
    }

    # ---- catalog (audit block) -------------------------------------------
    catalog = {
        "exploitdb": {"entries": poc.edb_entries,
                      "with_cve": poc.edb_entries_with_cve,
                      "cves": len(poc.edb_ids),
                      "dated_cves": len(poc.edb_dates)},
        "metasploit": {"modules": poc.msf_modules,
                       "with_cve": poc.msf_modules_with_cve,
                       "cves": len(poc.msf_ids),
                       "dated_cves": len(poc.msf_dates)},
        "nuclei": {"templates": poc.nuclei_templates,
                   "cves": len(poc.nuclei_ids)},
        "union_cves": len(poc.all_ids),
        "dated_cves": len(first_poc),
        "matched_in_corpus": len(agg.poc_published_dates),
    }

    return {
        "generated_at": generated_at,
        "hero": hero,
        "arming": _build_arming(agg, first_poc, generated_at,
                                max(min_n, 1) if min_n < 10 else 30),
        "kev_preempt": kev_preempt,
        "coverage": coverage,
        "catalog": catalog,
    }
