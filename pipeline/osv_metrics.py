"""Advisory Gap (module 25) and Registry Malware (module 26) builders.

Both read the per-ecosystem summaries of the OSV exports
(:mod:`pipeline.fetch_osv`); neither keeps history of its own — the
exports carry the whole record every night.

advisory_gap.json — GitHub-reviewed advisories (GHSA ids), withdrawn ones
excluded, merged by id across ecosystems. Per GitHub publication year (the
advisory's ``published`` date — when GitHub published it, which for an old
CVE imported later is the import date, not the vulnerability's age) and per
ecosystem: total, with a CVE alias, without. "With a CVE" means OSV lists a
``CVE-`` alias; OSV also links aliases from the CVE side, so its list can be
longer than GitHub's own and the no-CVE count is the narrower one.

A no-CVE advisory can gain a CVE later. Advisories published within
:data:`YOUNG_DAYS` of the edition are therefore split out as the *young*
no-CVE cohort, and ``cve_lag`` reports, for advisories that have a CVE with
an NVD publication date, how many saw that CVE reach NVD more than 30 / 90
/ 365 days after the advisory — the evidence for how provisional a young
"no CVE" is.

registry_malware.json — OpenSSF malicious-packages reports (MAL ids) per
ecosystem per publication month: the report's ``published`` stamp in the
feed, not when the package went live and not an install or victim count.
Withdrawn reports are counted in every total and reported separately.
"""
from __future__ import annotations

import statistics
from datetime import date, timedelta
from pathlib import Path
from typing import Callable

from .fetch_osv import (G_CVE, G_ECOSYSTEMS, G_ID, G_NVD_LAG, G_PUBLISHED,
                        G_REVIEWED, G_SEVERITY, G_WITHDRAWN, GHSA_ECOSYSTEMS,
                        MAL_ECOSYSTEMS, SEVERITIES, EcosystemSummary)

YOUNG_DAYS = 90
MIN_SHARE_N = 50
LAG_DAYS = (30, 90, 365)
UNRATED = "UNRATED"
SEVERITY_LEVELS = SEVERITIES + (UNRATED,)
MEDIAN_WINDOW_MONTHS = 24
BURST_COUNT = 3

FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures" / "osv"


def _pct(n: int, d: int) -> float | None:
    return round(100.0 * n / d, 1) if d else None


# ---- module 25: advisory gap ----------------------------------------------------

def merge_ghsa(summaries: dict[str, EcosystemSummary]) -> dict[str, list]:
    """GHSA rows merged by id across every export (an advisory affecting
    several ecosystems sits in several zips). The first row wins for the
    scalar fields; affected ecosystems are unioned."""
    merged: dict[str, list] = {}
    for eco in sorted(summaries):
        for row in summaries[eco].ghsa:
            prior = merged.get(row[G_ID])
            if prior is None:
                merged[row[G_ID]] = list(row[:G_ECOSYSTEMS]) + \
                    [sorted(set(row[G_ECOSYSTEMS]))]
            else:
                prior[G_ECOSYSTEMS] = sorted(set(prior[G_ECOSYSTEMS])
                                             | set(row[G_ECOSYSTEMS]))
    return merged


def _tally() -> dict:
    return {"total": 0, "with_cve": 0, "without_cve": 0,
            "without_cve_young": 0}


def _add(t: dict, has_cve: bool, young: bool) -> None:
    t["total"] += 1
    if has_cve:
        t["with_cve"] += 1
    else:
        t["without_cve"] += 1
        if young:
            t["without_cve_young"] += 1


def build_advisory_gap(summaries: dict[str, EcosystemSummary],
                       generated_at: str, *, min_n: int = MIN_SHARE_N,
                       young_days: int = YOUNG_DAYS) -> dict:
    today = date.fromisoformat(generated_at[:10])
    gen_year = today.year
    young_since = (today - timedelta(days=young_days)).isoformat()
    merged = merge_ghsa(summaries)

    withdrawn = sum(1 for r in merged.values() if r[G_WITHDRAWN])
    not_reviewed = sum(1 for r in merged.values()
                       if not r[G_WITHDRAWN] and not r[G_REVIEWED])
    live = [r for r in merged.values()
            if not r[G_WITHDRAWN] and r[G_REVIEWED]]

    overall = _tally()
    by_year: dict[int, dict] = {}
    by_eco: dict[str, dict] = {}
    eco_year: dict[str, dict[int, dict]] = {}
    sev = {lvl: {"with_cve": 0, "without_cve": 0} for lvl in SEVERITY_LEVELS}
    lag_n = 0
    lag_later = {d: 0 for d in LAG_DAYS}
    multi = 0
    for r in live:
        year = int(r[G_PUBLISHED][:4])
        has_cve = bool(r[G_CVE])
        young = r[G_PUBLISHED] >= young_since
        _add(overall, has_cve, young)
        _add(by_year.setdefault(year, _tally()), has_cve, young)
        ecos = r[G_ECOSYSTEMS]
        if len(ecos) > 1:
            multi += 1
        for eco in ecos:
            _add(by_eco.setdefault(eco, _tally()), has_cve, young)
            _add(eco_year.setdefault(eco, {}).setdefault(year, _tally()),
                 has_cve, young)
        level = r[G_SEVERITY] or UNRATED
        sev[level]["with_cve" if has_cve else "without_cve"] += 1
        if has_cve and r[G_NVD_LAG] is not None:
            lag_n += 1
            for d in LAG_DAYS:
                if r[G_NVD_LAG] > d:
                    lag_later[d] += 1

    years_range = list(range(min(by_year), max(by_year) + 1)) if by_year \
        else []

    def year_rows(src: dict[int, dict]) -> list[dict]:
        rows = []
        for y in years_range:
            t = src.get(y, _tally())
            rows.append({"year": y, **t,
                         "without_cve_pct": _pct(t["without_cve"],
                                                 t["total"]),
                         "partial": y == gen_year})
        return rows

    order = {e: i for i, e in enumerate(GHSA_ECOSYSTEMS)}
    ecosystems = []
    for eco, t in sorted(by_eco.items(),
                         key=lambda kv: (-kv[1]["total"],
                                         order.get(kv[0], 99), kv[0])):
        ecosystems.append({
            "ecosystem": eco, **t,
            "without_cve_pct": (_pct(t["without_cve"], t["total"])
                                if t["total"] >= min_n else None),
            "years": [{k: v for k, v in row.items() if k != "partial"}
                      for row in year_rows(eco_year[eco])],
        })

    with_total = overall["with_cve"]
    without_total = overall["without_cve"]
    severity = [{"level": lvl, **sev[lvl],
                 "with_cve_pct": _pct(sev[lvl]["with_cve"], with_total),
                 "without_cve_pct": _pct(sev[lvl]["without_cve"],
                                         without_total)}
                for lvl in SEVERITY_LEVELS]

    return {
        "generated_at": generated_at,
        # The date the counts were read. Partial-year flags and the young
        # window hang off this, not generated_at, so a carried-forward
        # edition (restamped generated_at) stays self-consistent.
        "as_of": today.isoformat(),
        "ecosystems_read": sorted(e for e in summaries
                                  if e in GHSA_ECOSYSTEMS),
        "young_days": young_days,
        "young_since": young_since,
        "min_n": min_n,
        "catalog": {
            "advisories": overall["total"],
            "with_cve": overall["with_cve"],
            "without_cve": overall["without_cve"],
            "without_cve_young": overall["without_cve_young"],
            "without_cve_pct": _pct(overall["without_cve"], overall["total"]),
            "withdrawn_excluded": withdrawn,
            "not_reviewed": not_reviewed,
            "multi_ecosystem": multi,
            "first_year": years_range[0] if years_range else None,
            "last_year": years_range[-1] if years_range else None,
        },
        "years": year_rows(by_year),
        "ecosystems": ecosystems,
        "severity": severity,
        "cve_lag": {"n": lag_n,
                    **{f"later_{d}d": lag_later[d] for d in LAG_DAYS}},
    }


# ---- module 26: registry malware -------------------------------------------------

def _month_range(first: str, last: str) -> list[str]:
    y, m = int(first[:4]), int(first[5:7])
    out = []
    while f"{y:04d}-{m:02d}" <= last:
        out.append(f"{y:04d}-{m:02d}")
        m += 1
        if m == 13:
            y, m = y + 1, 1
    return out


def build_registry_malware(summaries: dict[str, EcosystemSummary],
                           generated_at: str, *,
                           median_window: int = MEDIAN_WINDOW_MONTHS) -> dict:
    gen_month = generated_at[:7]
    gen_year = int(generated_at[:4])
    months: dict[str, dict] = {}
    eco_totals: dict[str, list[int]] = {}
    sources_by_month: dict[str, dict[str, int]] = {}
    for eco in sorted(summaries):
        s = summaries[eco]
        for month, (n, wd) in s.mal_months.items():
            if n <= 0:
                continue
            slot = months.setdefault(month, {"total": 0, "withdrawn": 0,
                                             "by_ecosystem": {}})
            slot["total"] += n
            slot["withdrawn"] += wd
            slot["by_ecosystem"][eco] = slot["by_ecosystem"].get(eco, 0) + n
            tot = eco_totals.setdefault(eco, [0, 0])
            tot[0] += n
            tot[1] += wd
        for month, per in s.mal_sources.items():
            dst = sources_by_month.setdefault(month, {})
            for src, n in per.items():
                dst[src] = dst.get(src, 0) + n

    reports = sum(m["total"] for m in months.values())
    withdrawn = sum(m["withdrawn"] for m in months.values())
    order = {e: i for i, e in enumerate(MAL_ECOSYSTEMS)}
    eco_rows = [{"ecosystem": e, "reports": t[0], "withdrawn": t[1],
                 "withdrawn_pct": _pct(t[1], t[0])}
                for e, t in sorted(eco_totals.items(),
                                   key=lambda kv: (-kv[1][0],
                                                   order.get(kv[0], 99),
                                                   kv[0]))]
    eco_names = [r["ecosystem"] for r in eco_rows]

    month_rows = []
    if months:
        # Run to the edition month even when it has no report yet: an
        # empty current month is a reading, not a missing row.
        for m in _month_range(min(months), max(max(months), gen_month)):
            slot = months.get(m, {"total": 0, "withdrawn": 0,
                                  "by_ecosystem": {}})
            month_rows.append({
                "month": m, "total": slot["total"],
                "withdrawn": slot["withdrawn"],
                "by_ecosystem": {e: slot["by_ecosystem"][e]
                                 for e in eco_names
                                 if slot["by_ecosystem"].get(e)},
                "partial": m == gen_month,
            })

    year_map: dict[int, dict] = {}
    for row in month_rows:
        y = int(row["month"][:4])
        slot = year_map.setdefault(y, {"total": 0, "withdrawn": 0,
                                       "by_ecosystem": {}})
        slot["total"] += row["total"]
        slot["withdrawn"] += row["withdrawn"]
        for e, n in row["by_ecosystem"].items():
            slot["by_ecosystem"][e] = slot["by_ecosystem"].get(e, 0) + n
    year_rows = [{"year": y, "total": v["total"], "withdrawn": v["withdrawn"],
                  "by_ecosystem": {e: v["by_ecosystem"][e] for e in eco_names
                                   if v["by_ecosystem"].get(e)},
                  "partial": y == gen_year}
                 for y, v in sorted(year_map.items())]

    complete = [r for r in month_rows if not r["partial"]]
    window = complete[-median_window:]
    median_month = (int(statistics.median(r["total"] for r in window))
                    if window else None)
    peak = max(month_rows, key=lambda r: (r["total"], r["month"])) \
        if month_rows else None

    bursts = []
    for row in sorted(month_rows, key=lambda r: (-r["total"], r["month"])
                      )[:BURST_COUNT]:
        if row["total"] <= 0:
            continue
        per = sources_by_month.get(row["month"], {})
        top_src, top_n = (min(per.items(), key=lambda kv: (-kv[1], kv[0]))
                          if per else (None, 0))
        bursts.append({"month": row["month"], "reports": row["total"],
                       "share_pct": _pct(row["total"], reports),
                       "top_source": top_src, "top_source_reports": top_n,
                       "top_ecosystem": max(row["by_ecosystem"].items(),
                                            key=lambda kv: kv[1])[0]})

    src_totals: dict[str, int] = {}
    for per in sources_by_month.values():
        for src, n in per.items():
            src_totals[src] = src_totals.get(src, 0) + n
    sources = [{"source": s, "reports": n}
               for s, n in sorted(src_totals.items(),
                                  key=lambda kv: (-kv[1], kv[0]))]

    return {
        "generated_at": generated_at,
        "as_of": generated_at[:10],
        "ecosystems_read": sorted(e for e in summaries
                                  if e in MAL_ECOSYSTEMS),
        "catalog": {
            "reports": reports,
            "withdrawn": withdrawn,
            "withdrawn_pct": _pct(withdrawn, reports),
            "ecosystems": len(eco_rows),
            "first_month": month_rows[0]["month"] if month_rows else None,
            "last_month": month_rows[-1]["month"] if month_rows else None,
            "peak_month": peak["month"] if peak else None,
            "peak_reports": peak["total"] if peak else 0,
            "peak_share_pct": _pct(peak["total"], reports) if peak else None,
            "median_month": median_month,
            "median_window": ([window[0]["month"], window[-1]["month"]]
                              if window else None),
            "this_year": year_rows[-1]["total"]
            if year_rows and year_rows[-1]["year"] == gen_year else 0,
        },
        "ecosystems": eco_rows,
        "months": month_rows,
        "years": year_rows,
        "bursts": bursts,
        "sources": sources,
    }


# ---- stage ----------------------------------------------------------------------

def _source(generated_at: str, gap: dict, mal: dict, stats: dict) -> dict:
    return {"fetched_at": generated_at,
            "ghsa_advisories": gap["catalog"]["advisories"],
            "mal_reports": mal["catalog"]["reports"],
            **stats}


def run_stage(cache_dir: Path, generated_at: str, *, offline_fixtures: bool,
              session=None, log: Callable[[str], None] = print
              ) -> tuple[dict, dict, dict]:
    """(advisory_gap.json, registry_malware.json, meta.sources.osv).

    Raises ``OSError`` / ``ValueError`` on an upstream failure; the caller
    carries both modules forward (one upstream, two modules)."""
    from .fetch_osv import fetch_all, load_fixture_dir, summary_stats

    if offline_fixtures:
        summaries = load_fixture_dir(FIXTURES_DIR)
    else:
        log("fetching OSV ecosystem exports (GHSA + MAL) ...")
        summaries = fetch_all(cache_dir, session=session, log=log)
    gap = build_advisory_gap(summaries, generated_at)
    mal = build_registry_malware(summaries, generated_at)
    return gap, mal, _source(generated_at, gap, mal, summary_stats(summaries))
