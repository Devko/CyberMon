"""Contract for the Time-to-PoC output (time_to_poc.json).

Hand-rolled stdlib validator, own module (the epssvol_contracts /
roster_contracts precedent), merged into pipeline/contracts.py's dispatch.

Module-specific rules beyond the shared helpers:

* the hero's gap medians may legitimately be NEGATIVE (a PoC predating
  the CVE record is kept as signal), so they are range-checked as plain
  bounded numbers, not through ``_check_year_stat``'s score keys;
* internal arithmetic is enforced: preempted counts can never exceed the
  matched counts they are drawn from, coverage ``with_poc`` can never
  exceed ``total``, and the catalog's dated/union counts must nest —
  a violation means the builder or a source parse broke, and publishing
  it would chart an impossibility.
"""
from __future__ import annotations

from typing import Any, Callable

from .contracts import (CVSS_BUCKETS, _check_generated_at, _check_int,
                        _check_list, _check_num, _check_sorted, _check_str,
                        _fail, _get)

# Widest plausible publication->PoC gap in days, either direction (the
# corpus spans ~40 years; a gap outside this window is corrupt data).
_GAP_LIMIT = 20000.0


def _check_share(obj: Any, path: str) -> None:
    with_poc = _get(obj, "with_poc_date", path)
    preempted = _get(obj, "preempted", path)
    _check_int(with_poc, f"{path}.with_poc_date")
    _check_int(preempted, f"{path}.preempted")
    if preempted > with_poc:
        _fail(f"{path}.preempted",
              f"preempted ({preempted}) exceeds with_poc_date ({with_poc})")
    _check_num(_get(obj, "pct_preempted", path),
               f"{path}.pct_preempted", 0.0, 100.0)


def _check_coverage_row(obj: Any, path: str) -> None:
    total = _get(obj, "total", path)
    with_poc = _get(obj, "with_poc", path)
    _check_int(total, f"{path}.total")
    _check_int(with_poc, f"{path}.with_poc")
    if with_poc > total:
        _fail(f"{path}.with_poc",
              f"with_poc ({with_poc}) exceeds total ({total})")
    _check_num(_get(obj, "pct", path), f"{path}.pct", 0.0, 100.0)


def _validate_time_to_poc(obj: Any) -> None:
    _check_generated_at(obj, "time_to_poc")

    # ---- hero -------------------------------------------------------------
    hero = _get(obj, "hero", "time_to_poc")
    matched = _get(hero, "matched", "time_to_poc.hero")
    dated = _get(matched, "dated_cves", "time_to_poc.hero.matched")
    m = _get(matched, "matched_cves", "time_to_poc.hero.matched")
    um = _get(matched, "unmatched_cves", "time_to_poc.hero.matched")
    for key, v in (("dated_cves", dated), ("matched_cves", m),
                   ("unmatched_cves", um)):
        _check_int(v, f"time_to_poc.hero.matched.{key}")
    if m + um != dated:
        _fail("time_to_poc.hero.matched",
              f"matched_cves ({m}) + unmatched_cves ({um}) must equal "
              f"dated_cves ({dated})")

    years = _check_list(_get(hero, "years", "time_to_poc.hero"),
                        "time_to_poc.hero.years")
    seen_years = []
    for i, row in enumerate(years):
        path = f"time_to_poc.hero.years[{i}]"
        year = _get(row, "year", path)
        _check_int(year, f"{path}.year", minimum=1988)
        seen_years.append(year)
        _check_int(_get(row, "n", path), f"{path}.n", minimum=1)
        for key in ("median_days", "p25_days", "p75_days"):
            _check_num(_get(row, key, path), f"{path}.{key}",
                       -_GAP_LIMIT, _GAP_LIMIT)
        if not row["p25_days"] <= row["median_days"] <= row["p75_days"]:
            _fail(path, "p25_days <= median_days <= p75_days violated")
        for key in ("pct_negative", "pct_within_week"):
            _check_num(_get(row, key, path), f"{path}.{key}", 0.0, 100.0)
    _check_sorted(seen_years, "time_to_poc.hero.years")
    if len(set(seen_years)) != len(seen_years):
        _fail("time_to_poc.hero.years", "duplicate years")

    headline = _get(hero, "headline", "time_to_poc.hero")
    _check_int(_get(headline, "latest_year", "time_to_poc.hero.headline"),
               "time_to_poc.hero.headline.latest_year")
    _check_int(_get(headline, "baseline_year", "time_to_poc.hero.headline"),
               "time_to_poc.hero.headline.baseline_year")
    for key in ("median_days_latest", "median_days_baseline"):
        _check_num(_get(headline, key, "time_to_poc.hero.headline"),
                   f"time_to_poc.hero.headline.{key}",
                   -_GAP_LIMIT, _GAP_LIMIT)
    _check_num(_get(headline, "pct_negative_latest",
                    "time_to_poc.hero.headline"),
               "time_to_poc.hero.headline.pct_negative_latest", 0.0, 100.0)

    # ---- kev_preempt ------------------------------------------------------
    kp = _get(obj, "kev_preempt", "time_to_poc")
    _check_str(_get(kp, "cutoff", "time_to_poc.kev_preempt"),
               "time_to_poc.kev_preempt.cutoff")
    _check_int(_get(kp, "total_kev", "time_to_poc.kev_preempt"),
               "time_to_poc.kev_preempt.total_kev")
    _check_share(_get(kp, "trend", "time_to_poc.kev_preempt"),
                 "time_to_poc.kev_preempt.trend")
    _check_share(_get(kp, "seeding", "time_to_poc.kev_preempt"),
                 "time_to_poc.kev_preempt.seeding")
    rows = _check_list(_get(kp, "years", "time_to_poc.kev_preempt"),
                       "time_to_poc.kev_preempt.years")
    kp_years = []
    for i, row in enumerate(rows):
        path = f"time_to_poc.kev_preempt.years[{i}]"
        year = _get(row, "year", path)
        _check_int(year, f"{path}.year", minimum=1990)
        kp_years.append(year)
        total_added = _get(row, "total_added", path)
        _check_int(total_added, f"{path}.total_added", minimum=1)
        _check_share(row, path)
        if row["with_poc_date"] > total_added:
            _fail(f"{path}.with_poc_date",
                  f"with_poc_date ({row['with_poc_date']}) exceeds "
                  f"total_added ({total_added})")
    _check_sorted(kp_years, "time_to_poc.kev_preempt.years")
    if len(set(kp_years)) != len(kp_years):
        _fail("time_to_poc.kev_preempt.years", "duplicate years")

    # ---- coverage ---------------------------------------------------------
    cov = _get(obj, "coverage", "time_to_poc")
    _check_int(_get(cov, "window_year", "time_to_poc.coverage"),
               "time_to_poc.coverage.window_year", minimum=1990)
    buckets = _check_list(_get(cov, "buckets", "time_to_poc.coverage"),
                          "time_to_poc.coverage.buckets")
    labels = []
    for i, row in enumerate(buckets):
        path = f"time_to_poc.coverage.buckets[{i}]"
        bucket = _get(row, "bucket", path)
        if bucket not in CVSS_BUCKETS:
            _fail(f"{path}.bucket", f"unknown bucket {bucket!r}")
        labels.append(bucket)
        _check_coverage_row(row, path)
    # Buckets appear in ascending-severity chart order, no duplicates
    # (min_n may drop some, so a subset is legal — the order is not).
    if labels != [b for b in CVSS_BUCKETS if b in set(labels)]:
        _fail("time_to_poc.coverage.buckets",
              f"buckets must follow the {CVSS_BUCKETS} order without "
              f"duplicates, got {labels}")
    _check_coverage_row(_get(cov, "unscored", "time_to_poc.coverage"),
                        "time_to_poc.coverage.unscored")

    # ---- catalog ----------------------------------------------------------
    cat = _get(obj, "catalog", "time_to_poc")
    edb = _get(cat, "exploitdb", "time_to_poc.catalog")
    for key in ("entries", "with_cve", "cves", "dated_cves"):
        _check_int(_get(edb, key, "time_to_poc.catalog.exploitdb"),
                   f"time_to_poc.catalog.exploitdb.{key}")
    if edb["with_cve"] > edb["entries"]:
        _fail("time_to_poc.catalog.exploitdb.with_cve",
              "cannot exceed entries")
    if edb["dated_cves"] > edb["cves"]:
        _fail("time_to_poc.catalog.exploitdb.dated_cves",
              "cannot exceed cves (dating is a subset of coverage)")
    msf = _get(cat, "metasploit", "time_to_poc.catalog")
    for key in ("modules", "with_cve", "cves", "dated_cves"):
        _check_int(_get(msf, key, "time_to_poc.catalog.metasploit"),
                   f"time_to_poc.catalog.metasploit.{key}")
    if msf["with_cve"] > msf["modules"]:
        _fail("time_to_poc.catalog.metasploit.with_cve",
              "cannot exceed modules")
    if msf["dated_cves"] > msf["cves"]:
        _fail("time_to_poc.catalog.metasploit.dated_cves",
              "cannot exceed cves (dating is a subset of coverage)")
    nuc = _get(cat, "nuclei", "time_to_poc.catalog")
    for key in ("templates", "cves"):
        _check_int(_get(nuc, key, "time_to_poc.catalog.nuclei"),
                   f"time_to_poc.catalog.nuclei.{key}")
    union = _get(cat, "union_cves", "time_to_poc.catalog")
    dated_cat = _get(cat, "dated_cves", "time_to_poc.catalog")
    matched_corpus = _get(cat, "matched_in_corpus", "time_to_poc.catalog")
    _check_int(union, "time_to_poc.catalog.union_cves")
    _check_int(dated_cat, "time_to_poc.catalog.dated_cves")
    _check_int(matched_corpus, "time_to_poc.catalog.matched_in_corpus")
    if dated_cat > union:
        _fail("time_to_poc.catalog.dated_cves", "cannot exceed union_cves")
    if matched_corpus > union:
        _fail("time_to_poc.catalog.matched_in_corpus",
              "cannot exceed union_cves")
    if dated_cat != dated:
        _fail("time_to_poc.catalog.dated_cves",
              f"must equal hero.matched.dated_cves ({dated}), "
              f"got {dated_cat} (same join, same arithmetic)")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "time_to_poc.json": _validate_time_to_poc,
}
