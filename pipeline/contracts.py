"""Output contracts from docs/data-contracts.md, encoded as validators.

Single source of truth for the pipeline -> site JSON shapes. The pipeline
MUST call :func:`validate` on every output object before writing it and
fail loudly (``ContractViolation``) on any mismatch.

Validators are hand-rolled (stdlib only, no jsonschema dependency). They
check: required keys, types, numeric ranges, 1-decimal rounding of floats,
sort order of series, bucket enumerations, and grid-cell completeness.
Unknown extra keys are tolerated (the site reads only the contracted keys),
with one documented exception: ``meta.json`` ``sources.nvd`` is optional so
that ``--skip-nvd`` runs with no prior NVD data can still emit a truthful
meta file.
"""
from __future__ import annotations

import re
from typing import Any, Callable

ISO_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

CVSS_BUCKETS = ["0.1-3.9", "4.0-6.9", "7.0-8.9", "9.0-10.0"]
EPSS_BUCKETS = ["<0.1%", "0.1-1%", "1-10%", ">10%"]
SEVERITY_KEYS = ["critical", "high", "medium", "low", "unscored"]


class ContractViolation(ValueError):
    """An output object does not match its data contract."""


def _fail(path: str, msg: str) -> None:
    raise ContractViolation(f"{path}: {msg}")


def _get(obj: Any, key: str, path: str) -> Any:
    if not isinstance(obj, dict):
        _fail(path, f"expected object, got {type(obj).__name__}")
    if key not in obj:
        _fail(path, f"missing required key {key!r}")
    return obj[key]


def _check_str(v: Any, path: str, pattern: re.Pattern[str] | None = None) -> None:
    if not isinstance(v, str) or not v:
        _fail(path, f"expected non-empty string, got {v!r}")
    if pattern is not None and not pattern.match(v):
        _fail(path, f"string {v!r} does not match required format")


def _check_bool(v: Any, path: str) -> None:
    if not isinstance(v, bool):
        _fail(path, f"expected boolean, got {v!r}")


def _check_int(v: Any, path: str, minimum: int = 0) -> None:
    if isinstance(v, bool) or not isinstance(v, int):
        _fail(path, f"expected integer, got {v!r}")
    if v < minimum:
        _fail(path, f"integer {v} below minimum {minimum}")


def _check_num(v: Any, path: str, lo: float, hi: float) -> None:
    """A float in [lo, hi], rounded to at most 1 decimal place."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        _fail(path, f"expected number, got {v!r}")
    if not lo <= v <= hi:
        _fail(path, f"number {v} outside range [{lo}, {hi}]")
    if abs(v * 10 - round(v * 10)) > 1e-6:
        _fail(path, f"number {v} not rounded to 1 decimal place")


def _check_list(v: Any, path: str) -> list:
    if not isinstance(v, list):
        _fail(path, f"expected array, got {type(v).__name__}")
    return v


def _check_sorted(values: list, path: str, *, descending: bool = False) -> None:
    ordered = all(b <= a for a, b in zip(values, values[1:])) if descending \
        else all(a <= b for a, b in zip(values, values[1:]))
    if not ordered:
        _fail(path, f"not sorted {'descending' if descending else 'ascending'}")


def _check_generated_at(obj: Any, path: str) -> None:
    _check_str(_get(obj, "generated_at", path), f"{path}.generated_at", ISO_UTC_RE)


def _check_pace_projection(proj: Any, path: str, generated_at: str,
                           count_keys: dict[str, int]) -> None:
    """Optional full-year pace projection block (flow metrics only —
    docs/data-contracts.md, "Pace projections"). ``count_keys`` maps each
    projected-count key to its minimum legal value. Checks: year equals the
    generated_at year (a projection is only ever about the run's partial
    current year), counts are ints at or above their minimum, and
    ``elapsed`` is a fraction in (0, 1] rounded to 3 decimals (the
    documented exception to the 1-decimal float rule)."""
    year = _get(proj, "year", path)
    _check_int(year, f"{path}.year", minimum=1990)
    if year != int(generated_at[:4]):
        _fail(f"{path}.year",
              f"projection year {year} must equal the generated_at year "
              f"{generated_at[:4]} (projections cover only the run's "
              f"partial current year)")
    for key, minimum in count_keys.items():
        _check_int(_get(proj, key, path), f"{path}.{key}", minimum=minimum)
    elapsed = _get(proj, "elapsed", path)
    if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)):
        _fail(f"{path}.elapsed", f"expected number, got {elapsed!r}")
    if not 0.0 < elapsed <= 1.0:
        _fail(f"{path}.elapsed", f"elapsed {elapsed} outside (0, 1]")
    if abs(elapsed * 1000 - round(elapsed * 1000)) > 1e-6:
        _fail(f"{path}.elapsed",
              f"elapsed {elapsed} not rounded to 3 decimal places")


def _check_year_stat(entry: Any, path: str, int_keys: list[str],
                     score_keys: list[str] = (), pct_keys: list[str] = ()) -> int:
    year = _get(entry, "year", path)
    _check_int(year, f"{path}.year", minimum=1990)
    for k in int_keys:
        _check_int(_get(entry, k, path), f"{path}.{k}")
    for k in score_keys:
        _check_num(_get(entry, k, path), f"{path}.{k}", 0.0, 10.0)
    for k in pct_keys:
        _check_num(_get(entry, k, path), f"{path}.{k}", 0.0, 100.0)
    return year


# ---------------------------------------------------------------- meta.json

def _validate_meta(obj: Any) -> None:
    _check_generated_at(obj, "meta")
    _check_bool(_get(obj, "sample", "meta"), "meta.sample")
    src = _get(obj, "sources", "meta")

    cvelist = _get(src, "cvelist", "meta.sources")
    _check_str(_get(cvelist, "release", "meta.sources.cvelist"),
               "meta.sources.cvelist.release")
    _check_int(_get(cvelist, "cve_count", "meta.sources.cvelist"),
               "meta.sources.cvelist.cve_count")

    epss = _get(src, "epss", "meta.sources")
    _check_str(_get(epss, "model_version", "meta.sources.epss"),
               "meta.sources.epss.model_version")
    _check_str(_get(epss, "score_date", "meta.sources.epss"),
               "meta.sources.epss.score_date", DATE_RE)
    _check_int(_get(epss, "row_count", "meta.sources.epss"),
               "meta.sources.epss.row_count")

    kev = _get(src, "kev", "meta.sources")
    _check_str(_get(kev, "catalog_version", "meta.sources.kev"),
               "meta.sources.kev.catalog_version")
    _check_int(_get(kev, "count", "meta.sources.kev"), "meta.sources.kev.count")

    # Optional (documented deviation): absent when --skip-nvd had no prior data.
    if "nvd" in src:
        _check_str(_get(src["nvd"], "fetched_at", "meta.sources.nvd"),
                   "meta.sources.nvd.fetched_at", ISO_UTC_RE)
        # Additive: transitions counted by today's throughput diff. Absent
        # on carry-forward runs and on runs with no prior state to diff.
        if "throughput_events" in src["nvd"]:
            _check_int(src["nvd"]["throughput_events"],
                       "meta.sources.nvd.throughput_events")

    # Optional for the same reason (--skip-attack with no prior data).
    if "attack" in src:
        _check_str(_get(src["attack"], "fetched_at", "meta.sources.attack"),
                   "meta.sources.attack.fetched_at", ISO_UTC_RE)
        _check_str(_get(src["attack"], "latest_version",
                        "meta.sources.attack"),
                   "meta.sources.attack.latest_version")
        _check_int(_get(src["attack"], "version_count",
                        "meta.sources.attack"),
                   "meta.sources.attack.version_count", minimum=1)
    # Optional additively (older committed meta files predate the module);
    # the hygiene stage itself always emits it.
    if "apnic" in src:
        _check_str(_get(src["apnic"], "fetched_at", "meta.sources.apnic"),
                   "meta.sources.apnic.fetched_at", ISO_UTC_RE)
        _check_int(_get(src["apnic"], "economy_count", "meta.sources.apnic"),
                   "meta.sources.apnic.economy_count")
        _check_int(_get(src["apnic"], "spread_economy_count",
                        "meta.sources.apnic"),
                   "meta.sources.apnic.spread_economy_count")

    # Optional for the same reason (--skip-market with no prior data).
    if "market" in src:
        _check_str(_get(src["market"], "fetched_at", "meta.sources.market"),
                   "meta.sources.market.fetched_at", ISO_UTC_RE)
        _check_int(_get(src["market"], "term_count", "meta.sources.market"),
                   "meta.sources.market.term_count")
        _check_int(_get(src["market"], "backfill_remaining",
                        "meta.sources.market"),
                   "meta.sources.market.backfill_remaining")

    # Optional so older meta files stay valid; the pipeline always emits it
    # (the HIBP stage has no skip flag — it fails loud instead).
    if "hibp" in src:
        _check_str(_get(src["hibp"], "fetched_at", "meta.sources.hibp"),
                   "meta.sources.hibp.fetched_at", ISO_UTC_RE)
        _check_int(_get(src["hibp"], "breach_count", "meta.sources.hibp"),
                   "meta.sources.hibp.breach_count")
    # Optional for the same reason (--skip-epss-report with no prior data):
    # the historical day-before EPSS lookups behind the EPSS Report Card.
    if "epss_history" in src:
        eh = src["epss_history"]
        _check_str(_get(eh, "fetched_at", "meta.sources.epss_history"),
                   "meta.sources.epss_history.fetched_at", ISO_UTC_RE)
        _check_int(_get(eh, "graded", "meta.sources.epss_history"),
                   "meta.sources.epss_history.graded")
        _check_int(_get(eh, "pending_backfill",
                        "meta.sources.epss_history"),
                   "meta.sources.epss_history.pending_backfill")

    # Optional (additive extension): the Silent Rescores diff stage.
    # ``events_total`` = rows on the committed event log after tonight's
    # append; ``state_release`` = the corpus release recorded in tonight's
    # fingerprint state (the release-skew guard's reference point).
    if "rescores" in src:
        rs = src["rescores"]
        _check_int(_get(rs, "events_total", "meta.sources.rescores"),
                   "meta.sources.rescores.events_total")
        _check_str(_get(rs, "state_release", "meta.sources.rescores"),
                   "meta.sources.rescores.state_release")
    # Optional additively (older committed meta files predate the module);
    # the KEV Changelog stage itself always emits it. last_observed may be
    # empty only in the degenerate no-record-yet case.
    if "kev_changelog" in src:
        kc = src["kev_changelog"]
        _check_str(_get(kc, "fetched_at", "meta.sources.kev_changelog"),
                   "meta.sources.kev_changelog.fetched_at", ISO_UTC_RE)
        _check_int(_get(kc, "events_total", "meta.sources.kev_changelog"),
                   "meta.sources.kev_changelog.events_total")
        last = _get(kc, "last_observed", "meta.sources.kev_changelog")
        if last != "":
            _check_str(last, "meta.sources.kev_changelog.last_observed",
                       DATE_RE)

    # Optional (additive extension, market precedent): the Ransomwhere
    # export behind the Extortion Ledger module. Checked when present.
    if "ransomwhere" in src:
        rw = src["ransomwhere"]
        _check_str(_get(rw, "fetched_at", "meta.sources.ransomwhere"),
                   "meta.sources.ransomwhere.fetched_at", ISO_UTC_RE)
        _check_int(_get(rw, "address_count", "meta.sources.ransomwhere"),
                   "meta.sources.ransomwhere.address_count", minimum=1)
        _check_int(_get(rw, "tx_count", "meta.sources.ransomwhere"),
                   "meta.sources.ransomwhere.tx_count", minimum=1)

    # Optional additively (older committed meta files predate the module);
    # the Threat-actor naming stage itself always emits it.
    if "naming" in src:
        nm = src["naming"]
        _check_str(_get(nm, "fetched_at", "meta.sources.naming"),
                   "meta.sources.naming.fetched_at", ISO_UTC_RE)
        _check_str(_get(nm, "version", "meta.sources.naming"),
                   "meta.sources.naming.version")
        _check_int(_get(nm, "group_count", "meta.sources.naming"),
                   "meta.sources.naming.group_count")

    # Optional additively (older committed meta files predate the module);
    # the CWE Top 25 stage itself always emits it. official_year is the
    # newest committed MITRE list; list_count is how many years are committed.
    if "top25" in src:
        t25 = src["top25"]
        _check_str(_get(t25, "fetched_at", "meta.sources.top25"),
                   "meta.sources.top25.fetched_at", ISO_UTC_RE)
        _check_int(_get(t25, "official_year", "meta.sources.top25"),
                   "meta.sources.top25.official_year", minimum=1999)
        _check_int(_get(t25, "list_count", "meta.sources.top25"),
                   "meta.sources.top25.list_count", minimum=1)
    # the Vulnrichment handoff stage emits it from the same corpus pass (no
    # separate fetch — fetched_at is the run's generation time).
    if "adp" in src:
        adp = src["adp"]
        _check_str(_get(adp, "fetched_at", "meta.sources.adp"),
                   "meta.sources.adp.fetched_at", ISO_UTC_RE)
        _check_int(_get(adp, "cisa_records", "meta.sources.adp"),
                   "meta.sources.adp.cisa_records")
    # the EPSS Volatility stage itself always emits it. score_date = the
    # EPSS snapshot recorded in tonight's committed fingerprint state (the
    # same-snapshot guard's reference point); days_observed = rows on the
    # committed daily log after tonight's diff.
    if "epssvol" in src:
        ev = src["epssvol"]
        _check_str(_get(ev, "score_date", "meta.sources.epssvol"),
                   "meta.sources.epssvol.score_date", DATE_RE)
        _check_int(_get(ev, "days_observed", "meta.sources.epssvol"),
                   "meta.sources.epssvol.days_observed")
    # the CNA Roster History stage itself always emits it. ``events_total`` =
    # rows on the committed churn log after tonight's append.
    if "roster" in src:
        rt = src["roster"]
        _check_str(_get(rt, "fetched_at", "meta.sources.roster"),
                   "meta.sources.roster.fetched_at", ISO_UTC_RE)
        _check_int(_get(rt, "org_count", "meta.sources.roster"),
                   "meta.sources.roster.org_count", minimum=1)
        _check_int(_get(rt, "events_total", "meta.sources.roster"),
                   "meta.sources.roster.events_total")


# -------------------------------------------------- severity_inflation.json

def _validate_severity_inflation(obj: Any) -> None:
    _check_generated_at(obj, "severity_inflation")
    series = _get(obj, "series", "severity_inflation")
    for version in ("v2", "v3", "v4"):
        entries = _check_list(_get(series, version, "severity_inflation.series"),
                              f"severity_inflation.series.{version}")
        years = [_check_year_stat(e, f"severity_inflation.series.{version}[{i}]",
                                  ["n"], score_keys=["median", "p25", "p75"])
                 for i, e in enumerate(entries)]
        _check_sorted(years, f"severity_inflation.series.{version}")

    blended = _check_list(_get(obj, "blended", "severity_inflation"),
                          "severity_inflation.blended")
    years = [_check_year_stat(e, f"severity_inflation.blended[{i}]", ["n"],
                              score_keys=["median"], pct_keys=["pct_high_critical"])
             for i, e in enumerate(blended)]
    _check_sorted(years, "severity_inflation.blended")

    annotations = _check_list(_get(obj, "annotations", "severity_inflation"),
                              "severity_inflation.annotations")
    for i, a in enumerate(annotations):
        path = f"severity_inflation.annotations[{i}]"
        _check_int(_get(a, "year", path), f"{path}.year", minimum=1990)
        _check_str(_get(a, "label", path), f"{path}.label")

    headline = _get(obj, "headline", "severity_inflation")
    _check_int(_get(headline, "latest_year", "severity_inflation.headline"),
               "severity_inflation.headline.latest_year", minimum=1990)
    _check_int(_get(headline, "baseline_year", "severity_inflation.headline"),
               "severity_inflation.headline.baseline_year", minimum=1990)
    for k in ("pct_high_critical_latest", "pct_high_critical_baseline"):
        _check_num(_get(headline, k, "severity_inflation.headline"),
                   f"severity_inflation.headline.{k}", 0.0, 100.0)


# ---------------------------------------------------- nine_eight_flood.json

def _validate_nine_eight_flood(obj: Any) -> None:
    _check_generated_at(obj, "nine_eight_flood")
    entries = _check_list(_get(obj, "years", "nine_eight_flood"),
                          "nine_eight_flood.years")
    years = [_check_year_stat(e, f"nine_eight_flood.years[{i}]", SEVERITY_KEYS)
             for i, e in enumerate(entries)]
    _check_sorted(years, "nine_eight_flood.years")

    # Optional: full-year pace projection of the current year's total.
    if "projection" in obj:
        _check_pace_projection(obj["projection"], "nine_eight_flood.projection",
                               obj["generated_at"], {"total": 1})

    # Optional: the in-record scoring era marker — the first year in which
    # scores embedded in the CVE record stop being a rounding error. Absent
    # when no charted year clears the threshold (tiny fixture corpora).
    if "record_era" in obj:
        era = obj["record_era"]
        year = _get(era, "year", "nine_eight_flood.record_era")
        _check_int(year, "nine_eight_flood.record_era.year", minimum=1999)
        if year not in years:
            _fail("nine_eight_flood.record_era.year",
                  "must be one of the charted years")
        share = _get(era, "min_share", "nine_eight_flood.record_era")
        if not isinstance(share, float) or not 0.0 < share < 1.0:
            _fail("nine_eight_flood.record_era.min_share",
                  "must be a float in (0, 1)")


# ---------------------------------------------------- score_vs_reality.json

def _validate_score_vs_reality(obj: Any) -> None:
    _check_generated_at(obj, "score_vs_reality")
    if _get(obj, "cvss_buckets", "score_vs_reality") != CVSS_BUCKETS:
        _fail("score_vs_reality.cvss_buckets", f"must equal {CVSS_BUCKETS}")
    if _get(obj, "epss_buckets", "score_vs_reality") != EPSS_BUCKETS:
        _fail("score_vs_reality.epss_buckets", f"must equal {EPSS_BUCKETS}")

    grid = _check_list(_get(obj, "grid", "score_vs_reality"), "score_vs_reality.grid")
    seen: set[tuple[str, str]] = set()
    for i, cell in enumerate(grid):
        path = f"score_vs_reality.grid[{i}]"
        cb = _get(cell, "cvss_bucket", path)
        eb = _get(cell, "epss_bucket", path)
        if cb not in CVSS_BUCKETS:
            _fail(f"{path}.cvss_bucket", f"unknown bucket {cb!r}")
        if eb not in EPSS_BUCKETS:
            _fail(f"{path}.epss_bucket", f"unknown bucket {eb!r}")
        if (cb, eb) in seen:
            _fail(path, f"duplicate cell ({cb!r}, {eb!r})")
        seen.add((cb, eb))
        _check_int(_get(cell, "n", path), f"{path}.n")
    missing = {(c, e) for c in CVSS_BUCKETS for e in EPSS_BUCKETS} - seen
    if missing:
        _fail("score_vs_reality.grid", f"missing cells: {sorted(missing)}")

    headline = _get(obj, "headline", "score_vs_reality")
    _check_num(_get(headline, "pct_critical_epss_below_1pct", "score_vs_reality.headline"),
               "score_vs_reality.headline.pct_critical_epss_below_1pct", 0.0, 100.0)
    _check_int(_get(headline, "n_critical_with_epss", "score_vs_reality.headline"),
               "score_vs_reality.headline.n_critical_with_epss")

    kev = _get(obj, "kev", "score_vs_reality")
    _check_int(_get(kev, "total", "score_vs_reality.kev"), "score_vs_reality.kev.total")
    _check_int(_get(kev, "below_high", "score_vs_reality.kev"),
               "score_vs_reality.kev.below_high")
    _check_num(_get(kev, "pct_below_high", "score_vs_reality.kev"),
               "score_vs_reality.kev.pct_below_high", 0.0, 100.0)
    dist = _check_list(_get(kev, "cvss_distribution", "score_vs_reality.kev"),
                       "score_vs_reality.kev.cvss_distribution")
    for i, d in enumerate(dist):
        path = f"score_vs_reality.kev.cvss_distribution[{i}]"
        if _get(d, "bucket", path) not in CVSS_BUCKETS:
            _fail(f"{path}.bucket", f"unknown bucket {d['bucket']!r}")
        _check_int(_get(d, "n", path), f"{path}.n")


# ----------------------------------------------------------- nvd_decay.json

def _validate_nvd_decay(obj: Any) -> None:
    _check_generated_at(obj, "nvd_decay")
    current = _get(obj, "current", "nvd_decay")
    statuses = _check_list(_get(current, "statuses", "nvd_decay.current"),
                           "nvd_decay.current.statuses")
    for i, s in enumerate(statuses):
        path = f"nvd_decay.current.statuses[{i}]"
        _check_str(_get(s, "status", path), f"{path}.status")
        _check_int(_get(s, "n", path), f"{path}.n")
    _check_int(_get(current, "backlog_total", "nvd_decay.current"),
               "nvd_decay.current.backlog_total")

    history = _check_list(_get(obj, "history", "nvd_decay"), "nvd_decay.history")
    dates = []
    for i, h in enumerate(history):
        path = f"nvd_decay.history[{i}]"
        date = _get(h, "date", path)
        _check_str(date, f"{path}.date", DATE_RE)
        _check_int(_get(h, "backlog_total", path), f"{path}.backlog_total")
        _check_int(_get(h, "awaiting_analysis", path), f"{path}.awaiting_analysis")
        dates.append(date)
    _check_sorted(dates, "nvd_decay.history")
    if len(set(dates)) != len(dates):
        _fail("nvd_decay.history", "duplicate dates (one row per run date)")


# ------------------------------------------------------ nvd_throughput.json

def _validate_nvd_throughput(obj: Any) -> None:
    _check_generated_at(obj, "nvd_throughput")
    _check_int(_get(obj, "min_known_duration", "nvd_throughput"),
               "nvd_throughput.min_known_duration", minimum=1)

    queue = _get(obj, "queue", "nvd_throughput")
    n_known = _get(queue, "n_known_duration", "nvd_throughput.queue")
    _check_int(n_known, "nvd_throughput.queue.n_known_duration")
    median = _get(queue, "median_days", "nvd_throughput.queue")
    if median is not None:
        _check_num(median, "nvd_throughput.queue.median_days", 0.0, 100000.0)
    # The threshold is a promise: no median publishes on a small sample.
    if median is not None and n_known < obj["min_known_duration"]:
        _fail("nvd_throughput.queue.median_days",
              f"median published with only {n_known} known durations "
              f"(threshold {obj['min_known_duration']})")

    history = _check_list(_get(obj, "history", "nvd_throughput"),
                          "nvd_throughput.history")
    dates = []
    for i, h in enumerate(history):
        path = f"nvd_throughput.history[{i}]"
        date = _get(h, "date", path)
        _check_str(date, f"{path}.date", DATE_RE)
        for k in ("received_new", "entered_awaiting",
                  "analyzed_from_awaiting", "deferred_from_awaiting"):
            _check_int(_get(h, k, path), f"{path}.{k}")
        _check_bool(_get(h, "resweep", path), f"{path}.resweep")
        dates.append(date)
    _check_sorted(dates, "nvd_throughput.history")
    if len(set(dates)) != len(dates):
        _fail("nvd_throughput.history",
              "duplicate dates (one row per run date)")


# ----------------------------------------------------- cna_leaderboard.json

def _validate_cna_leaderboard(obj: Any) -> None:
    _check_generated_at(obj, "cna_leaderboard")
    _check_int(_get(obj, "window_years", "cna_leaderboard"),
               "cna_leaderboard.window_years", minimum=1)
    _check_int(_get(obj, "min_cves", "cna_leaderboard"),
               "cna_leaderboard.min_cves", minimum=1)
    cnas = _check_list(_get(obj, "cnas", "cna_leaderboard"), "cna_leaderboard.cnas")
    pcts = []
    for i, c in enumerate(cnas):
        path = f"cna_leaderboard.cnas[{i}]"
        _check_str(_get(c, "cna", path), f"{path}.cna")
        _check_str(_get(c, "org", path), f"{path}.org")
        _check_int(_get(c, "n", path), f"{path}.n")
        _check_num(_get(c, "avg_cvss", path), f"{path}.avg_cvss", 0.0, 10.0)
        _check_num(_get(c, "median_cvss", path), f"{path}.median_cvss", 0.0, 10.0)
        _check_num(_get(c, "pct_geq_9", path), f"{path}.pct_geq_9", 0.0, 100.0)
        _check_num(_get(c, "pct_geq_7", path), f"{path}.pct_geq_7", 0.0, 100.0)
        pcts.append(c["pct_geq_9"])
    _check_sorted(pcts, "cna_leaderboard.cnas (by pct_geq_9)", descending=True)


# -------------------------------------------------------- volume_curve.json

def _validate_volume_curve(obj: Any) -> None:
    _check_generated_at(obj, "volume_curve")
    entries = _check_list(_get(obj, "years", "volume_curve"), "volume_curve.years")
    years = [_check_year_stat(e, f"volume_curve.years[{i}]", ["published", "rejected"])
             for i, e in enumerate(entries)]
    _check_sorted(years, "volume_curve.years")

    # Optional: full-year pace projection for the current year. Keyed off
    # the published flow, so published >= 1; rejections may pace to 0.
    if "projection" in obj:
        _check_pace_projection(obj["projection"], "volume_curve.projection",
                               obj["generated_at"],
                               {"published": 1, "rejected": 0})


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "meta.json": _validate_meta,
    "severity_inflation.json": _validate_severity_inflation,
    "nine_eight_flood.json": _validate_nine_eight_flood,
    "score_vs_reality.json": _validate_score_vs_reality,
    "nvd_decay.json": _validate_nvd_decay,
    "nvd_throughput.json": _validate_nvd_throughput,
    "cna_leaderboard.json": _validate_cna_leaderboard,
    "volume_curve.json": _validate_volume_curve,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the contract for ``filename``.

    Raises :class:`ContractViolation` on any mismatch, ``KeyError`` if the
    filename has no contract (an output file we never agreed to emit).
    """
    VALIDATORS[filename](obj)


# Module contracts register themselves here. Imported at the bottom on
# purpose: market_contracts reuses this module's private helpers at import
# time, so it must load only after they are all defined.
from . import market_contracts  # noqa: E402

VALIDATORS.update(market_contracts.VALIDATORS)

from . import tier1_contracts  # noqa: E402

VALIDATORS.update(tier1_contracts.VALIDATORS)

from . import tier2_contracts  # noqa: E402

VALIDATORS.update(tier2_contracts.VALIDATORS)

from . import breach_contracts  # noqa: E402

VALIDATORS.update(breach_contracts.VALIDATORS)
from . import extortion_contracts  # noqa: E402

VALIDATORS.update(extortion_contracts.VALIDATORS)
from . import attack_contracts  # noqa: E402

VALIDATORS.update(attack_contracts.VALIDATORS)
from . import hygiene_contracts  # noqa: E402

VALIDATORS.update(hygiene_contracts.VALIDATORS)
from . import guards_contracts  # noqa: E402

VALIDATORS.update(guards_contracts.VALIDATORS)
from . import epss_report_contracts  # noqa: E402

VALIDATORS.update(epss_report_contracts.VALIDATORS)
from . import calendar_contracts  # noqa: E402

VALIDATORS.update(calendar_contracts.VALIDATORS)
from . import rescore_contracts  # noqa: E402

VALIDATORS.update(rescore_contracts.VALIDATORS)
from . import kev_changelog_contracts  # noqa: E402

VALIDATORS.update(kev_changelog_contracts.VALIDATORS)
from . import naming_contracts  # noqa: E402

VALIDATORS.update(naming_contracts.VALIDATORS)
from . import top25_contracts  # noqa: E402

VALIDATORS.update(top25_contracts.VALIDATORS)
from . import adp_contracts  # noqa: E402

VALIDATORS.update(adp_contracts.VALIDATORS)
from . import epssvol_contracts  # noqa: E402

VALIDATORS.update(epssvol_contracts.VALIDATORS)
from . import roster_contracts  # noqa: E402

VALIDATORS.update(roster_contracts.VALIDATORS)
