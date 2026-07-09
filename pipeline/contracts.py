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
    for k in ("pct_high_critical_latest", "pct_high_critical_decade_ago"):
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


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "meta.json": _validate_meta,
    "severity_inflation.json": _validate_severity_inflation,
    "nine_eight_flood.json": _validate_nine_eight_flood,
    "score_vs_reality.json": _validate_score_vs_reality,
    "nvd_decay.json": _validate_nvd_decay,
    "cna_leaderboard.json": _validate_cna_leaderboard,
    "volume_curve.json": _validate_volume_curve,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the contract for ``filename``.

    Raises :class:`ContractViolation` on any mismatch, ``KeyError`` if the
    filename has no contract (an output file we never agreed to emit).
    """
    VALIDATORS[filename](obj)
