"""Contract for the EPSS Report Card output (epss_report.json).

Same philosophy as pipeline/contracts.py — hand-rolled stdlib validators
that fail loudly — kept in its own module so the EPSS Report Card stage
lands without touching the core contracts file. The coordinator merges
:data:`VALIDATORS` into the pipeline's dispatch; failures raise the same
:class:`pipeline.contracts.ContractViolation` type.

The core module's private checking helpers are reused read-only.

Load-bearing shape guarantee (docs/data-contracts.md): the per-entry
objects in ``entries[]`` must round-trip losslessly into
``fetch_epss_history``'s sync-state entries — the published file doubles
as the backup of the state cache. Anything this validator lets through
must therefore satisfy ``fetch_epss_history.reconstruct_state``.

Documented float exception: ``epss`` and ``percentile`` in ``entries[]``
are raw 0-1 probabilities at up to FIVE decimals (1-decimal rounding
would crush sub-10% probabilities — the whole point of the module).
Everything aggregated stays on the site's usual 0-100 1-decimal scale.
"""
from __future__ import annotations

import re
from datetime import date, timedelta
from typing import Any, Callable

from .contracts import (DATE_RE, EPSS_BUCKETS, _check_bool,
                        _check_generated_at, _check_int, _check_list,
                        _check_num, _check_sorted, _check_str, _fail, _get)
from .fetch_epss_history import MODEL_LABELS, REASONS

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
PERCENTILE_BUCKETS = ["0-25", "25-50", "50-75", "75-90", "90-99", "99-100"]
UNGRADEABLE_KEYS = ("pre_epss", "listed_before_publication",
                    "no_prior_score")


def _check_prob(v: Any, path: str) -> None:
    """A raw probability/percentile: 0-1 float at up to 5 decimals (the
    documented exception to the site's 1-decimal rule)."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        _fail(path, f"expected number, got {v!r}")
    if not 0.0 <= v <= 1.0:
        _fail(path, f"probability {v} outside [0, 1]")
    if abs(v * 1e5 - round(v * 1e5)) > 1e-6:
        _fail(path, f"probability {v} not rounded to 5 decimal places")


def _check_model_eras(eras: Any) -> None:
    path = "epss_report.model_eras"
    entries = _check_list(eras, path)
    if not entries:
        _fail(path, "must list at least one model era")
    froms = []
    for i, era in enumerate(entries):
        p = f"{path}[{i}]"
        label = _get(era, "label", p)
        _check_str(label, f"{p}.label")
        if label not in MODEL_LABELS:
            _fail(f"{p}.label", f"unknown era label {label!r}")
        _check_str(_get(era, "model_version", p), f"{p}.model_version")
        frm = _get(era, "from", p)
        _check_str(frm, f"{p}.from", DATE_RE)
        to = _get(era, "to", p)
        if i + 1 < len(entries):
            _check_str(to, f"{p}.to", DATE_RE)
            if to < frm:
                _fail(f"{p}.to", f"era ends ({to}) before it starts ({frm})")
        elif to is not None:
            _fail(f"{p}.to", "the newest era must be open-ended (null)")
        froms.append(frm)
    _check_sorted(froms, f"{path} (by from-date)")


def _check_grade_year(entry: Any, path: str, min_n: int) -> int:
    year = _get(entry, "year", path)
    _check_int(year, f"{path}.year", minimum=2021)  # KEV launched Nov 2021
    graded = _get(entry, "graded", path)
    _check_int(graded, f"{path}.graded", minimum=min_n)
    parts = ["n_below_1pct", "n_1_to_10pct", "n_above_10pct"]
    for key in parts:
        _check_int(_get(entry, key, path), f"{path}.{key}")
    if sum(entry[key] for key in parts) != graded:
        _fail(path, "band counts do not sum to graded")
    for key in ("pct_below_1pct", "pct_1_to_10pct", "pct_above_10pct"):
        _check_num(_get(entry, key, path), f"{path}.{key}", 0.0, 100.0)
    _check_int(_get(entry, "ungradeable", path), f"{path}.ungradeable")
    _check_int(_get(entry, "pending", path), f"{path}.pending")
    return year


def _check_distribution(dist: Any, graded_total: int) -> None:
    path = "epss_report.distribution"
    if _get(dist, "buckets", path) != EPSS_BUCKETS:
        _fail(f"{path}.buckets", f"must equal {EPSS_BUCKETS}")
    by_model = _check_list(_get(dist, "by_model", path), f"{path}.by_model")
    order = []
    total = 0
    for i, row in enumerate(by_model):
        p = f"{path}.by_model[{i}]"
        model = _get(row, "model", p)
        if model not in MODEL_LABELS:
            _fail(f"{p}.model", f"unknown model label {model!r}")
        order.append(MODEL_LABELS.index(model))
        n = _get(row, "n", p)
        _check_int(n, f"{p}.n", minimum=1)
        counts = _get(row, "counts", p)
        if not isinstance(counts, dict) or \
                sorted(counts) != sorted(EPSS_BUCKETS):
            _fail(f"{p}.counts", f"must carry exactly the buckets "
                                 f"{EPSS_BUCKETS}")
        for bucket in EPSS_BUCKETS:
            _check_int(counts[bucket], f"{p}.counts[{bucket!r}]")
        if sum(counts.values()) != n:
            _fail(f"{p}.counts", "bucket counts do not sum to n")
        total += n
    _check_sorted(order, f"{path}.by_model (by era order)")
    if len(set(order)) != len(order):
        _fail(f"{path}.by_model", "duplicate model eras")
    if total != graded_total:
        _fail(f"{path}.by_model",
              f"per-model n sums to {total}, catalog.graded is "
              f"{graded_total}")


def _check_percentiles(pct: Any, graded_total: int) -> None:
    path = "epss_report.percentiles"
    n = _get(pct, "n", path)
    _check_int(n, f"{path}.n")
    if n > graded_total:
        _fail(f"{path}.n", f"{n} exceeds catalog.graded {graded_total}")
    buckets = _check_list(_get(pct, "buckets", path), f"{path}.buckets")
    labels = []
    total = 0
    for i, row in enumerate(buckets):
        p = f"{path}.buckets[{i}]"
        labels.append(_get(row, "bucket", p))
        nb = _get(row, "n", p)
        _check_int(nb, f"{p}.n")
        _check_num(_get(row, "pct", p), f"{p}.pct", 0.0, 100.0)
        total += nb
    if labels != PERCENTILE_BUCKETS:
        _fail(f"{path}.buckets", f"bucket labels must equal "
                                 f"{PERCENTILE_BUCKETS} in order")
    if total != n:
        _fail(f"{path}.buckets", "bucket counts do not sum to n")
    bottom = _get(pct, "bottom_half", path)
    bn = _get(bottom, "n", f"{path}.bottom_half")
    _check_int(bn, f"{path}.bottom_half.n")
    if bn > n:
        _fail(f"{path}.bottom_half.n", f"{bn} exceeds n {n}")
    _check_num(_get(bottom, "pct", f"{path}.bottom_half"),
               f"{path}.bottom_half.pct", 0.0, 100.0)
    median = _get(pct, "median_percentile", path)
    if n == 0:
        if median is not None:
            _fail(f"{path}.median_percentile", "must be null when n is 0")
    else:
        _check_num(median, f"{path}.median_percentile", 0.0, 100.0)


def _check_entry(entry: Any, path: str) -> tuple[str, str]:
    cve = _get(entry, "cve", path)
    _check_str(cve, f"{path}.cve", CVE_RE)
    added = _get(entry, "date_added", path)
    _check_str(added, f"{path}.date_added", DATE_RE)
    score_date = _get(entry, "score_date", path)
    _check_str(score_date, f"{path}.score_date", DATE_RE)
    try:
        expected = (date.fromisoformat(added)
                    - timedelta(days=1)).isoformat()
    except ValueError:
        _fail(f"{path}.date_added", f"not a real date: {added!r}")
    if score_date != expected:
        _fail(f"{path}.score_date",
              f"{score_date} is not the day before {added}")
    epss = _get(entry, "epss", path)
    percentile = _get(entry, "percentile", path)
    model = _get(entry, "model", path)
    reason = _get(entry, "reason", path)
    if epss is None:
        # The fact "no score existed that day": everything else null,
        # reason set to what was known at fetch time.
        if percentile is not None or model is not None:
            _fail(path, "null epss requires null percentile and model")
        if reason not in REASONS:
            _fail(f"{path}.reason",
                  f"null epss requires a reason in {list(REASONS)}")
    else:
        _check_prob(epss, f"{path}.epss")
        if percentile is not None:  # early feed rows may lack percentile
            _check_prob(percentile, f"{path}.percentile")
        if model not in MODEL_LABELS:
            _fail(f"{path}.model", f"unknown model label {model!r}")
        if reason is not None:
            _fail(f"{path}.reason", "scored entries carry no reason")
    return added, cve


def _check_headline(headline: Any, graded_total: int) -> None:
    path = "epss_report.headline"
    if graded_total == 0:
        if headline is not None:
            _fail(path, "must be null when catalog.graded is 0")
        return
    if headline is None:
        _fail(path, "must be present when catalog.graded is non-zero")
    if _get(headline, "graded", path) != graded_total:
        _fail(f"{path}.graded", "must equal catalog.graded")
    _check_num(_get(headline, "pct_below_1pct", path),
               f"{path}.pct_below_1pct", 0.0, 100.0)
    _check_int(_get(headline, "latest_year", path), f"{path}.latest_year")
    _check_int(_get(headline, "graded_latest", path),
               f"{path}.graded_latest")
    _check_num(_get(headline, "pct_below_1pct_latest", path),
               f"{path}.pct_below_1pct_latest", 0.0, 100.0)


# ----------------------------------------------------------- epss_report.json

def _validate_epss_report(obj: Any) -> None:
    _check_generated_at(obj, "epss_report")
    # Optional: present (and true) only on --skip-epss-report carry-forwards.
    if "stale" in obj:
        _check_bool(obj["stale"], "epss_report.stale")
    min_n = _get(obj, "min_n", "epss_report")
    _check_int(min_n, "epss_report.min_n", minimum=1)

    _check_model_eras(_get(obj, "model_eras", "epss_report"))

    catalog = _get(obj, "catalog", "epss_report")
    total = _get(catalog, "total", "epss_report.catalog")
    _check_int(total, "epss_report.catalog.total")
    graded_total = _get(catalog, "graded", "epss_report.catalog")
    _check_int(graded_total, "epss_report.catalog.graded")
    ungradeable = _get(catalog, "ungradeable", "epss_report.catalog")
    if not isinstance(ungradeable, dict) or \
            sorted(ungradeable) != sorted(UNGRADEABLE_KEYS):
        _fail("epss_report.catalog.ungradeable",
              f"must carry exactly the keys {list(UNGRADEABLE_KEYS)}")
    for key in UNGRADEABLE_KEYS:
        _check_int(ungradeable[key],
                   f"epss_report.catalog.ungradeable.{key}")
    pending = _get(catalog, "pending_backfill", "epss_report.catalog")
    _check_int(pending, "epss_report.catalog.pending_backfill")
    if graded_total + sum(ungradeable.values()) + pending != total:
        _fail("epss_report.catalog",
              "graded + ungradeable + pending_backfill must equal total")

    rows = _check_list(_get(obj, "grade_by_year", "epss_report"),
                       "epss_report.grade_by_year")
    years = [_check_grade_year(r, f"epss_report.grade_by_year[{i}]", min_n)
             for i, r in enumerate(rows)]
    _check_sorted(years, "epss_report.grade_by_year")
    if len(set(years)) != len(years):
        _fail("epss_report.grade_by_year", "duplicate years")

    _check_distribution(_get(obj, "distribution", "epss_report"),
                        graded_total)
    _check_percentiles(_get(obj, "percentiles", "epss_report"),
                       graded_total)
    _check_headline(_get(obj, "headline", "epss_report"), graded_total)

    entries = _check_list(_get(obj, "entries", "epss_report"),
                          "epss_report.entries")
    keys = [_check_entry(e, f"epss_report.entries[{i}]")
            for i, e in enumerate(entries)]
    _check_sorted(keys, "epss_report.entries (by date_added, cve)")
    if len(set(keys)) != len(keys):
        _fail("epss_report.entries", "duplicate (date_added, cve) pairs")
    scored = sum(1 for e in entries if e["epss"] is not None)
    if scored != graded_total:
        _fail("epss_report.entries",
              f"{scored} scored entries but catalog.graded is "
              f"{graded_total}")
    if len(entries) - scored != sum(ungradeable.values()):
        _fail("epss_report.entries",
              "null-score entries must equal the ungradeable total")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "epss_report.json": _validate_epss_report,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the EPSS Report Card contract for
    ``filename``.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no EPSS Report Card contract.
    """
    VALIDATORS[filename](obj)
