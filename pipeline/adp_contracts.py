"""Contract for adp_coverage.json (Vulnrichment / CISA-ADP handoff).

Same philosophy as pipeline/contracts.py — hand-rolled stdlib validators
that fail loudly — kept in its own module so the ADP stage lands without
touching the core contracts file. The coordinator merges :data:`VALIDATORS`
into the pipeline's dispatch; failures raise the same
:class:`pipeline.contracts.ContractViolation` type.

Monthly granularity is new to this codebase: month keys are validated
against a ``"YYYY-MM"`` regex, and the series must be sorted ascending and
unique. The core module's private checking helpers are reused read-only.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .contracts import (_check_bool, _check_generated_at, _check_int,
                        _check_list, _check_num, _check_sorted, _check_str,
                        _fail, _get)

MONTH_RE = re.compile(r"^\d{4}-(?:0[1-9]|1[0-2])$")
ADD_KEYS = ("ssvc", "cvss", "cwe")


def _check_opt_month(v: Any, path: str) -> None:
    """A ``"YYYY-MM"`` string, or null for the absent-data headline fields."""
    if v is None:
        return
    _check_str(v, path, MONTH_RE)


# ----------------------------------------------------------- adp_coverage.json

def _validate_adp_coverage(obj: Any) -> None:
    _check_generated_at(obj, "adp_coverage")
    _check_int(_get(obj, "min_n", "adp_coverage"), "adp_coverage.min_n",
               minimum=1)

    # months = the CISA-ADP enrichment curve, bucketed by the container's own
    # dateUpdated month; each per-field count is bounded by that month's
    # enriched total; ascending and unique.
    months = _check_list(_get(obj, "months", "adp_coverage"),
                         "adp_coverage.months")
    keys = []
    for i, row in enumerate(months):
        path = f"adp_coverage.months[{i}]"
        month = _get(row, "month", path)
        _check_str(month, f"{path}.month", MONTH_RE)
        enriched = _get(row, "enriched", path)
        _check_int(enriched, f"{path}.enriched")
        for k in ("ssvc", "cvss", "cwe", "legacy"):
            _check_int(_get(row, k, path), f"{path}.{k}")
            if row[k] > enriched:
                _fail(f"{path}.{k}",
                      f"{k} {row[k]} exceeds enriched {enriched}")
        _check_bool(_get(row, "backfill", path), f"{path}.backfill")
        keys.append(month)
    _check_sorted(keys, "adp_coverage.months (by month)")
    if len(set(keys)) != len(keys):
        _fail("adp_coverage.months", "duplicate month buckets")

    # adds = SSVC / CVSS / CWE shares over records carrying a CISA-ADP block.
    # Independent (a record can carry all three), each count bounded by total.
    adds = _get(obj, "adds", "adp_coverage")
    total = _get(adds, "total", "adp_coverage.adds")
    _check_int(total, "adp_coverage.adds.total")
    for k in ADD_KEYS:
        _check_int(_get(adds, k, "adp_coverage.adds"), f"adp_coverage.adds.{k}")
        if adds[k] > total:
            _fail(f"adp_coverage.adds.{k}",
                  f"{k} {adds[k]} exceeds total {total}")
        _check_num(_get(adds, f"pct_{k}", "adp_coverage.adds"),
                   f"adp_coverage.adds.pct_{k}", 0.0, 100.0)

    # providers = the sole-enricher board: every ADP publisher by record
    # count, descending.
    providers = _check_list(_get(obj, "providers", "adp_coverage"),
                            "adp_coverage.providers")
    counts = []
    for i, p in enumerate(providers):
        path = f"adp_coverage.providers[{i}]"
        _check_str(_get(p, "provider", path), f"{path}.provider")
        n = _get(p, "n", path)
        _check_int(n, f"{path}.n")
        _check_num(_get(p, "pct", path), f"{path}.pct", 0.0, 100.0)
        counts.append(n)
    _check_sorted(counts, "adp_coverage.providers (by n)", descending=True)

    headline = _get(obj, "headline", "adp_coverage")
    _check_int(_get(headline, "total_published", "adp_coverage.headline"),
               "adp_coverage.headline.total_published")
    _check_int(_get(headline, "total_cisa", "adp_coverage.headline"),
               "adp_coverage.headline.total_cisa")
    if headline["total_cisa"] > headline["total_published"]:
        _fail("adp_coverage.headline.total_cisa",
              "cannot exceed total_published")
    _check_num(_get(headline, "pct_cisa", "adp_coverage.headline"),
               "adp_coverage.headline.pct_cisa", 0.0, 100.0)
    for k in ("first_month", "last_month", "peak_month"):
        _check_opt_month(_get(headline, k, "adp_coverage.headline"),
                         f"adp_coverage.headline.{k}")
    _check_int(_get(headline, "peak_enriched", "adp_coverage.headline"),
               "adp_coverage.headline.peak_enriched")
    sole = _get(headline, "sole_enricher", "adp_coverage.headline")
    if sole is not None:
        _check_str(sole, "adp_coverage.headline.sole_enricher")
    _check_int(_get(headline, "backfill_month_count", "adp_coverage.headline"),
               "adp_coverage.headline.backfill_month_count")
    # adds.total is exactly the CISA-carrier count the headline reports.
    if total != headline["total_cisa"]:
        _fail("adp_coverage.adds.total", "must equal headline.total_cisa")
    # The headline names the board leader; it must agree with providers[0].
    if providers and sole != providers[0]["provider"]:
        _fail("adp_coverage.headline.sole_enricher",
              "must equal providers[0].provider")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "adp_coverage.json": _validate_adp_coverage,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the ADP contract for ``filename``.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no ADP contract.
    """
    VALIDATORS[filename](obj)
