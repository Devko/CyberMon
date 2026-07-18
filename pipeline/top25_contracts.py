"""Contract for the cwe_top25.json output (CWE Top 25 vs reality).

Same philosophy as pipeline/contracts.py — hand-rolled stdlib validators
that fail loudly — kept in its own module so the top25 stage lands without
touching the core contracts file. The coordinator merges :data:`VALIDATORS`
into the pipeline's dispatch; failures raise the same
:class:`pipeline.contracts.ContractViolation` type.

The core module's private checking helpers are reused read-only.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .contracts import (_check_generated_at, _check_int, _check_list,
                        _check_num, _check_sorted, _check_str, _fail, _get)

CWE_ID_RE = re.compile(r"^CWE-\d+$")


# ------------------------------------------------------------ cwe_top25.json

def _validate_cwe_top25(obj: Any) -> None:
    _check_generated_at(obj, "cwe_top25")
    official_year = _get(obj, "official_year", "cwe_top25")
    _check_int(official_year, "cwe_top25.official_year", minimum=1999)

    official_years = _check_list(_get(obj, "official_years", "cwe_top25"),
                                 "cwe_top25.official_years")
    for i, y in enumerate(official_years):
        _check_int(y, f"cwe_top25.official_years[{i}]", minimum=1999)
    _check_sorted(official_years, "cwe_top25.official_years")
    if official_year not in official_years:
        _fail("cwe_top25.official_year",
              "must be one of official_years (the newest committed list)")
    if official_year != max(official_years):
        _fail("cwe_top25.official_year",
              "must equal the newest committed official year")

    window = _get(obj, "window", "cwe_top25")
    start = _get(window, "start", "cwe_top25.window")
    end = _get(window, "end", "cwe_top25.window")
    _check_int(start, "cwe_top25.window.start", minimum=1999)
    _check_int(end, "cwe_top25.window.end", minimum=1999)
    if end < start:
        _fail("cwe_top25.window", f"end {end} before start {start}")
    _check_int(_get(obj, "window_years", "cwe_top25"),
               "cwe_top25.window_years", minimum=1)
    _check_int(_get(obj, "min_n", "cwe_top25"), "cwe_top25.min_n", minimum=1)
    measured_total = _get(obj, "measured_total", "cwe_top25")
    _check_int(measured_total, "cwe_top25.measured_total")
    _check_int(_get(obj, "kev_total", "cwe_top25"), "cwe_top25.kev_total")

    # ranks = the official Top-25, in official rank order (1..N contiguous),
    # each carrying its measured-prevalence rank + counts and KEV count.
    ranks = _check_list(_get(obj, "ranks", "cwe_top25"), "cwe_top25.ranks")
    official_ranks = []
    seen: set[str] = set()
    for i, r in enumerate(ranks):
        path = f"cwe_top25.ranks[{i}]"
        cwe = _get(r, "cwe", path)
        _check_str(cwe, f"{path}.cwe", CWE_ID_RE)
        if cwe in seen:
            _fail(f"{path}.cwe", f"duplicate cwe {cwe!r}")
        seen.add(cwe)
        _check_str(_get(r, "name", path), f"{path}.name")
        orank = _get(r, "official_rank", path)
        _check_int(orank, f"{path}.official_rank", minimum=1)
        official_ranks.append(orank)
        mrank = _get(r, "measured_rank", path)
        if mrank is not None:
            _check_int(mrank, f"{path}.measured_rank", minimum=1)
        n = _get(r, "measured_n", path)
        _check_int(n, f"{path}.measured_n")
        _check_num(_get(r, "measured_share", path), f"{path}.measured_share",
                   0.0, 100.0)
        _check_int(_get(r, "kev_n", path), f"{path}.kev_n")
        # measured_rank is present exactly when the class was observed.
        if (n == 0) != (mrank is None):
            _fail(f"{path}.measured_rank",
                  "must be null iff measured_n is 0")
    _check_sorted(official_ranks, "cwe_top25.ranks (by official_rank)")
    if official_ranks != list(range(1, len(ranks) + 1)):
        _fail("cwe_top25.ranks",
              "official_rank must be 1..N contiguous in order")

    headline = _get(obj, "headline", "cwe_top25")
    if measured_total < obj["min_n"]:
        if headline is not None:
            _fail("cwe_top25.headline",
                  "must be null when measured_total is below min_n")
        return
    if headline is None:
        _fail("cwe_top25.headline",
              "must be present when measured_total reaches min_n")

    _check_int(_get(headline, "official_year", "cwe_top25.headline"),
               "cwe_top25.headline.official_year", minimum=1999)
    _check_int(_get(headline, "window_start", "cwe_top25.headline"),
               "cwe_top25.headline.window_start", minimum=1999)
    _check_int(_get(headline, "window_end", "cwe_top25.headline"),
               "cwe_top25.headline.window_end", minimum=1999)
    for k in ("in_measured_top25", "outside_measured_top25", "in_kev"):
        _check_int(_get(headline, k, "cwe_top25.headline"),
                   f"cwe_top25.headline.{k}")
    _check_num(_get(headline, "kev_coverage_pct", "cwe_top25.headline"),
               "cwe_top25.headline.kev_coverage_pct", 0.0, 100.0)
    _check_str(_get(headline, "official_top_cwe", "cwe_top25.headline"),
               "cwe_top25.headline.official_top_cwe", CWE_ID_RE)
    _check_str(_get(headline, "measured_top_cwe", "cwe_top25.headline"),
               "cwe_top25.headline.measured_top_cwe", CWE_ID_RE)

    # The headline must agree with the ranks it summarizes.
    if headline["official_year"] != official_year:
        _fail("cwe_top25.headline.official_year",
              "must equal cwe_top25.official_year")
    if headline["window_start"] != start or headline["window_end"] != end:
        _fail("cwe_top25.headline", "window bounds must equal cwe_top25.window")
    if headline["official_top_cwe"] != ranks[0]["cwe"]:
        _fail("cwe_top25.headline.official_top_cwe",
              "must equal the rank-1 CWE in ranks")
    if (headline["in_measured_top25"]
            + headline["outside_measured_top25"] != len(ranks)):
        _fail("cwe_top25.headline.in_measured_top25",
              "in + outside must equal the number of ranks")
    if headline["in_kev"] > len(ranks):
        _fail("cwe_top25.headline.in_kev", "cannot exceed the number of ranks")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "cwe_top25.json": _validate_cwe_top25,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the top25 contract for ``filename``.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no top25 contract.
    """
    VALIDATORS[filename](obj)
