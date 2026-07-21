"""Contract for the Security Market output (market_hype.json).

Same philosophy as pipeline/contracts.py — hand-rolled stdlib validators
that fail loudly — kept in its own module so the market stage lands
without touching the core contracts file. The coordinator merges
:data:`VALIDATORS` into the pipeline's dispatch; failures raise the same
:class:`pipeline.contracts.ContractViolation` type, so callers need only
one except clause.

The core module's private checking helpers are reused read-only.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .contracts import (_check_bool, _check_generated_at, _check_int,
                        _check_list, _check_num, _check_sorted, _check_str,
                        _fail, _get)

MONTH_RE = re.compile(r"^\d{4}-\d{2}$")
SOURCES = ["gdelt", "hn", "arxiv", "wiki", "edgar"]
# Pre-v1.1 files (three sources). Accepted so the committed
# site/data/market_hype.json — one nightly behind this code by
# construction — keeps validating between the v1.1 merge and the first
# nightly rebuild, which rewrites it with five sources. Safe to delete
# after that first nightly has committed.
LEGACY_SOURCES = ["gdelt", "hn", "arxiv"]
DIRECTIONS = ("research_leads", "media_leads", "aligned")
# pct_change is bounded below (counts cannot drop more than 100%) but a
# breakout term can rise by any amount, so there is no upper bound.
_NO_UPPER = float("inf")


def _check_series(entries: list, path: str) -> None:
    months = []
    for i, point in enumerate(entries):
        ppath = f"{path}[{i}]"
        month = _get(point, "month", ppath)
        _check_str(month, f"{ppath}.month", MONTH_RE)
        _check_int(_get(point, "n", ppath), f"{ppath}.n")
        _check_num(_get(point, "index", ppath), f"{ppath}.index", 0.0, 100.0)
        months.append(month)
    _check_sorted(months, path)
    if len(set(months)) != len(months):
        _fail(path, "duplicate months (one point per month)")


def _check_yoy(y: Any, path: str) -> None:
    _check_str(_get(y, "latest_month", path), f"{path}.latest_month", MONTH_RE)
    _check_num(_get(y, "pct_change", path), f"{path}.pct_change",
               -100.0, _NO_UPPER)
    _check_int(_get(y, "n_latest_12m", path), f"{path}.n_latest_12m")
    _check_int(_get(y, "n_prior_12m", path), f"{path}.n_prior_12m")


def _check_direction(v: Any, path: str) -> None:
    if v not in DIRECTIONS:
        _fail(path, f"direction {v!r} not one of {list(DIRECTIONS)}")


def _check_divergence(d: Any, path: str) -> None:
    _check_num(_get(d, "gdelt_index_avg3m", path),
               f"{path}.gdelt_index_avg3m", 0.0, 100.0)
    _check_num(_get(d, "arxiv_index_avg3m", path),
               f"{path}.arxiv_index_avg3m", 0.0, 100.0)
    _check_num(_get(d, "research_vs_media_index", path),
               f"{path}.research_vs_media_index", -100.0, 100.0)
    _check_direction(_get(d, "direction", path), f"{path}.direction")


def _check_mover(m: Any, path: str) -> None:
    _check_str(_get(m, "term_id", path), f"{path}.term_id")
    _check_str(_get(m, "label", path), f"{path}.label")
    source = _get(m, "source", path)
    if source not in SOURCES:
        _fail(f"{path}.source", f"unknown source {source!r}")
    _check_num(_get(m, "pct_change", path), f"{path}.pct_change",
               -100.0, _NO_UPPER)


# ---------------------------------------------------------- market_hype.json

def _validate_market_hype(obj: Any) -> None:
    _check_generated_at(obj, "market_hype")
    _check_int(_get(obj, "window_months", "market_hype"),
               "market_hype.window_months", minimum=1)
    # The declared source list drives the per-term key checks below, so a
    # legacy file is held to exactly its three keys and a v1.1 file to
    # all five — never a mix.
    declared = _get(obj, "sources", "market_hype")
    if declared not in (SOURCES, LEGACY_SOURCES):
        _fail("market_hype.sources",
              f"must equal {SOURCES} (or, until the first v1.1 nightly "
              f"rewrites the published file, {LEGACY_SOURCES})")
    _check_int(_get(obj, "backfill_remaining", "market_hype"),
               "market_hype.backfill_remaining")
    # Optional: present (and true) only on --skip-market carry-forwards.
    if "stale" in obj:
        _check_bool(obj["stale"], "market_hype.stale")

    terms = _check_list(_get(obj, "terms", "market_hype"), "market_hype.terms")
    for i, t in enumerate(terms):
        path = f"market_hype.terms[{i}]"
        _check_str(_get(t, "id", path), f"{path}.id")
        _check_str(_get(t, "label", path), f"{path}.label")
        series = _get(t, "series", path)
        for source in declared:
            _check_series(
                _check_list(_get(series, source, f"{path}.series"),
                            f"{path}.series.{source}"),
                f"{path}.series.{source}")
        yoy = _get(t, "yoy", path)
        for source in declared:
            y = _get(yoy, source, f"{path}.yoy")
            if y is not None:
                _check_yoy(y, f"{path}.yoy.{source}")
        div = _get(t, "divergence", path)
        if div is not None:
            _check_divergence(div, f"{path}.divergence")

    headline = _get(obj, "headline", "market_hype")
    for key in ("top_riser", "top_faller"):
        mover = _get(headline, key, "market_hype.headline")
        if mover is not None:
            _check_mover(mover, f"market_hype.headline.{key}")
    top_div = _get(headline, "top_divergence", "market_hype.headline")
    if top_div is not None:
        path = "market_hype.headline.top_divergence"
        _check_str(_get(top_div, "term_id", path), f"{path}.term_id")
        _check_str(_get(top_div, "label", path), f"{path}.label")
        _check_num(_get(top_div, "research_vs_media_index", path),
                   f"{path}.research_vs_media_index", -100.0, 100.0)
        _check_direction(_get(top_div, "direction", path), f"{path}.direction")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "market_hype.json": _validate_market_hype,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the market contract for ``filename``.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no market contract.
    """
    VALIDATORS[filename](obj)
