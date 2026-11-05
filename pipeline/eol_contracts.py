"""Contract for the Support Windows output (support_windows.json).

Same philosophy as pipeline/contracts.py: a hand-rolled stdlib validator
that fails loudly, in its own module so the stage lands without touching
the core contracts beyond one registration line.

The consistency checks are strong on purpose. Every line partition (by
state, by release year, by category) must add up to the catalogue, a
median is either a number of days or null with a lower bound, and a
release year's ``partial`` flag belongs to the ``as_of`` year only (never
``generated_at``, so an edition carried forward across New Year stays
valid).
"""
from __future__ import annotations

from typing import Any, Callable

from .contracts import (DATE_RE, _check_generated_at, _check_int, _check_list,
                        _check_num, _check_sorted, _check_str, _fail, _get)
from .eol_metrics import STATES

_MEDIAN_KEYS = ("median_days", "median_at_least")


def _check_bool(v: Any, path: str) -> None:
    if not isinstance(v, bool):
        _fail(path, f"expected boolean, got {v!r}")


def _check_opt_int(v: Any, path: str) -> None:
    if v is not None:
        _check_int(v, path)


def _check_median(obj: Any, path: str, med_key: str = "median_days",
                  min_key: str = "median_at_least") -> None:
    """A median is a day count or null; ``at_least`` is set only when the
    median is null (the median was not reached)."""
    med = _get(obj, med_key, path)
    low = _get(obj, min_key, path)
    _check_opt_int(med, f"{path}.{med_key}")
    _check_opt_int(low, f"{path}.{min_key}")
    if med is not None and low is not None:
        _fail(path, f"{min_key} must be null when {med_key} is set")


def _check_pct(v: Any, path: str) -> None:
    _check_num(v, path, 0.0, 100.0)


def _check_states(obj: Any, path: str) -> int:
    """The four line states are ints summing to ``lines``; returns it."""
    lines = _get(obj, "lines", path)
    _check_int(lines, f"{path}.lines")
    total = 0
    for s in STATES:
        v = _get(obj, s, path)
        _check_int(v, f"{path}.{s}")
        total += v
    if total != lines:
        _fail(path, f"line states sum to {total}, lines is {lines}")
    return lines


def _check_period(cell: Any, path: str, span: list) -> None:
    for k in ("from", "to"):
        _check_int(_get(cell, k, path), f"{path}.{k}", minimum=1900)
    if [cell["from"], cell["to"]] != span:
        _fail(path, f"period must span {span}")
    _check_int(_get(cell, "lines", path), f"{path}.lines")
    _check_int(_get(cell, "products", path), f"{path}.products")
    _check_median(cell, path)


def _validate_support_windows(obj: Any) -> None:
    p = "support_windows"
    _check_generated_at(obj, p)
    as_of = _get(obj, "as_of", p)
    _check_str(as_of, f"{p}.as_of", DATE_RE)
    as_of_year = int(as_of[:4])
    upstream = _get(obj, "upstream", p)
    for k in ("generated_at", "schema_version"):
        v = _get(upstream, k, f"{p}.upstream")
        if v is not None:
            _check_str(v, f"{p}.upstream.{k}")
    _check_num(_get(obj, "provisional_open_pct", p),
               f"{p}.provisional_open_pct", 0.0, 100.0)
    min_products = _get(obj, "min_products", p)
    _check_int(min_products, f"{p}.min_products", minimum=1)
    min_cat = _get(obj, "min_category_products", p)
    _check_int(min_cat, f"{p}.min_category_products", minimum=1)

    # ---- catalog -------------------------------------------------------------
    cat = _get(obj, "catalog", p)
    cp = f"{p}.catalog"
    products = _get(cat, "products", cp)
    _check_int(products, f"{cp}.products", minimum=1)
    lines = _check_states(cat, cp)
    for k in ("categories", "unreleased", "malformed", "no_supported_line",
              "newest_line_ended"):
        _check_int(_get(cat, k, cp), f"{cp}.{k}")
    if cat["no_supported_line"] > cat["newest_line_ended"]:
        _fail(cp, "a product with no line in support has its newest line "
                  "out of support too: no_supported_line <= newest_line_ended")
    if cat["newest_line_ended"] > products:
        _fail(f"{cp}.newest_line_ended", "exceeds products")
    for k in ("first_year", "last_year"):
        _check_opt_int(_get(cat, k, cp), f"{cp}.{k}")
    if lines and (cat["first_year"] is None or cat["last_year"] is None
                  or cat["first_year"] > cat["last_year"]
                  or cat["last_year"] > as_of_year):
        _fail(cp, "first_year/last_year must bracket the lines and end by "
                  "the as_of year")

    # ---- panel and periods ---------------------------------------------------
    panel = _get(obj, "panel", p)
    early = _get(panel, "early", f"{p}.panel")
    late = _get(panel, "late", f"{p}.panel")
    for name, span in (("early", early), ("late", late)):
        if not (isinstance(span, list) and len(span) == 2
                and all(isinstance(y, int) for y in span)
                and span[0] <= span[1]):
            _fail(f"{p}.panel.{name}", "expected [first_year, last_year]")
    if early[1] >= late[0]:
        _fail(f"{p}.panel", "the early window must end before the late one")
    panel_n = _get(panel, "products", f"{p}.panel")
    _check_int(panel_n, f"{p}.panel.products")
    if panel_n > products:
        _fail(f"{p}.panel.products", "exceeds catalog.products")
    periods = _get(obj, "periods", p)
    for group in ("all", "panel"):
        gp = f"{p}.periods.{group}"
        g = _get(periods, group, f"{p}.periods")
        _check_period(_get(g, "early", gp), f"{gp}.early", early)
        _check_period(_get(g, "late", gp), f"{gp}.late", late)
        chg = _get(g, "change_pct", gp)
        if chg is not None:
            _check_num(chg, f"{gp}.change_pct", -100.0, 10000.0)
    for span_key in ("early", "late"):
        if periods["panel"][span_key]["products"] != panel_n:
            _fail(f"{p}.periods.panel.{span_key}.products",
                  "every panel product has a line in both windows")
        if periods["panel"][span_key]["lines"] > \
                periods["all"][span_key]["lines"]:
            _fail(f"{p}.periods.panel.{span_key}.lines",
                  "the panel is a subset of all products")

    # ---- years ---------------------------------------------------------------
    years = _check_list(_get(obj, "years", p), f"{p}.years")
    if lines and not years:
        _fail(f"{p}.years", "lines on file but no release years charted")
    ys: list[int] = []
    for i, r in enumerate(years):
        rp = f"{p}.years[{i}]"
        y = _get(r, "year", rp)
        _check_int(y, f"{rp}.year", minimum=1900)
        ys.append(y)
        _check_states(r, rp)
        n_prod = _get(r, "products", rp)
        _check_int(n_prod, f"{rp}.products")
        _check_median(r, rp)
        _check_pct(_get(r, "open_pct", rp), f"{rp}.open_pct")
        for k in ("panel_lines", "panel_products"):
            _check_int(_get(r, k, rp), f"{rp}.{k}")
        _check_median(r, rp, "panel_median_days", "panel_median_at_least")
        if r["panel_products"] > n_prod or r["panel_lines"] > r["lines"]:
            _fail(rp, "panel counts exceed the year's counts")
        if n_prod < min_products and (r["median_days"] is not None
                                      or r["median_at_least"] is not None):
            _fail(rp, f"fewer than {min_products} products publish no median")
        if r["panel_products"] < min_products and \
                (r["panel_median_days"] is not None
                 or r["panel_median_at_least"] is not None):
            _fail(rp, f"fewer than {min_products} panel products publish no "
                      f"median")
        _check_bool(_get(r, "partial", rp), f"{rp}.partial")
        _check_bool(_get(r, "provisional", rp), f"{rp}.provisional")
        if r["partial"] != (y == as_of_year):
            _fail(f"{rp}.partial", "exactly the as_of year is partial")
        if r["partial"] and not r["provisional"]:
            _fail(f"{rp}.provisional", "the partial year is provisional")
        if r["open_pct"] > obj["provisional_open_pct"] and \
                not r["provisional"]:
            _fail(f"{rp}.provisional", "open share above the threshold "
                                        "must be provisional")
    _check_sorted(ys, f"{p}.years (by year)")
    if ys:
        if ys != list(range(ys[0], ys[-1] + 1)):
            _fail(f"{p}.years", "release years must be contiguous")
        if ys[-1] != as_of_year:
            _fail(f"{p}.years", "the series must end at the as_of year")
        if sum(r["lines"] for r in years) > lines:
            _fail(f"{p}.years", "year lines exceed catalog.lines")

    # ---- phases --------------------------------------------------------------
    ph = _get(obj, "phases", p)
    pp = f"{p}.phases"
    for k in ("products", "lines", "gap_lines", "zero_gap_lines",
              "gap_unknown_lines"):
        _check_int(_get(ph, k, pp), f"{pp}.{k}")
    if ph["products"] > products or ph["lines"] > lines:
        _fail(pp, "phase counts exceed the catalogue")
    if ph["gap_lines"] + ph["gap_unknown_lines"] != ph["lines"]:
        _fail(pp, "gap_lines + gap_unknown_lines must equal lines")
    if ph["zero_gap_lines"] > ph["gap_lines"]:
        _fail(f"{pp}.zero_gap_lines", "exceeds gap_lines")
    _check_median(ph, pp, "active_median_days", "active_median_at_least")
    _check_median(ph, pp, "security_median_days", "security_median_at_least")
    _check_opt_int(_get(ph, "gap_median_days", pp), f"{pp}.gap_median_days")
    if (ph["gap_median_days"] is None) != (ph["gap_lines"] == 0):
        _fail(f"{pp}.gap_median_days", "null exactly when no line has both "
                                       "dates")
    prow = _check_list(_get(ph, "years", pp), f"{pp}.years")
    pys: list[int] = []
    for i, r in enumerate(prow):
        rp = f"{pp}.years[{i}]"
        y = _get(r, "year", rp)
        _check_int(y, f"{rp}.year", minimum=1900)
        pys.append(y)
        _check_int(_get(r, "lines", rp), f"{rp}.lines")
        _check_int(_get(r, "products", rp), f"{rp}.products")
        _check_median(r, rp, "active_median_days", "active_median_at_least")
        _check_median(r, rp, "security_median_days",
                      "security_median_at_least")
        _check_bool(_get(r, "partial", rp), f"{rp}.partial")
        _check_bool(_get(r, "provisional", rp), f"{rp}.provisional")
        if r["partial"] != (y == as_of_year):
            _fail(f"{rp}.partial", "exactly the as_of year is partial")
        if r["partial"] and not r["provisional"]:
            _fail(f"{rp}.provisional", "the partial year is provisional")
    _check_sorted(pys, f"{pp}.years (by year)")
    if pys and pys[-1] > as_of_year:
        _fail(f"{pp}.years", "no release year after as_of")

    # ---- categories ----------------------------------------------------------
    cats = _check_list(_get(obj, "categories", p), f"{p}.categories")
    if len(cats) != cat["categories"]:
        _fail(f"{p}.categories", "must list catalog.categories rows")
    names: set[str] = set()
    keys: list[tuple] = []
    sums = {"products": 0, "lines": 0, "no_supported_line": 0,
            "newest_line_ended": 0}
    for i, r in enumerate(cats):
        rp = f"{p}.categories[{i}]"
        name = _get(r, "category", rp)
        _check_str(name, f"{rp}.category")
        if name in names:
            _fail(f"{rp}.category", f"duplicate category {name!r}")
        names.add(name)
        _check_int(_get(r, "products", rp), f"{rp}.products", minimum=1)
        _check_states(r, rp)
        _check_median(r, rp)
        if r["products"] < min_cat and (r["median_days"] is not None
                                        or r["median_at_least"] is not None):
            _fail(rp, f"fewer than {min_cat} products publish no median")
        _check_pct(_get(r, "open_pct", rp), f"{rp}.open_pct")
        for k in ("no_supported_line", "newest_line_ended"):
            _check_int(_get(r, k, rp), f"{rp}.{k}")
        if not r["no_supported_line"] <= r["newest_line_ended"] \
                <= r["products"]:
            _fail(rp, "no_supported_line <= newest_line_ended <= products")
        for k in sums:
            sums[k] += r[k]
        keys.append((r["median_days"] is None, -(r["median_days"] or 0),
                     name))
    _check_sorted(keys, f"{p}.categories (by median desc, nulls last)")
    for k, v in sums.items():
        if v != cat[k]:
            _fail(f"{p}.categories", f"category {k} sum to {v}, catalog "
                                     f"says {cat[k]}")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "support_windows.json": _validate_support_windows,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the support-windows contract. Raises
    :class:`pipeline.contracts.ContractViolation` on any mismatch."""
    VALIDATORS[filename](obj)
