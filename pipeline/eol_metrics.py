"""Support Windows (support_windows.json): how long software release lines
are supported, read from the endoflife.date catalogue (fetch_eol).

A *release line* is one of endoflife.date's release cycles (Ubuntu 24.04,
Python 3.12, iPhone 15, PostgreSQL 17 ...). Its *support window* is the
days from its release date to its end-of-support date (``eolFrom``, the end
of the last standard support phase; paid extended support is not counted).

Every line falls in one of four states on the snapshot date (``as_of``):

* ``ended`` — the end date is on or before ``as_of``;
* ``scheduled`` — the vendor has announced an end date after ``as_of``;
  the announced date counts as the end (vendors sometimes extend);
* ``open`` — still supported and no end date announced. Its window is at
  least its age so far: a right-censored observation, never "forever";
* ``ended_undated`` — endoflife.date marks support as ended but records
  no date. The window is unknown; the line is counted and excluded from
  every median.

Medians are Kaplan–Meier estimates, which use an open line as "supported
for at least its age" instead of dropping it or treating it as ended. When
fewer than half the lines have ended by the longest age observed, the
median is not reached: it is published as null with ``median_at_least``,
a lower bound.

Weighting: each product counts once per group. A product with k lines in
a release year gives each a weight of 1/k there, so a product that ships a
line every month does not outvote one that ships every two years. The
catalogue is whatever endoflife.date tracks; nothing here samples it.

Sections:

* ``years`` (hero) — the median window by release year for every tracked
  product, and for a fixed panel: the products with lines released in both
  :data:`PANEL_EARLY` and :data:`PANEL_LATE`. The catalogue's product mix
  changes over the years (most products were added with only their recent
  lines); the panel holds the products fixed. ``periods`` pools the two
  windows for both groups. A year is ``provisional`` while it is the
  current year or more than :data:`PROVISIONAL_OPEN_PCT` % of its weight is
  still open.
* ``phases`` — products that separate active support (bug fixes) from
  security support: the median days to the end of each, by release year,
  and the gap between the two on lines where both dates are known.
* ``categories`` — the median window per endoflife.date category, and how
  many of each category's products have no release line in support.
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import date
from pathlib import Path
from typing import Callable, Iterable

from .fetch_eol import EolSnapshot, Product, ReleaseLine

FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures"
FIXTURE_NAME = "eol_products_full.json"
OUTPUT_NAME = "support_windows.json"

STATES = ("ended", "scheduled", "open", "ended_undated")

# The fixed panel: products with release lines in both windows.
PANEL_EARLY = (2014, 2016)
PANEL_LATE = (2022, 2024)
# A release year is provisional while more than this share of its weight
# has no announced end date (or while it is the current year).
PROVISIONAL_OPEN_PCT = 20.0
# A release year is charted from the first year with this many products;
# a year below it publishes no median. (At 20 the 2000s cohorts, 20-35
# products each, swung between two and six years from year to year.)
MIN_PRODUCTS = 50
# Categories with fewer products are listed but publish no median.
MIN_CATEGORY_PRODUCTS = 5


def _r1(v: float) -> float:
    return round(float(v), 1)


def _days(a: str, b: str) -> int:
    return (date.fromisoformat(b) - date.fromisoformat(a)).days


def line_state(line: ReleaseLine, as_of: str) -> str:
    """One of :data:`STATES`. The date wins over the upstream ``isEol``
    flag, which endoflife.date computes at its own build time."""
    if line.eol is not None:
        return "ended" if line.eol <= as_of else "scheduled"
    return "ended_undated" if line.is_eol else "open"


def window_item(line: ReleaseLine, as_of: str) -> tuple[int, bool] | None:
    """(days, ended) for the support window: ``ended`` True for an ended
    or announced end, False for an open (censored) line; None when the
    window is unknown (ended without a date)."""
    if line.eol is not None:
        return _days(line.release, line.eol), True
    if line.is_eol:
        return None
    return _days(line.release, as_of), False


def active_item(line: ReleaseLine, as_of: str) -> tuple[int, bool] | None:
    """The same for the end of active support (lines whose product
    separates the phases only)."""
    if not line.has_eoas:
        return None
    if line.eoas is not None:
        return _days(line.release, line.eoas), True
    if line.is_eoas:
        return None
    return _days(line.release, as_of), False


def km_median(items: Iterable[tuple[int, bool, float]]
              ) -> tuple[int | None, int | None]:
    """Weighted Kaplan–Meier median of ``(days, ended, weight)`` items.

    Returns ``(median, at_least)``: the median in days and None, or None
    and a lower bound (the longest time observed) when the survival curve
    never falls to one half. Ended items are processed before censored
    ones at the same time (the standard convention). ``(None, None)`` for
    no items."""
    rows = sorted(items, key=lambda r: (r[0], not r[1]))
    if not rows:
        return None, None
    at_risk = sum(w for _, _, w in rows)
    surv = 1.0
    i = 0
    n = len(rows)
    while i < n:
        t = rows[i][0]
        ended_w = censored_w = 0.0
        while i < n and rows[i][0] == t:
            if rows[i][1]:
                ended_w += rows[i][2]
            else:
                censored_w += rows[i][2]
            i += 1
        if ended_w and at_risk > 0:
            surv *= 1.0 - ended_w / at_risk
            if surv <= 0.5 + 1e-9:
                return t, None
        at_risk -= ended_w + censored_w
    return None, rows[-1][0]


def weighted_median(values: Iterable[tuple[float, float]]) -> float | None:
    """Plain weighted median of ``(value, weight)`` pairs (lower median on
    an exact half)."""
    rows = sorted(values)
    total = sum(w for _, w in rows)
    if not rows or total <= 0:
        return None
    acc = 0.0
    for v, w in rows:
        acc += w
        if acc >= total / 2 - 1e-9:
            return v
    return rows[-1][0]


def _year(line: ReleaseLine) -> int:
    return int(line.release[:4])


def _released(products: list[Product], as_of: str
              ) -> list[tuple[Product, list[ReleaseLine]]]:
    """Each product with its lines released on or before ``as_of`` (an
    announced future release is not a window yet)."""
    return [(p, [ln for ln in p.lines if ln.release <= as_of])
            for p in products]


def _weighted(groups: dict, key_fn: Callable[[ReleaseLine, str],
                                              tuple[int, bool] | None],
              as_of: str) -> list[tuple[int, bool, float]]:
    """``groups``: product name -> its lines in one cell. Each product's
    usable items get weight 1/k (k = its usable items in the cell)."""
    out: list[tuple[int, bool, float]] = []
    for lines in groups.values():
        items = [it for it in (key_fn(ln, as_of) for ln in lines)
                 if it is not None]
        for days, ended in items:
            out.append((days, ended, 1.0 / len(items)))
    return out


def _state_counts(lines: Iterable[ReleaseLine], as_of: str) -> dict:
    counts = dict.fromkeys(STATES, 0)
    for ln in lines:
        counts[line_state(ln, as_of)] += 1
    return counts


def _open_pct(groups: dict, as_of: str) -> float:
    """Share of the cell's product weight that is still open (no announced
    end), over the usable lines."""
    items = _weighted(groups, window_item, as_of)
    total = sum(w for _, _, w in items)
    if total <= 0:
        return 0.0
    return _r1(100.0 * sum(w for _, ended, w in items if not ended) / total)


def _cell(groups: dict, as_of: str) -> dict:
    """Median block for one cell (product name -> lines)."""
    lines = [ln for ls in groups.values() for ln in ls]
    med, at_least = km_median(_weighted(groups, window_item, as_of))
    return {"lines": len(lines), "products": len(groups),
            "median_days": med, "median_at_least": at_least,
            **_state_counts(lines, as_of)}


def panel_products(released) -> list[str]:
    """Products with a line of known or open window released in both
    panel windows."""
    out = []
    lo1, hi1 = PANEL_EARLY
    lo2, hi2 = PANEL_LATE
    for p, lines in released:
        years = {_year(ln) for ln in lines
                 if window_item(ln, "9999-12-31") is not None}
        if any(lo1 <= y <= hi1 for y in years) and \
                any(lo2 <= y <= hi2 for y in years):
            out.append(p.name)
    return sorted(out)


def build_years(released, as_of: str, panel: set[str], *,
                min_products: int = MIN_PRODUCTS) -> list[dict]:
    as_of_year = int(as_of[:4])
    by_year: dict[int, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for p, lines in released:
        for ln in lines:
            by_year[_year(ln)][p.name].append(ln)
    if not by_year:
        return []
    eligible = [y for y in sorted(by_year) if len(by_year[y]) >= min_products]
    first = eligible[0] if eligible else min(by_year)
    rows = []
    for y in range(first, as_of_year + 1):
        groups = by_year.get(y, {})
        cell = _cell(groups, as_of)
        thin = cell["products"] < min_products
        if thin:
            cell["median_days"] = cell["median_at_least"] = None
        open_pct = _open_pct(groups, as_of)
        pgroups = {k: v for k, v in groups.items() if k in panel}
        pcell = _cell(pgroups, as_of)
        if pcell["products"] < min_products:
            pcell["median_days"] = pcell["median_at_least"] = None
        rows.append({
            "year": y,
            **cell,
            "open_pct": open_pct,
            "panel_lines": pcell["lines"],
            "panel_products": pcell["products"],
            "panel_median_days": pcell["median_days"],
            "panel_median_at_least": pcell["median_at_least"],
            "partial": y == as_of_year,
            "provisional": y == as_of_year or thin
                           or open_pct > PROVISIONAL_OPEN_PCT,
        })
    return rows


def _period_cell(released, as_of: str, span: tuple[int, int],
                 only: set[str] | None) -> dict:
    """Pooled window over a span of release years; weights stay per
    product-year, so each product counts once in each year it shipped."""
    lo, hi = span
    items: list[tuple[int, bool, float]] = []
    products: set[str] = set()
    lines = 0
    for p, plines in released:
        if only is not None and p.name not in only:
            continue
        per_year: dict[int, list] = defaultdict(list)
        for ln in plines:
            if lo <= _year(ln) <= hi:
                per_year[_year(ln)].append(ln)
        for y, ls in per_year.items():
            products.add(p.name)
            lines += len(ls)
            items.extend(_weighted({p.name: ls}, window_item, as_of))
    med, at_least = km_median(items)
    return {"from": lo, "to": hi, "lines": lines, "products": len(products),
            "median_days": med, "median_at_least": at_least}


def _change_pct(early: dict, late: dict) -> float | None:
    a, b = early["median_days"], late["median_days"]
    if not a or b is None:
        return None
    return _r1(100.0 * (b - a) / a)


def build_periods(released, as_of: str, panel: set[str]) -> dict:
    out = {}
    for key, only in (("all", None), ("panel", panel)):
        early = _period_cell(released, as_of, PANEL_EARLY, only)
        late = _period_cell(released, as_of, PANEL_LATE, only)
        out[key] = {"early": early, "late": late,
                    "change_pct": _change_pct(early, late)}
    return out


def build_phases(released, as_of: str, *,
                 min_products: int = MIN_PRODUCTS) -> dict:
    """Products whose lines carry an end of active support."""
    as_of_year = int(as_of[:4])
    by_year: dict[int, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    products: set[str] = set()
    for p, lines in released:
        for ln in lines:
            if ln.has_eoas:
                by_year[_year(ln)][p.name].append(ln)
                products.add(p.name)
    rows = []
    eligible = [y for y in sorted(by_year) if len(by_year[y]) >= min_products]
    pooled_active: list = []
    pooled_security: list = []
    gaps: list[tuple[float, float]] = []
    gap_lines = zero_gap = gap_unknown = 0
    for y in sorted(by_year):
        groups = by_year[y]
        act = _weighted(groups, active_item, as_of)
        sec = _weighted(groups, window_item, as_of)
        pooled_active.extend(act)
        pooled_security.extend(sec)
        for lines in groups.values():
            known = [ln for ln in lines
                     if ln.eoas is not None and ln.eol is not None]
            gap_unknown += len(lines) - len(known)
            for ln in known:
                g = _days(ln.eoas, ln.eol)
                gaps.append((g, 1.0 / len(known)))
                gap_lines += 1
                zero_gap += g == 0
        if eligible and eligible[0] <= y <= as_of_year:
            a_med, a_min = km_median(act)
            s_med, s_min = km_median(sec)
            thin = len(groups) < min_products
            rows.append({
                "year": y,
                "lines": sum(len(v) for v in groups.values()),
                "products": len(groups),
                "active_median_days": None if thin else a_med,
                "active_median_at_least": None if thin else a_min,
                "security_median_days": None if thin else s_med,
                "security_median_at_least": None if thin else s_min,
                "partial": y == as_of_year,
                "provisional": y == as_of_year or thin
                               or _open_pct(groups, as_of)
                               > PROVISIONAL_OPEN_PCT,
            })
    a_med, a_min = km_median(pooled_active)
    s_med, s_min = km_median(pooled_security)
    gap = weighted_median(gaps)
    return {
        "products": len(products),
        "lines": sum(len(v) for g in by_year.values() for v in g.values()),
        "active_median_days": a_med, "active_median_at_least": a_min,
        "security_median_days": s_med, "security_median_at_least": s_min,
        "gap_lines": gap_lines,
        "gap_median_days": None if gap is None else int(gap),
        "zero_gap_lines": zero_gap,
        "gap_unknown_lines": gap_unknown,
        "years": rows,
    }


def _supported(line: ReleaseLine, as_of: str) -> bool:
    return line_state(line, as_of) in ("scheduled", "open")


def build_categories(released, as_of: str, *,
                     min_products: int = MIN_CATEGORY_PRODUCTS) -> list[dict]:
    """One row per endoflife.date category: product-weighted median window
    over all of the category's lines, and support status today."""
    by_cat: dict[str, list] = defaultdict(list)
    for p, lines in released:
        by_cat[p.category].append((p, lines))
    rows = []
    for cat, members in by_cat.items():
        groups = {p.name: lines for p, lines in members if lines}
        med, at_least = km_median(_weighted(groups, window_item, as_of))
        thin = len(members) < min_products
        no_supported = sum(1 for _p, lines in members
                           if lines and not any(_supported(ln, as_of)
                                                for ln in lines))
        newest_ended = 0
        for _p, lines in members:
            if lines:
                newest = max(lines, key=lambda ln: ln.release)
                newest_ended += not _supported(newest, as_of)
        all_lines = [ln for _p, lines in members for ln in lines]
        rows.append({
            "category": cat,
            "products": len(members),
            "lines": len(all_lines),
            "median_days": None if thin else med,
            "median_at_least": None if thin else at_least,
            "open_pct": _open_pct(groups, as_of),
            "no_supported_line": no_supported,
            "newest_line_ended": newest_ended,
            **_state_counts(all_lines, as_of),
        })
    rows.sort(key=lambda r: (r["median_days"] is None,
                             -(r["median_days"] or 0), r["category"]))
    return rows


def build_support_windows(snap: EolSnapshot, generated_at: str, *,
                          min_products: int = MIN_PRODUCTS,
                          min_category_products: int = MIN_CATEGORY_PRODUCTS
                          ) -> dict:
    """Assemble support_windows.json. The two floors drop to 1 for the
    tiny fixture catalogue (the real thresholds are unit-tested)."""
    as_of = generated_at[:10]
    released = _released(snap.products, as_of)
    panel = set(panel_products(released))
    all_lines = [ln for _p, lines in released for ln in lines]
    unreleased = snap.line_count - len(all_lines)
    years = build_years(released, as_of, panel, min_products=min_products)
    cats = build_categories(released, as_of,
                            min_products=min_category_products)
    no_supported = sum(r["no_supported_line"] for r in cats)
    newest_ended = sum(r["newest_line_ended"] for r in cats)
    return {
        "generated_at": generated_at,
        "as_of": as_of,
        "upstream": {"generated_at": snap.upstream_generated_at,
                     "schema_version": snap.schema_version},
        "provisional_open_pct": PROVISIONAL_OPEN_PCT,
        "min_products": min_products,
        "min_category_products": min_category_products,
        "catalog": {
            "products": snap.product_count,
            "categories": len(cats),
            "lines": len(all_lines),
            **_state_counts(all_lines, as_of),
            "unreleased": unreleased,
            "malformed": snap.malformed,
            "first_year": min((_year(ln) for ln in all_lines), default=None),
            "last_year": max((_year(ln) for ln in all_lines), default=None),
            "no_supported_line": no_supported,
            "newest_line_ended": newest_ended,
        },
        "panel": {"early": list(PANEL_EARLY), "late": list(PANEL_LATE),
                  "products": len(panel)},
        "periods": build_periods(released, as_of, panel),
        "years": years,
        "phases": build_phases(released, as_of, min_products=min_products),
        "categories": cats,
    }


def source_block(obj: dict, fetched_at: str, snap: EolSnapshot) -> dict:
    """meta.sources.eol."""
    return {"fetched_at": fetched_at,
            "products": obj["catalog"]["products"],
            "lines": obj["catalog"]["lines"],
            "not_modified": snap.not_modified}


def prior_product_count(out_dir: Path | None) -> int | None:
    """The previous published edition's product count, or None when there
    is no readable previous edition."""
    if out_dir is None:
        return None
    try:
        prior = json.loads((out_dir / OUTPUT_NAME).read_text("utf-8"))
        n = prior["catalog"]["products"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return n if isinstance(n, int) and not isinstance(n, bool) else None


def run_stage(cache_dir: Path, generated_at: str, *, offline_fixtures: bool,
              out_dir: Path | None = None, session=None,
              log: Callable[[str], None] = print) -> tuple[dict, dict]:
    """(support_windows.json, meta.sources.eol).

    Raises ``OSError`` / ``ValueError`` on an upstream failure; the caller
    carries the previous edition forward, marked stale. ``out_dir`` holds
    the previous edition, whose product count sets the shrink floor."""
    from .fetch_eol import fetch_full, load_full_file

    if offline_fixtures:
        snap = load_full_file(FIXTURES_DIR / FIXTURE_NAME)
        floors = {"min_products": 1, "min_category_products": 1}
    else:
        log("fetching endoflife.date release-cycle catalogue ...")
        snap = fetch_full(cache_dir, session=session,
                          prior_products=prior_product_count(out_dir),
                          log=log)
        floors = {}
    obj = build_support_windows(snap, generated_at, **floors)
    c = obj["catalog"]
    log(f"  support windows: {c['products']} products, {c['lines']} release "
        f"lines ({c['open']} open, {c['ended_undated']} ended undated), "
        f"panel {obj['panel']['products']} products")
    return obj, source_block(obj, generated_at, snap)
