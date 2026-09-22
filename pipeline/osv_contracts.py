"""Contracts for the OSV-fed outputs: advisory_gap.json (module 25) and
registry_malware.json (module 26).

Same philosophy as pipeline/contracts.py — a hand-rolled stdlib validator
that fails loudly — kept in its own module like botnet_contracts; the
coordinator merges :data:`VALIDATORS` into the pipeline's dispatch.

The checks are mostly internal consistency: every total is a partition of
the level above it (years, ecosystems, months and severities must add up
to the catalog), because a mismatch can only mean the builder broke. An
EMPTY edition (zero advisories / zero reports) is legal — the page then
shows its "no edition yet" card — but a non-empty one must be whole.
Partial-period flags are checked against ``as_of`` (the date the counts
were read), never ``generated_at``, so a carried-forward edition stays
valid across a month or year boundary.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .contracts import (DATE_RE, _check_generated_at, _check_int,
                        _check_list, _check_num, _check_str, _fail, _get)
from .osv_metrics import LAG_DAYS, SEVERITY_LEVELS

MONTH_RE = re.compile(r"^\d{4}-\d{2}$")


def _pct_of(value: Any, n: int, d: int, path: str) -> None:
    """``value`` is n/d as a 1-decimal percentage, or null when d is 0."""
    if d == 0:
        if value is not None:
            _fail(path, "must be null when the denominator is zero")
        return
    _check_num(value, path, 0.0, 100.0)
    if abs(value - round(100.0 * n / d, 1)) > 1e-6:
        _fail(path, f"{value} does not equal {n}/{d}")


def _check_tally(t: Any, path: str) -> int:
    for k in ("total", "with_cve", "without_cve", "without_cve_young"):
        _check_int(_get(t, k, path), f"{path}.{k}")
    if t["with_cve"] + t["without_cve"] != t["total"]:
        _fail(path, "with_cve + without_cve must equal total")
    if t["without_cve_young"] > t["without_cve"]:
        _fail(f"{path}.without_cve_young", "exceeds without_cve")
    return t["total"]


def _check_years(rows: Any, path: str, as_year: int | None,
                 expect_years: list[int] | None = None,
                 partial_flag: bool = True) -> list[int]:
    rows = _check_list(rows, path)
    years = []
    for i, r in enumerate(rows):
        p = f"{path}[{i}]"
        y = _get(r, "year", p)
        _check_int(y, f"{p}.year", minimum=1990)
        years.append(y)
        _check_tally(r, p)
        _pct_of(_get(r, "without_cve_pct", p), r["without_cve"], r["total"],
                f"{p}.without_cve_pct")
        if partial_flag and _get(r, "partial", p) is not (y == as_year):
            _fail(f"{p}.partial", "must be true exactly for the as_of year")
    if years and years != list(range(years[0], years[0] + len(years))):
        _fail(path, "years must be consecutive and ascending")
    if expect_years is not None and years != expect_years:
        _fail(path, "must cover exactly the top-level year range")
    return years


def _validate_advisory_gap(obj: Any) -> None:
    _check_generated_at(obj, "advisory_gap")
    as_of = _get(obj, "as_of", "advisory_gap")
    _check_str(as_of, "advisory_gap.as_of", DATE_RE)
    as_year = int(as_of[:4])
    read = _check_list(_get(obj, "ecosystems_read", "advisory_gap"),
                       "advisory_gap.ecosystems_read")
    for i, e in enumerate(read):
        _check_str(e, f"advisory_gap.ecosystems_read[{i}]")
    _check_int(_get(obj, "young_days", "advisory_gap"),
               "advisory_gap.young_days", minimum=1)
    _check_str(_get(obj, "young_since", "advisory_gap"),
               "advisory_gap.young_since", DATE_RE)
    if obj["young_since"] >= as_of:
        _fail("advisory_gap.young_since", "must precede as_of")
    min_n = _get(obj, "min_n", "advisory_gap")
    _check_int(min_n, "advisory_gap.min_n", minimum=1)

    cat = _get(obj, "catalog", "advisory_gap")
    p = "advisory_gap.catalog"
    for k in ("advisories", "with_cve", "without_cve", "without_cve_young",
              "withdrawn_excluded", "not_reviewed", "multi_ecosystem"):
        _check_int(_get(cat, k, p), f"{p}.{k}")
    total = cat["advisories"]
    _check_tally({"total": total, "with_cve": cat["with_cve"],
                  "without_cve": cat["without_cve"],
                  "without_cve_young": cat["without_cve_young"]}, p)
    _pct_of(_get(cat, "without_cve_pct", p), cat["without_cve"], total,
            f"{p}.without_cve_pct")
    if cat["multi_ecosystem"] > total:
        _fail(f"{p}.multi_ecosystem", "exceeds advisories")

    years = _check_years(_get(obj, "years", "advisory_gap"),
                         "advisory_gap.years", as_year)
    if bool(years) != (total > 0):
        _fail("advisory_gap.years", "must be empty exactly when there are "
                                    "no advisories")
    first, last = _get(cat, "first_year", p), _get(cat, "last_year", p)
    if (first, last) != ((years[0], years[-1]) if years else (None, None)):
        _fail(p, "first_year/last_year must match the years series")
    for key in ("total", "with_cve", "without_cve", "without_cve_young"):
        s = sum(r[key] for r in obj["years"])
        want = total if key == "total" else cat[key]
        if s != want:
            _fail("advisory_gap.years", f"{key} sums to {s}, catalog {want}")

    ecos = _check_list(_get(obj, "ecosystems", "advisory_gap"),
                       "advisory_gap.ecosystems")
    if bool(ecos) != (total > 0):
        _fail("advisory_gap.ecosystems", "must be empty exactly when there "
                                         "are no advisories")
    names: set[str] = set()
    prev_total = None
    member_sum = 0
    for i, e in enumerate(ecos):
        pe = f"advisory_gap.ecosystems[{i}]"
        name = _get(e, "ecosystem", pe)
        _check_str(name, f"{pe}.ecosystem")
        if name in names:
            _fail(f"{pe}.ecosystem", f"duplicate {name!r}")
        names.add(name)
        n = _check_tally(e, pe)
        if n < 1:
            _fail(f"{pe}.total", "an ecosystem row needs at least one "
                                 "advisory")
        if prev_total is not None and n > prev_total:
            _fail("advisory_gap.ecosystems", "not sorted by total descending")
        prev_total = n
        member_sum += n
        share = _get(e, "without_cve_pct", pe)
        if n < min_n:
            if share is not None:
                _fail(f"{pe}.without_cve_pct",
                      f"must be null below min_n ({n} < {min_n})")
        else:
            _pct_of(share, e["without_cve"], n, f"{pe}.without_cve_pct")
        _check_years(_get(e, "years", pe), f"{pe}.years", as_year,
                     expect_years=years, partial_flag=False)
        for key in ("total", "with_cve", "without_cve", "without_cve_young"):
            if sum(r[key] for r in e["years"]) != e[key]:
                _fail(f"{pe}.years", f"{key} does not sum to the ecosystem "
                                     f"row")
    # An advisory counts once per affected ecosystem: memberships can only
    # exceed the deduplicated total, and only through multi-ecosystem ids.
    if member_sum < total:
        _fail("advisory_gap.ecosystems",
              f"ecosystem totals sum to {member_sum}, below the "
              f"{total} advisories")
    if member_sum > total and cat["multi_ecosystem"] == 0:
        _fail("advisory_gap.ecosystems",
              "ecosystem totals exceed advisories but no advisory is "
              "multi-ecosystem")

    sev = _check_list(_get(obj, "severity", "advisory_gap"),
                      "advisory_gap.severity")
    if [_get(s, "level", f"advisory_gap.severity[{i}]")
            for i, s in enumerate(sev)] != list(SEVERITY_LEVELS):
        _fail("advisory_gap.severity",
              f"must list exactly {list(SEVERITY_LEVELS)}")
    for key, pct_key in (("with_cve", "with_cve_pct"),
                         ("without_cve", "without_cve_pct")):
        s = 0
        for i, row in enumerate(sev):
            ps = f"advisory_gap.severity[{i}]"
            _check_int(_get(row, key, ps), f"{ps}.{key}")
            s += row[key]
            _pct_of(_get(row, pct_key, ps), row[key], cat[key],
                    f"{ps}.{pct_key}")
        if s != cat[key]:
            _fail("advisory_gap.severity",
                  f"{key} sums to {s}, catalog {cat[key]}")

    lag = _get(obj, "cve_lag", "advisory_gap")
    _check_int(_get(lag, "n", "advisory_gap.cve_lag"), "advisory_gap.cve_lag.n")
    if lag["n"] > cat["with_cve"]:
        _fail("advisory_gap.cve_lag.n", "exceeds with_cve")
    prev = lag["n"]
    for d in LAG_DAYS:
        k = f"later_{d}d"
        _check_int(_get(lag, k, "advisory_gap.cve_lag"),
                   f"advisory_gap.cve_lag.{k}")
        if lag[k] > prev:
            _fail(f"advisory_gap.cve_lag.{k}",
                  "must not exceed the shorter threshold's count")
        prev = lag[k]


def _check_eco_map(m: Any, path: str, names: set[str], total: int) -> None:
    if not isinstance(m, dict):
        _fail(path, f"expected object, got {type(m).__name__}")
    s = 0
    for k, v in m.items():
        if k not in names:
            _fail(f"{path}.{k}", "ecosystem missing from ecosystems[]")
        _check_int(v, f"{path}.{k}", minimum=1)
        s += v
    if s != total:
        _fail(path, f"sums to {s}, row total is {total}")


def _validate_registry_malware(obj: Any) -> None:
    _check_generated_at(obj, "registry_malware")
    as_of = _get(obj, "as_of", "registry_malware")
    _check_str(as_of, "registry_malware.as_of", DATE_RE)
    read = _check_list(_get(obj, "ecosystems_read", "registry_malware"),
                       "registry_malware.ecosystems_read")
    for i, e in enumerate(read):
        _check_str(e, f"registry_malware.ecosystems_read[{i}]")

    cat = _get(obj, "catalog", "registry_malware")
    p = "registry_malware.catalog"
    for k in ("reports", "withdrawn", "ecosystems", "peak_reports",
              "this_year"):
        _check_int(_get(cat, k, p), f"{p}.{k}")
    reports = cat["reports"]
    if cat["withdrawn"] > reports:
        _fail(f"{p}.withdrawn", "exceeds reports")
    _pct_of(_get(cat, "withdrawn_pct", p), cat["withdrawn"], reports,
            f"{p}.withdrawn_pct")

    ecos = _check_list(_get(obj, "ecosystems", "registry_malware"),
                       "registry_malware.ecosystems")
    names: set[str] = set()
    prev = None
    rep_sum = wd_sum = 0
    for i, e in enumerate(ecos):
        pe = f"registry_malware.ecosystems[{i}]"
        name = _get(e, "ecosystem", pe)
        _check_str(name, f"{pe}.ecosystem")
        if name in names:
            _fail(f"{pe}.ecosystem", f"duplicate {name!r}")
        names.add(name)
        n = _get(e, "reports", pe)
        _check_int(n, f"{pe}.reports", minimum=1)
        _check_int(_get(e, "withdrawn", pe), f"{pe}.withdrawn")
        if e["withdrawn"] > n:
            _fail(f"{pe}.withdrawn", "exceeds reports")
        _pct_of(_get(e, "withdrawn_pct", pe), e["withdrawn"], n,
                f"{pe}.withdrawn_pct")
        if prev is not None and n > prev:
            _fail("registry_malware.ecosystems",
                  "not sorted by reports descending")
        prev = n
        rep_sum += n
        wd_sum += e["withdrawn"]
    if cat["ecosystems"] != len(ecos):
        _fail(f"{p}.ecosystems", "must equal len(ecosystems)")
    if (rep_sum, wd_sum) != (reports, cat["withdrawn"]):
        _fail("registry_malware.ecosystems",
              "reports/withdrawn must sum to the catalog")

    months = _check_list(_get(obj, "months", "registry_malware"),
                         "registry_malware.months")
    if bool(months) != (reports > 0):
        _fail("registry_malware.months",
              "must be empty exactly when there are no reports")
    labels = []
    m_rep = m_wd = 0
    for i, m in enumerate(months):
        pm = f"registry_malware.months[{i}]"
        label = _get(m, "month", pm)
        _check_str(label, f"{pm}.month", MONTH_RE)
        labels.append(label)
        _check_int(_get(m, "total", pm), f"{pm}.total")
        _check_int(_get(m, "withdrawn", pm), f"{pm}.withdrawn")
        if m["withdrawn"] > m["total"]:
            _fail(f"{pm}.withdrawn", "exceeds total")
        _check_eco_map(_get(m, "by_ecosystem", pm), f"{pm}.by_ecosystem",
                       names, m["total"])
        if _get(m, "partial", pm) is not (label == as_of[:7]):
            _fail(f"{pm}.partial", "must be true exactly for the as_of month")
        m_rep += m["total"]
        m_wd += m["withdrawn"]
    for a, b in zip(labels, labels[1:]):
        ya, ma = int(a[:4]), int(a[5:])
        nxt = f"{ya + (ma == 12):04d}-{ma % 12 + 1:02d}"
        if b != nxt:
            _fail("registry_malware.months",
                  f"months must be consecutive ({a} -> {b})")
    if (m_rep, m_wd) != (reports, cat["withdrawn"]):
        _fail("registry_malware.months",
              "totals/withdrawn must sum to the catalog")
    if months:
        if (_get(cat, "first_month", p), _get(cat, "last_month", p)) != \
                (labels[0], labels[-1]):
            _fail(p, "first_month/last_month must match the months series")
        peak = max(months, key=lambda m: (m["total"], m["month"]))
        if (_get(cat, "peak_month", p), cat["peak_reports"]) != \
                (peak["month"], peak["total"]):
            _fail(p, "peak_month/peak_reports must name the largest month")
        _pct_of(_get(cat, "peak_share_pct", p), peak["total"], reports,
                f"{p}.peak_share_pct")
    median = _get(cat, "median_month", p)
    window = _get(cat, "median_window", p)
    if median is None:
        if window is not None:
            _fail(f"{p}.median_window", "must be null with no median")
    else:
        _check_int(median, f"{p}.median_month")
        window = _check_list(window, f"{p}.median_window")
        if len(window) != 2 or window[0] not in labels or \
                window[1] not in labels or window[0] > window[1]:
            _fail(f"{p}.median_window", "must be [first, last] months held")

    years = _check_list(_get(obj, "years", "registry_malware"),
                        "registry_malware.years")
    y_rep = 0
    for i, y in enumerate(years):
        py = f"registry_malware.years[{i}]"
        yr = _get(y, "year", py)
        _check_int(yr, f"{py}.year", minimum=1990)
        _check_int(_get(y, "total", py), f"{py}.total")
        _check_int(_get(y, "withdrawn", py), f"{py}.withdrawn")
        _check_eco_map(_get(y, "by_ecosystem", py), f"{py}.by_ecosystem",
                       names, y["total"])
        if _get(y, "partial", py) is not (yr == int(as_of[:4])):
            _fail(f"{py}.partial", "must be true exactly for the as_of year")
        want = sum(m["total"] for m in months if m["month"][:4] == str(yr))
        if y["total"] != want:
            _fail(f"{py}.total", f"must equal its months' sum ({want})")
        y_rep += y["total"]
    if y_rep != reports:
        _fail("registry_malware.years", "totals must sum to the catalog")
    this_year = sum(y["total"] for y in years if y["year"] == int(as_of[:4]))
    if cat["this_year"] != this_year:
        _fail(f"{p}.this_year", "must equal the as_of year's total")

    bursts = _check_list(_get(obj, "bursts", "registry_malware"),
                         "registry_malware.bursts")
    by_label = {m["month"]: m for m in months}
    prev = None
    for i, b in enumerate(bursts):
        pb = f"registry_malware.bursts[{i}]"
        label = _get(b, "month", pb)
        if label not in by_label:
            _fail(f"{pb}.month", "not in the months series")
        n = _get(b, "reports", pb)
        if n != by_label[label]["total"] or n < 1:
            _fail(f"{pb}.reports", "must equal that month's total")
        if prev is not None and n > prev:
            _fail("registry_malware.bursts", "not sorted by reports desc")
        prev = n
        _pct_of(_get(b, "share_pct", pb), n, reports, f"{pb}.share_pct")
        _check_str(_get(b, "top_source", pb), f"{pb}.top_source")
        top_n = _get(b, "top_source_reports", pb)
        _check_int(top_n, f"{pb}.top_source_reports", minimum=1)
        if top_n > n:
            _fail(f"{pb}.top_source_reports", "exceeds the month's reports")
        if _get(b, "top_ecosystem", pb) not in by_label[label]["by_ecosystem"]:
            _fail(f"{pb}.top_ecosystem", "not an ecosystem of that month")

    sources = _check_list(_get(obj, "sources", "registry_malware"),
                          "registry_malware.sources")
    prev = None
    s_sum = 0
    for i, s in enumerate(sources):
        ps = f"registry_malware.sources[{i}]"
        _check_str(_get(s, "source", ps), f"{ps}.source")
        n = _get(s, "reports", ps)
        _check_int(n, f"{ps}.reports", minimum=1)
        if n > reports:
            _fail(f"{ps}.reports", "exceeds reports")
        if prev is not None and n > prev:
            _fail("registry_malware.sources", "not sorted by reports desc")
        prev = n
        s_sum += n
    # Every report credits at least one source (or "unattributed").
    if s_sum < reports:
        _fail("registry_malware.sources",
              f"source credits sum to {s_sum}, below {reports} reports")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "advisory_gap.json": _validate_advisory_gap,
    "registry_malware.json": _validate_registry_malware,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the OSV contracts for ``filename``."""
    VALIDATORS[filename](obj)
