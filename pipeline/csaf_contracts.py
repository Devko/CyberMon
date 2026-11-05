"""Contract for the Machine-Readable Advisories output (csaf_adoption.json).

Same philosophy as pipeline/contracts.py — a hand-rolled stdlib validator
that fails loudly — kept in its own module (the botnet_contracts
precedent). Every partition must add up: a source's year counts plus its
undated documents equal its documents, its category mix equals its
documents, the year series equals the sum over sources, and the totals
equal the sum over rows. A source that was not measured carries no
documents and no field shares.
"""
from __future__ import annotations

from typing import Any, Callable

from .contracts import (DATE_RE, _check_generated_at, _check_int,
                        _check_list, _check_num, _check_str, _fail, _get)
from .csaf_metrics import GROUPS, STATUSES, _sort_key
from .fetch_csaf import FIELDS

KINDS = ("provider", "publisher")
MEASURED = ("measured", "carried")


def _check_pct_or_none(v: Any, path: str) -> None:
    if v is not None:
        _check_num(v, path, 0.0, 100.0)


def _check_by_year(rows: Any, path: str) -> int:
    rows = _check_list(rows, path)
    years = []
    total = 0
    for i, r in enumerate(rows):
        p = f"{path}[{i}]"
        y = _get(r, "year", p)
        _check_int(y, f"{p}.year", minimum=1990)
        n = _get(r, "n", p)
        _check_int(n, f"{p}.n", minimum=1)
        years.append(y)
        total += n
    if years != sorted(set(years)):
        _fail(path, "years must be unique and ascending")
    return total


def _check_row(r: Any, path: str, k: int) -> None:
    for key in ("name", "category"):
        _check_str(_get(r, key, path), f"{path}.{key}")
    if not isinstance(_get(r, "role", path), str):
        _fail(f"{path}.role", "expected string")
    if _get(r, "kind", path) not in KINDS:
        _fail(f"{path}.kind", f"must be one of {KINDS}")
    status = _get(r, "status", path)
    if status not in STATUSES:
        _fail(f"{path}.status", f"must be one of {STATUSES}")
    if not isinstance(_get(r, "detail", path), str):
        _fail(f"{path}.detail", "expected string")
    measured_on = _get(r, "measured_on", path)
    docs = _get(r, "documents", path)
    _check_int(docs, f"{path}.documents")
    undated = _get(r, "undated", path)
    _check_int(undated, f"{path}.undated")
    dated = _check_by_year(_get(r, "by_year", path), f"{path}.by_year")
    if dated + undated != docs:
        _fail(path, f"by_year ({dated}) + undated ({undated}) != documents "
                    f"({docs})")
    first, last = _get(r, "first_year", path), _get(r, "last_year", path)
    if r["by_year"]:
        if first != r["by_year"][0]["year"] or last != r["by_year"][-1]["year"]:
            _fail(path, "first_year/last_year must bound by_year")
    elif first is not None or last is not None:
        _fail(path, "first_year/last_year must be null without by_year")
    mix = _get(r, "mix", path)
    if not isinstance(mix, dict) or set(mix) != set(GROUPS):
        _fail(f"{path}.mix", f"keys must be {GROUPS}")
    for g in GROUPS:
        _check_int(mix[g], f"{path}.mix.{g}")
    if sum(mix.values()) != docs:
        _fail(f"{path}.mix", f"sums to {sum(mix.values())}, documents "
                             f"{docs}")
    sample_n = _get(r, "sample_n", path)
    _check_int(sample_n, f"{path}.sample_n")
    if sample_n > docs:
        _fail(f"{path}.sample_n", "exceeds documents")
    fields = _get(r, "fields", path)
    if status in MEASURED:
        _check_str(measured_on, f"{path}.measured_on", DATE_RE)
        if docs < 1:
            _fail(path, "a measured source has at least one document")
        if fields is None:
            if sample_n:
                _fail(f"{path}.fields", "sampled source without field shares")
        else:
            if not isinstance(fields, dict) or set(fields) != set(FIELDS):
                _fail(f"{path}.fields", f"keys must be {FIELDS}")
            for f in FIELDS:
                _check_num(fields[f], f"{path}.fields.{f}", 0.0, 100.0)
    else:
        if measured_on is not None or docs or sample_n or fields is not None:
            _fail(path, f"a source with status {status!r} carries no "
                        f"documents, sample or measurement date")
    groups = r.get("sample_groups", {})
    if not isinstance(groups, dict):
        _fail(f"{path}.sample_groups", "expected object")
    pooled = 0
    for g, tally in groups.items():
        if g not in GROUPS:
            _fail(f"{path}.sample_groups.{g}", "unknown group")
        n = _get(tally, "n", f"{path}.sample_groups.{g}")
        _check_int(n, f"{path}.sample_groups.{g}.n", minimum=1)
        for f in FIELDS:
            c = _get(tally, f, f"{path}.sample_groups.{g}")
            _check_int(c, f"{path}.sample_groups.{g}.{f}")
            if c > n:
                _fail(f"{path}.sample_groups.{g}.{f}", "exceeds n")
        pooled += n
    if pooled != sample_n:
        _fail(f"{path}.sample_groups", f"sums to {pooled}, sample_n "
                                       f"{sample_n}")


def _validate_csaf_adoption(obj: Any) -> None:
    _check_generated_at(obj, "csaf_adoption")
    year = _get(obj, "current_year", "csaf_adoption")
    edition_year = int(obj["generated_at"][:4])
    # A carried-forward edition is restamped with tonight's generated_at but
    # keeps the year it was measured in (a lister outage over New Year must
    # not fail the run the carry-forward exists to save).
    if year != edition_year and not (obj.get("stale") is True
                                     and isinstance(year, int)
                                     and year < edition_year):
        _fail("csaf_adoption.current_year", "must be the edition's year")
    sampling = _get(obj, "sampling", "csaf_adoption")
    k = _get(sampling, "k", "csaf_adoption.sampling")
    _check_int(k, "csaf_adoption.sampling.k", minimum=1)
    for key in ("new_cap", "refresh_cap"):
        _check_int(_get(sampling, key, "csaf_adoption.sampling"),
                   f"csaf_adoption.sampling.{key}")
    _check_num(_get(sampling, "nearly_all_pct", "csaf_adoption.sampling"),
               "csaf_adoption.sampling.nearly_all_pct", 0.0, 100.0)

    rows = _check_list(_get(obj, "sources", "csaf_adoption"),
                       "csaf_adoption.sources")
    if not rows:
        _fail("csaf_adoption.sources", "the lister names at least one source")
    names = set()
    for i, r in enumerate(rows):
        _check_row(r, f"csaf_adoption.sources[{i}]", k)
        if r["name"] in names:
            _fail(f"csaf_adoption.sources[{i}].name", "duplicate source")
        names.add(r["name"])
    if [_sort_key(r) for r in rows] != sorted(_sort_key(r) for r in rows):
        _fail("csaf_adoption.sources", "must be sorted: measured first, "
                                       "by documents descending")

    lister = _get(obj, "lister", "csaf_adoption")
    _check_str(_get(lister, "name", "csaf_adoption.lister"),
               "csaf_adoption.lister.name")
    _check_str(_get(lister, "url", "csaf_adoption.lister"),
               "csaf_adoption.lister.url")
    listed = _get(lister, "listed", "csaf_adoption.lister")
    if listed != len(rows):
        _fail("csaf_adoption.lister.listed", "must equal len(sources)")
    for kind, key in (("provider", "providers"), ("publisher", "publishers")):
        if _get(lister, key, "csaf_adoption.lister") != \
                sum(1 for r in rows if r["kind"] == kind):
            _fail(f"csaf_adoption.lister.{key}", "count mismatch")

    measured = [r for r in rows if r["status"] in MEASURED]
    expect: dict[int, list[int]] = {}
    for r in measured:
        for y in r["by_year"]:
            e = expect.setdefault(y["year"], [0, 0])
            e[0] += y["n"]
            e[1] += 1
    years = _check_list(_get(obj, "years", "csaf_adoption"),
                        "csaf_adoption.years")
    got = {}
    for i, y in enumerate(years):
        p = f"csaf_adoption.years[{i}]"
        _check_int(_get(y, "year", p), f"{p}.year", minimum=1990)
        _check_int(_get(y, "n", p), f"{p}.n", minimum=1)
        _check_int(_get(y, "providers", p), f"{p}.providers", minimum=1)
        got[y["year"]] = [y["n"], y["providers"]]
    if [y["year"] for y in years] != sorted(got):
        _fail("csaf_adoption.years", "years must be unique and ascending")
    if got != expect:
        _fail("csaf_adoption.years", "must equal the sum over measured "
                                     "sources")

    t = _get(obj, "totals", "csaf_adoption")
    docs = sum(r["documents"] for r in rows)
    checks = {
        "listed": len(rows), "measured": len(measured),
        "carried": sum(1 for r in rows if r["status"] == "carried"),
        "unmeasured": len(rows) - len(measured), "documents": docs,
        "undated": sum(r["undated"] for r in rows),
    }
    for key, want in checks.items():
        if _get(t, key, "csaf_adoption.totals") != want:
            _fail(f"csaf_adoption.totals.{key}", f"must be {want}")
    mix = _get(t, "mix", "csaf_adoption.totals")
    for g in GROUPS:
        if _get(mix, g, "csaf_adoption.totals.mix") != \
                sum(r["mix"][g] for r in rows):
            _fail(f"csaf_adoption.totals.mix.{g}", "must equal the row sum")
    for key in ("vex_pct", "top_share_pct", "vex_top_share_pct"):
        _check_pct_or_none(_get(t, key, "csaf_adoption.totals"),
                           f"csaf_adoption.totals.{key}")
    for key in ("top_name", "vex_top_name"):
        v = _get(t, key, "csaf_adoption.totals")
        if v is not None and v not in names:
            _fail(f"csaf_adoption.totals.{key}", "not a listed source")
    by_group = _get(t, "by_group", "csaf_adoption.totals")
    for g, e in by_group.items():
        if g not in GROUPS:
            _fail(f"csaf_adoption.totals.by_group.{g}", "unknown group")
        _check_int(_get(e, "n", f"csaf_adoption.totals.by_group.{g}"),
                   f"csaf_adoption.totals.by_group.{g}.n", minimum=1)
        for f in FIELDS:
            _check_pct_or_none(_get(e, f, f"csaf_adoption.totals.by_group.{g}"),
                               f"csaf_adoption.totals.by_group.{g}.{f}")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "csaf_adoption.json": _validate_csaf_adoption,
}
