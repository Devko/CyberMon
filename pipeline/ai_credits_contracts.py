"""Contract for the ai_credits.json output (AI-credited CVEs).

Same philosophy as pipeline/contracts.py — hand-rolled stdlib validators
that fail loudly — kept in its own module so the stage lands without
touching the core contracts file. The core module's private checking
helpers are reused read-only.

Beyond shape, the contract pins the module's arithmetic: every funnel must
agree with the severity cut it summarizes, monthly lanes are gap-free, a
board row's severity describes exactly its counted CVEs, every board row
and claim must resolve to a committed registry finder, and each claim
carries the measured count it is drawn beside.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .ai_credits_data import (CLAIM_QUALIFIERS, CLAIM_UNIT_KINDS, FINDERS,
                              GROUPS, KINDS, kind_of)
from .ai_credits_metrics import SEVERITIES
from .contracts import (DATE_RE, _check_bool, _check_generated_at, _check_int,
                        _check_list, _check_num, _check_sorted, _check_str,
                        _fail, _get)

MONTH_RE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")
SOURCE_RE = re.compile(r"^https://\S+$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_FINDER_KEYS = {f.key: f for f in FINDERS}


def _check_severity(obj: Any, path: str) -> int:
    if set(obj) != set(SEVERITIES):
        _fail(path, f"keys must be exactly {SEVERITIES}")
    for s in SEVERITIES:
        _check_int(obj[s], f"{path}.{s}")
    return sum(obj.values())


def _check_funnel(funnel: Any, severity: dict, path: str) -> None:
    for k in ("credited", "scored", "high_or_critical", "kev"):
        _check_int(_get(funnel, k, path), f"{path}.{k}")
    for k in ("high_or_critical_pct", "kev_pct"):
        _check_num(_get(funnel, k, path), f"{path}.{k}", 0.0, 100.0)
    total = sum(severity.values())
    if funnel["credited"] != total:
        _fail(f"{path}.credited", "must equal the summed severity cut")
    if funnel["scored"] != total - severity["unscored"]:
        _fail(f"{path}.scored", "must equal credited minus unscored")
    if funnel["high_or_critical"] != severity["critical"] + severity["high"]:
        _fail(f"{path}.high_or_critical", "must equal critical + high")
    if funnel["kev"] > funnel["credited"]:
        _fail(f"{path}.kev", "cannot exceed credited")


def _validate_kind(kind: str, obj: Any, path: str) -> None:
    lanes = _check_list(_get(obj, "lanes", path), f"{path}.lanes")
    if lanes != [g for g in GROUPS if kind_of(g) == kind]:
        _fail(f"{path}.lanes", "must be this kind's registry groups, in order")
    severity = _get(obj, "severity", path)
    total = _check_severity(severity, f"{path}.severity")
    _check_funnel(_get(obj, "funnel", path), severity, f"{path}.funnel")
    kev_cves = _check_list(_get(obj, "kev_cves", path), f"{path}.kev_cves")
    for i, c in enumerate(kev_cves):
        _check_str(c, f"{path}.kev_cves[{i}]", CVE_RE)
    _check_sorted(kev_cves, f"{path}.kev_cves")
    if len(kev_cves) != obj["funnel"]["kev"]:
        _fail(f"{path}.kev_cves", "length must equal funnel.kev")

    months = _check_list(_get(obj, "months", path), f"{path}.months")
    keys = []
    for i, m in enumerate(months):
        mp = f"{path}.months[{i}]"
        _check_str(_get(m, "month", mp), f"{mp}.month", MONTH_RE)
        _check_int(_get(m, "total", mp), f"{mp}.total")
        lane_sum = 0
        for g in lanes:
            _check_int(_get(m, g, mp), f"{mp}.{g}")
            lane_sum += m[g]
        # a CVE ticks every lane it credits, so the lanes may sum past the
        # month's distinct-CVE total but never below it
        if lane_sum < m["total"]:
            _fail(mp, "lanes sum below the month's distinct-CVE total")
        keys.append(m["month"])
    _check_sorted(keys, f"{path}.months (by month)")
    for a, b in zip(keys, keys[1:]):
        y, mo = int(a[:4]), int(a[5:])
        nxt = f"{y + 1:04d}-01" if mo == 12 else f"{y:04d}-{mo + 1:02d}"
        if b != nxt:
            _fail(f"{path}.months", f"gap between {a} and {b}")

    headline = _get(obj, "headline", path)
    if not total:
        if headline is not None or months:
            _fail(f"{path}.headline",
                  "must be null (and months empty) when nothing counts")
        return
    if headline is None:
        _fail(f"{path}.headline", "must be present when CVEs count")
    for k in ("cves", "this_year", "cves_this_year", "finders"):
        _check_int(_get(headline, k, f"{path}.headline"),
                   f"{path}.headline.{k}")
    _check_str(_get(headline, "first_month", f"{path}.headline"),
               f"{path}.headline.first_month", MONTH_RE)
    if headline["cves"] != total:
        _fail(f"{path}.headline.cves", "must equal the summed severity cut")
    if headline["first_month"] != keys[0]:
        _fail(f"{path}.headline.first_month", "must equal months[0].month")
    if headline["cves_this_year"] > headline["cves"]:
        _fail(f"{path}.headline.cves_this_year", "cannot exceed cves")


def _validate_ai_credits(obj: Any) -> None:
    _check_generated_at(obj, "ai_credits")
    kinds = _get(obj, "kinds", "ai_credits")
    if list(kinds) != list(KINDS):
        _fail("ai_credits.kinds", f"keys must be exactly {KINDS}, in order")
    for kind in KINDS:
        _validate_kind(kind, kinds[kind], f"ai_credits.kinds.{kind}")

    board = _check_list(_get(obj, "board", "ai_credits"), "ai_credits.board")
    counted = []
    for i, r in enumerate(board):
        path = f"ai_credits.board[{i}]"
        key = _get(r, "key", path)
        if key not in _FINDER_KEYS:
            _fail(f"{path}.key", f"{key!r} is not in the committed registry")
        finder = _FINDER_KEYS[key]
        if (r.get("label"), r.get("group"), r.get("kind")) != \
                (finder.label, finder.group, kind_of(finder.group)):
            _fail(path, "label/group/kind must match the registry entry")
        for k in ("cves", "counted", "system", "org", "kev"):
            _check_int(_get(r, k, path), f"{path}.{k}")
        if r["cves"] < 1 or r["cves"] != r["system"] + r["org"]:
            _fail(f"{path}.cves", "must be >= 1 and equal system + org")
        if r["counted"] > r["cves"]:
            _fail(f"{path}.counted", "cannot exceed cves")
        if _check_severity(_get(r, "severity", path),
                           f"{path}.severity") != r["counted"]:
            _fail(f"{path}.severity", "must sum to counted")
        if r["kev"] > r["counted"]:
            _fail(f"{path}.kev", "cannot exceed counted")
        for k in ("first_month", "last_month"):
            _check_str(_get(r, k, path), f"{path}.{k}", MONTH_RE)
        if r["first_month"] > r["last_month"]:
            _fail(f"{path}.first_month", "is after last_month")
        cnas = _check_list(_get(r, "top_cnas", path), f"{path}.top_cnas")
        for j, c in enumerate(cnas):
            _check_str(_get(c, "cna", f"{path}.top_cnas[{j}]"),
                       f"{path}.top_cnas[{j}].cna")
            _check_int(_get(c, "n", f"{path}.top_cnas[{j}]"),
                       f"{path}.top_cnas[{j}].n", minimum=1)
        counted.append(r["counted"])
    _check_sorted(counted, "ai_credits.board (by counted)", descending=True)
    if len({r["key"] for r in board}) != len(board):
        _fail("ai_credits.board", "duplicate finder keys")

    coverage = _check_list(_get(obj, "coverage", "ai_credits"),
                           "ai_credits.coverage")
    years = []
    for i, c in enumerate(coverage):
        path = f"ai_credits.coverage[{i}]"
        for k in ("year", "published", "with_credits"):
            _check_int(_get(c, k, path), f"{path}.{k}")
        _check_num(_get(c, "pct", path), f"{path}.pct", 0.0, 100.0)
        if c["with_credits"] > c["published"]:
            _fail(f"{path}.with_credits", "cannot exceed published")
        years.append(c["year"])
    _check_sorted(years, "ai_credits.coverage (by year)")

    # claims: the vendor's own numbers — quoted with a source, tied to a
    # registry finder, and carrying the measured count they sit beside.
    counted_by_key = {r["key"]: r["counted"] for r in board}
    for i, c in enumerate(_check_list(_get(obj, "claims", "ai_credits"),
                                      "ai_credits.claims")):
        path = f"ai_credits.claims[{i}]"
        finder = _get(c, "finder", path)
        if finder not in _FINDER_KEYS:
            _fail(f"{path}.finder", f"{finder!r} is not in the registry")
        if (c.get("label"), c.get("kind")) != (
                _FINDER_KEYS[finder].label,
                kind_of(_FINDER_KEYS[finder].group)):
            _fail(path, "label/kind must match the registry entry")
        _check_int(_get(c, "value", path), f"{path}.value", minimum=1)
        if _get(c, "qualifier", path) not in CLAIM_QUALIFIERS:
            _fail(f"{path}.qualifier", f"must be one of {CLAIM_QUALIFIERS}")
        _check_str(_get(c, "unit", path), f"{path}.unit")
        if _get(c, "unit_kind", path) not in CLAIM_UNIT_KINDS:
            _fail(f"{path}.unit_kind", f"must be one of {CLAIM_UNIT_KINDS}")
        _check_str(_get(c, "date", path), f"{path}.date", DATE_RE)
        _check_bool(_get(c, "live", path), f"{path}.live")
        _check_str(_get(c, "source", path), f"{path}.source", SOURCE_RE)
        if not isinstance(_get(c, "note", path), str):
            _fail(f"{path}.note", "must be a string")
        _check_int(_get(c, "credited", path), f"{path}.credited")
        if c["credited"] != counted_by_key.get(finder, 0):
            _fail(f"{path}.credited", "must equal the board's counted")

    baseline = _get(obj, "baseline", "ai_credits")
    any_headline = any(kinds[k]["headline"] for k in KINDS)
    if not any_headline:
        if baseline is not None:
            _fail("ai_credits.baseline", "must be null when nothing counts")
        return
    if baseline is None:
        _fail("ai_credits.baseline", "must be present when CVEs count")
    _check_str(_get(baseline, "from_month", "ai_credits.baseline"),
               "ai_credits.baseline.from_month", MONTH_RE)
    severity = _get(baseline, "severity", "ai_credits.baseline")
    _check_severity(severity, "ai_credits.baseline.severity")
    _check_funnel(baseline, severity, "ai_credits.baseline")
    firsts = [kinds[k]["headline"]["first_month"] for k in KINDS
              if kinds[k]["headline"]]
    if baseline["from_month"] != min(firsts):
        _fail("ai_credits.baseline.from_month",
              "must be the earliest kind's first_month")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "ai_credits.json": _validate_ai_credits,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the ai_credits contract for ``filename``.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no ai_credits contract.
    """
    VALIDATORS[filename](obj)
