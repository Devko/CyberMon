"""Contract for the Detection Rules output (sigma_coverage.json).

Same philosophy as pipeline/contracts.py — a hand-rolled stdlib validator
that fails loudly — kept in its own module so the stage lands without
reshaping the core contracts file. Failures raise
:class:`pipeline.contracts.ContractViolation`.

The internal-consistency checks are deliberately strong: every per-quarter,
per-year, per-cohort and per-tactic figure derives from the same rule set
and technique table, so totals MUST agree.

One red-line check lives here too: the module republishes counts, never
rules. No string in the emitted object may look like a Sigma rule id (a
UUID), and no object may carry a rule ``title``, ``author`` or
``detection`` key.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .contracts import (DATE_RE, _check_bool, _check_generated_at,
                        _check_int, _check_list, _check_num, _check_sorted,
                        _check_str, _fail, _get)
from .fetch_attack import version_key
from .sigma_metrics import LAG_BUCKETS

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_QUARTER_RE = re.compile(r"^(\d{4})Q([1-4])$")
_TECH_RE = re.compile(r"^T\d{4}$")
_ANY_TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_VERSION_RE = re.compile(r"^\d+\.\d+$")
_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_RULE_KEYS = {"title", "author", "detection", "logsource", "falsepositives"}


def _check_pct(obj: dict, path: str, num: str, den: str) -> None:
    pct = _get(obj, "pct", path)
    n, d = obj[num], obj[den]
    if d == 0:
        if pct is not None:
            _fail(f"{path}.pct", "must be null when the denominator is 0")
        return
    _check_num(pct, f"{path}.pct", 0.0, 100.0)
    if abs(pct - 100.0 * n / d) > 0.05 + 1e-9:
        _fail(f"{path}.pct", f"{pct} != 100 * {n}/{d}")


def _no_rule_content(node: Any, path: str) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if k in _RULE_KEYS:
                _fail(f"{path}.{k}", "rule content in the emitted file — the "
                                     "module publishes counts, never rules")
            _no_rule_content(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _no_rule_content(v, f"{path}[{i}]")
    elif isinstance(node, str) and _UUID_RE.search(node):
        _fail(path, f"{node!r} looks like a Sigma rule id")


def _validate_sigma_coverage(obj: Any) -> None:
    p = "sigma_coverage"
    _check_generated_at(obj, p)
    # Partial flags and follow-ups are measured to as_of, which a
    # carried-forward edition keeps while generated_at is restamped.
    today = _get(obj, "as_of", p)
    _check_str(today, f"{p}.as_of", DATE_RE)
    if today > obj["generated_at"][:10]:
        _fail(f"{p}.as_of", "after generated_at")
    _no_rule_content(obj, p)

    src = _get(obj, "source", p)
    _check_str(_get(src, "commit", f"{p}.source"), f"{p}.source.commit",
               _SHA_RE)
    _check_str(_get(src, "commit_date", f"{p}.source"),
               f"{p}.source.commit_date", DATE_RE)

    # ---- catalog -------------------------------------------------------------
    cat = _get(obj, "catalog", p)
    for k in ("rules", "active", "deprecated", "technique_tagged", "mapped",
              "active_mapped", "files", "skipped", "future_dated"):
        _check_int(_get(cat, k, f"{p}.catalog"), f"{p}.catalog.{k}")
    if cat["rules"] < 1:
        _fail(f"{p}.catalog.rules", "no rules")
    if cat["active"] + cat["deprecated"] != cat["rules"]:
        _fail(f"{p}.catalog", "active + deprecated != rules")
    if not cat["mapped"] <= cat["technique_tagged"] <= cat["rules"]:
        _fail(f"{p}.catalog", "mapped <= technique_tagged <= rules violated")
    if cat["active_mapped"] > min(cat["mapped"], cat["active"]):
        _fail(f"{p}.catalog.active_mapped", "exceeds mapped or active")
    if cat["skipped"] > cat["files"] or \
            cat["files"] != cat["rules"] + cat["skipped"] + cat["future_dated"]:
        _fail(f"{p}.catalog", "files != rules + skipped + future_dated")
    _check_str(_get(cat, "first_rule_date", f"{p}.catalog"),
               f"{p}.catalog.first_rule_date", DATE_RE)
    _check_str(_get(cat, "first_quarter", f"{p}.catalog"),
               f"{p}.catalog.first_quarter", _QUARTER_RE)

    # ---- attack join -----------------------------------------------------------
    atk = _get(obj, "attack", p)
    synced = _check_list(_get(atk, "synced", f"{p}.attack"),
                         f"{p}.attack.synced")
    if not synced:
        _fail(f"{p}.attack.synced", "empty")
    for i, v in enumerate(synced):
        _check_str(v, f"{p}.attack.synced[{i}]", _VERSION_RE)
    _check_sorted([version_key(v) for v in synced], f"{p}.attack.synced")
    if len(set(synced)) != len(synced):
        _fail(f"{p}.attack.synced", "duplicate version")
    if _get(atk, "version", f"{p}.attack") != synced[-1]:
        _fail(f"{p}.attack.version", "must be the last synced release")
    if _get(atk, "first_version", f"{p}.attack") != synced[0]:
        _fail(f"{p}.attack.first_version", "must be the first synced release")
    for k in ("released", "first_released"):
        _check_str(_get(atk, k, f"{p}.attack"), f"{p}.attack.{k}", DATE_RE)
    tactic_ids = []
    for i, t in enumerate(_check_list(_get(atk, "tactics", f"{p}.attack"),
                                      f"{p}.attack.tactics")):
        _check_str(_get(t, "id", f"{p}.attack.tactics[{i}]"),
                   f"{p}.attack.tactics[{i}].id")
        _check_str(_get(t, "name", f"{p}.attack.tactics[{i}]"),
                   f"{p}.attack.tactics[{i}].name")
        tactic_ids.append(t["id"])
    if len(set(tactic_ids)) != len(tactic_ids):
        _fail(f"{p}.attack.tactics", "duplicate tactic id")
    revoked = _get(atk, "revoked_to", f"{p}.attack")
    if not isinstance(revoked, dict):
        _fail(f"{p}.attack.revoked_to", "expected object")
    for k, v in revoked.items():
        if not (_ANY_TECH_RE.match(k) and isinstance(v, str)
                and _ANY_TECH_RE.match(v)):
            _fail(f"{p}.attack.revoked_to.{k}", f"bad mapping -> {v!r}")

    # ---- techniques ------------------------------------------------------------
    techs = _check_list(_get(obj, "techniques", p), f"{p}.techniques")
    ids: set[str] = set()
    covered_now = 0
    for i, t in enumerate(techs):
        tp = f"{p}.techniques[{i}]"
        _check_str(_get(t, "id", tp), f"{tp}.id", _TECH_RE)
        if t["id"] in ids:
            _fail(f"{tp}.id", f"duplicate {t['id']}")
        ids.add(t["id"])
        _check_str(_get(t, "name", tp), f"{tp}.name")
        for j, tac in enumerate(_check_list(_get(t, "tactics", tp),
                                            f"{tp}.tactics")):
            if tac not in tactic_ids:
                _fail(f"{tp}.tactics[{j}]", f"unknown tactic {tac!r}")
        if _get(t, "debut", tp) not in synced:
            _fail(f"{tp}.debut", f"{t['debut']!r} is not a synced release")
        _check_str(_get(t, "debut_date", tp), f"{tp}.debut_date", DATE_RE)
        first = _get(t, "first_rule", tp)
        if first is not None:
            _check_str(first, f"{tp}.first_rule", DATE_RE)
            if first > today:
                _fail(f"{tp}.first_rule", "after the edition date")
        _check_int(_get(t, "rules", tp), f"{tp}.rules")
        if t["rules"] > 0:
            covered_now += 1
            if first is None:
                _fail(tp, "has rules but no first_rule date")
    retired_ids: set[str] = set()
    for i, t in enumerate(_check_list(_get(obj, "retired_techniques", p),
                                      f"{p}.retired_techniques")):
        tp = f"{p}.retired_techniques[{i}]"
        _check_str(_get(t, "id", tp), f"{tp}.id", _TECH_RE)
        if t["id"] in ids or t["id"] in retired_ids:
            _fail(f"{tp}.id", f"{t['id']} listed twice")
        retired_ids.add(t["id"])
        for k in ("debut", "retired"):
            if _get(t, k, tp) not in synced:
                _fail(f"{tp}.{k}", f"{t[k]!r} is not a synced release")
        if version_key(t["retired"]) <= version_key(t["debut"]):
            _fail(tp, "retired no later than its debut")

    # ---- coverage today --------------------------------------------------------
    cov = _get(obj, "coverage", p)
    _check_int(_get(cov, "techniques", f"{p}.coverage"),
               f"{p}.coverage.techniques")
    _check_int(_get(cov, "covered", f"{p}.coverage"), f"{p}.coverage.covered")
    if cov["techniques"] != len(techs):
        _fail(f"{p}.coverage.techniques", "!= len(techniques)")
    if cov["covered"] != covered_now:
        _fail(f"{p}.coverage.covered", "!= techniques with rules > 0")
    _check_pct(cov, f"{p}.coverage", "covered", "techniques")

    # ---- quarters --------------------------------------------------------------
    quarters = _check_list(_get(obj, "quarters", p), f"{p}.quarters")
    if not quarters:
        _fail(f"{p}.quarters", "empty")
    if quarters[0]["quarter"] != cat["first_quarter"]:
        _fail(f"{p}.quarters[0]", "does not start at catalog.first_quarter")
    prev = None
    added = deprecated = 0
    for i, row in enumerate(quarters):
        qp = f"{p}.quarters[{i}]"
        label = _get(row, "quarter", qp)
        m = _QUARTER_RE.match(label) if isinstance(label, str) else None
        if not m:
            _fail(f"{qp}.quarter", f"bad label {label!r}")
        key = (int(m.group(1)), int(m.group(2)))
        if prev is not None:
            want = (prev[0] + 1, 1) if prev[1] == 4 else (prev[0], prev[1] + 1)
            if key != want:
                _fail(f"{qp}.quarter", f"gap after {prev}: {label}")
        prev = key
        for k in ("start", "end"):
            _check_str(_get(row, k, qp), f"{qp}.{k}", DATE_RE)
        _check_bool(_get(row, "partial", qp), f"{qp}.partial")
        if row["partial"] != (i == len(quarters) - 1 and row["end"] > today):
            _fail(f"{qp}.partial", "only the current quarter may be partial")
        for k in ("added", "deprecated", "techniques", "covered"):
            _check_int(_get(row, k, qp), f"{qp}.{k}")
        if row["covered"] > row["techniques"]:
            _fail(f"{qp}.covered", "exceeds techniques")
        if row["techniques"] > len(techs):
            _fail(f"{qp}.techniques", "exceeds today's technique list")
        _check_pct(row, qp, "covered", "techniques")
        added += row["added"]
        deprecated += row["deprecated"]
    if not quarters[-1]["start"] <= today <= quarters[-1]["end"]:
        _fail(f"{p}.quarters", "does not end with the edition's quarter")
    if added != cat["rules"]:
        _fail(f"{p}.quarters", f"added sums to {added}, catalog has "
                               f"{cat['rules']} rules")
    if deprecated > cat["deprecated"]:
        _fail(f"{p}.quarters", "deprecated exceeds catalog.deprecated")
    last = quarters[-1]
    if (last["techniques"], last["covered"]) != (cov["techniques"],
                                                 cov["covered"]):
        _fail(f"{p}.quarters[-1]", "current quarter disagrees with coverage")
    peak = _get(cov, "peak", f"{p}.coverage")
    shares = [r["pct"] for r in quarters if r["pct"] is not None]
    if shares:
        if not isinstance(peak, dict):
            _fail(f"{p}.coverage.peak", "missing")
        if peak["pct"] != max(shares):
            _fail(f"{p}.coverage.peak.pct", "is not the series maximum")
        match = [r for r in quarters if r["quarter"] == peak.get("quarter")]
        if not match or match[0]["pct"] != peak["pct"]:
            _fail(f"{p}.coverage.peak.quarter", "does not match its quarter")
    elif peak is not None:
        _fail(f"{p}.coverage.peak", "must be null when no quarter has a percentage")

    # ---- years -----------------------------------------------------------------
    years = _check_list(_get(obj, "years", p), f"{p}.years")
    ys = []
    y_added = y_dep = 0
    for i, row in enumerate(years):
        yp = f"{p}.years[{i}]"
        _check_int(_get(row, "year", yp), f"{yp}.year", minimum=2000)
        ys.append(row["year"])
        _check_bool(_get(row, "partial", yp), f"{yp}.partial")
        if row["partial"] != (row["year"] == int(today[:4])):
            _fail(f"{yp}.partial", "only the edition year is partial")
        for k in ("added", "deprecated"):
            _check_int(_get(row, k, yp), f"{yp}.{k}")
        y_added += row["added"]
        y_dep += row["deprecated"]
    if not ys or ys != list(range(ys[0], ys[0] + len(ys))):
        _fail(f"{p}.years", "years must be contiguous and non-empty")
    if (y_added, y_dep) != (added, deprecated):
        _fail(f"{p}.years", "year totals disagree with the quarters")

    # ---- lag -------------------------------------------------------------------
    lag = _get(obj, "lag", p)
    lp = f"{p}.lag"
    for k in ("follow_up_days", "n", *LAG_BUCKETS):
        _check_int(_get(lag, k, lp), f"{lp}.{k}")
    if sum(lag[k] for k in LAG_BUCKETS) != lag["n"]:
        _fail(lp, "buckets do not sum to n")
    if _get(lag, "debut_after", lp) != synced[0]:
        _fail(f"{lp}.debut_after", "must be the first synced release")
    _check_str(_get(lag, "debut_through", lp), f"{lp}.debut_through",
               DATE_RE)
    exact = _get(lag, "median_exact", lp)
    _check_bool(exact, f"{lp}.median_exact")
    md, ml = _get(lag, "median_days", lp), _get(lag, "median_at_least_days",
                                                lp)
    if lag["n"] == 0:
        if md is not None or ml is not None or exact:
            _fail(lp, "an empty cohort has no median")
    elif exact:
        _check_int(md, f"{lp}.median_days")
        if ml is not None:
            _fail(f"{lp}.median_at_least_days", "must be null when exact")
    else:
        _check_int(ml, f"{lp}.median_at_least_days")
        if md is not None:
            _fail(f"{lp}.median_days", "must be null when not exact")

    cohorts = _check_list(_get(obj, "cohorts", p), f"{p}.cohorts")
    c_years = []
    for i, row in enumerate(cohorts):
        cp = f"{p}.cohorts[{i}]"
        _check_int(_get(row, "year", cp), f"{cp}.year", minimum=2000)
        c_years.append(row["year"])
        for k in ("techniques", "min_follow_up_days", *LAG_BUCKETS):
            _check_int(_get(row, k, cp), f"{cp}.{k}")
        if sum(row[k] for k in LAG_BUCKETS) != row["techniques"]:
            _fail(cp, "buckets do not sum to techniques")
        _check_bool(_get(row, "full_year", cp), f"{cp}.full_year")
        if row["full_year"] != (row["min_follow_up_days"] >= 365):
            _fail(f"{cp}.full_year", "disagrees with min_follow_up_days")
    _check_sorted(c_years, f"{p}.cohorts")
    if len(set(c_years)) != len(c_years):
        _fail(f"{p}.cohorts", "duplicate year")
    later = sum(1 for t in techs if t["debut"] != synced[0])
    if sum(r["techniques"] for r in cohorts) != later:
        _fail(f"{p}.cohorts", "cohorts do not cover every later debut")
    if lag["n"] > later:
        _fail(f"{lp}.n", "exceeds the techniques that debuted later")

    # ---- tactics ---------------------------------------------------------------
    seen = set()
    for i, row in enumerate(_check_list(_get(obj, "tactics", p),
                                        f"{p}.tactics")):
        tp = f"{p}.tactics[{i}]"
        if _get(row, "id", tp) not in tactic_ids or row["id"] in seen:
            _fail(f"{tp}.id", f"unknown or repeated tactic {row['id']!r}")
        seen.add(row["id"])
        _check_str(_get(row, "name", tp), f"{tp}.name")
        _check_int(_get(row, "techniques", tp), f"{tp}.techniques", minimum=1)
        _check_int(_get(row, "covered", tp), f"{tp}.covered")
        if row["covered"] > row["techniques"]:
            _fail(f"{tp}.covered", "exceeds techniques")
        _check_pct(row, tp, "covered", "techniques")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "sigma_coverage.json": _validate_sigma_coverage,
}
