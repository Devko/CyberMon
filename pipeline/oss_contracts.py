"""Contract for Open-Source Maintainers (oss_maintainers.json, module 30).

Hand-rolled like pipeline/contracts.py; merged into its dispatch. Beyond
shapes, it enforces the module's two rules:

* **Per registry, never pooled.** The four registries appear exactly once
  each, in a fixed order, and every count is internally consistent within
  its registry (buckets sum to the measured packages, a top-k reach never
  shrinks as k grows, Scorecard buckets sum to the scored repositories).
* **Aggregates only.** No package name, account name or repository may
  leave the pipeline: every string in the object must be a date, a
  timestamp or one of the fixed labels below. A list of single-account
  packages would be a list of account-takeover targets.
"""
from __future__ import annotations

from typing import Any, Callable

from .contracts import (DATE_RE, ISO_UTC_RE, _check_generated_at, _check_int,
                        _check_list, _check_num, _check_str, _fail, _get)
from .fetch_oss import CHECKS
from .oss_metrics import (ACCOUNT_BUCKET_LABELS, SCORE_BUCKETS, TOP_K)
from .oss_universe import ECOSYSTEMS

_ALLOWED_STRINGS = (set(ECOSYSTEMS) | set(ACCOUNT_BUCKET_LABELS)
                    | set(SCORE_BUCKETS) | set(CHECKS))
_EDITION_RE = __import__("re").compile(r"^\d{4}-\d{2}$")

P = "oss_maintainers"


def _check_pct_or_null(v: Any, path: str, n: int, d: int) -> None:
    if d == 0:
        if v is not None:
            _fail(path, "must be null when the denominator is zero")
        return
    _check_num(v, path, 0.0, 100.0)
    if abs(v - round(100.0 * n / d, 1)) > 1e-9:
        _fail(path, f"{v} is not {n}/{d} rounded to one decimal")


def _check_buckets(obj: Any, path: str, labels, total: int) -> None:
    rows = _check_list(obj, path)
    if [_get(r, "label", f"{path}[{i}]") for i, r in enumerate(rows)] != \
            list(labels):
        _fail(path, f"must carry exactly the labels {list(labels)}")
    s = 0
    for i, r in enumerate(rows):
        _check_int(_get(r, "n", f"{path}[{i}]"), f"{path}[{i}].n")
        s += r["n"]
    if s != total:
        _fail(path, f"buckets sum to {s}, expected {total}")


def _validate_ecosystem(e: Any, path: str, eco: str, per: int) -> None:
    if _get(e, "id", path) != eco:
        _fail(f"{path}.id", f"expected {eco!r}")
    packages = _get(e, "packages", path)
    measured = _get(e, "measured", path)
    missing = _get(e, "missing", path)
    for k, v in (("packages", packages), ("measured", measured),
                 ("missing", missing)):
        _check_int(v, f"{path}.{k}")
    if packages != per:
        _fail(f"{path}.packages", f"must equal universe.per_ecosystem {per}")
    if measured + missing != packages:
        _fail(path, "measured + missing must equal packages")
    if measured < 1:
        _fail(f"{path}.measured", "no package of this registry was measured")

    acc = _get(e, "accounts", path)
    _check_buckets(_get(acc, "buckets", f"{path}.accounts"),
                   f"{path}.accounts.buckets", ACCOUNT_BUCKET_LABELS, measured)
    med = _get(acc, "median", f"{path}.accounts")
    _check_num(med, f"{path}.accounts.median", 0.0, 10_000.0)

    single = _get(e, "single_account", path)
    _check_int(_get(single, "n", f"{path}.single_account"),
               f"{path}.single_account.n")
    one_bucket = next(r["n"] for r in acc["buckets"] if r["label"] == "1")
    if single["n"] > one_bucket:
        _fail(f"{path}.single_account.n",
              f"exceeds the one-account bucket ({one_bucket})")
    _check_pct_or_null(_get(single, "pct", f"{path}.single_account"),
                       f"{path}.single_account.pct", single["n"], measured)
    sole = _get(single, "accounts", f"{path}.single_account")
    largest = _get(single, "largest", f"{path}.single_account")
    _check_int(sole, f"{path}.single_account.accounts")
    _check_int(largest, f"{path}.single_account.largest")
    if not (sole <= single["n"] and largest <= single["n"]
            and (sole == 0) == (single["n"] == 0)
            and (largest == 0) == (single["n"] == 0)
            and largest * sole >= single["n"]):
        _fail(f"{path}.single_account",
              "accounts/largest do not fit the single-account count")
    team = _get(e, "team_or_org", path)
    _check_int(_get(team, "n", f"{path}.team_or_org"), f"{path}.team_or_org.n")
    if team["n"] + single["n"] > measured:
        _fail(f"{path}.team_or_org.n", "single-account and team/org "
                                       "packages overlap or exceed measured")
    _check_pct_or_null(_get(team, "pct", f"{path}.team_or_org"),
                       f"{path}.team_or_org.pct", team["n"], measured)
    zero_bucket = next(r["n"] for r in acc["buckets"] if r["label"] == "0")
    if zero_bucket > team["n"]:
        _fail(f"{path}.accounts.buckets",
              "a package with no account must have a team or organisation")

    shared = _get(e, "shared", path)
    distinct = _get(shared, "distinct_accounts", f"{path}.shared")
    _check_int(distinct, f"{path}.shared.distinct_accounts", minimum=1)
    top = _check_list(_get(shared, "top", f"{path}.shared"),
                      f"{path}.shared.top")
    if [_get(t, "k", f"{path}.shared.top[{i}]") for i, t in enumerate(top)] \
            != list(TOP_K):
        _fail(f"{path}.shared.top", f"k must be exactly {list(TOP_K)}")
    prev = 0
    for i, t in enumerate(top):
        tp = f"{path}.shared.top[{i}]"
        _check_int(_get(t, "n", tp), f"{tp}.n", minimum=1)
        if t["n"] < prev or t["n"] > measured:
            _fail(f"{tp}.n", "reach must grow with k and stay within the "
                             "measured packages")
        prev = t["n"]
        _check_pct_or_null(_get(t, "pct", tp), f"{tp}.pct", t["n"], measured)

    sc = _get(e, "scorecard", path)
    sp = f"{path}.scorecard"
    for k in ("github_packages", "repos", "scored", "old_results"):
        _check_int(_get(sc, k, sp), f"{sp}.{k}")
    if not sc["scored"] + sc["old_results"] <= sc["repos"] \
            <= sc["github_packages"] <= measured:
        _fail(sp, "need scored + old_results <= repos <= github_packages "
                  "<= measured")
    ms = _get(sc, "median_score", sp)
    if (ms is None) != (sc["scored"] == 0):
        _fail(f"{sp}.median_score", "null exactly when nothing is scored")
    if ms is not None:
        _check_num(ms, f"{sp}.median_score", 0.0, 10.0)
    checks = _get(sc, "checks", sp)
    not_rep = _get(sc, "not_reported", sp)
    if not isinstance(checks, dict) or set(checks) != set(CHECKS):
        _fail(f"{sp}.checks", f"must hold exactly {list(CHECKS)}")
    if not isinstance(not_rep, dict) or set(not_rep) != set(CHECKS):
        _fail(f"{sp}.not_reported", f"must hold exactly {list(CHECKS)}")
    for check in CHECKS:
        _check_int(not_rep[check], f"{sp}.not_reported.{check}")
        _check_buckets(checks[check], f"{sp}.checks.{check}", SCORE_BUCKETS,
                       sc["scored"] - not_rep[check])


def _scan_strings(node: Any, path: str) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            _scan_strings(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _scan_strings(v, f"{path}[{i}]")
    elif isinstance(node, str):
        if node in _ALLOWED_STRINGS or DATE_RE.match(node) or \
                ISO_UTC_RE.match(node) or _EDITION_RE.match(node):
            return
        _fail(path, f"string {node!r} is not a fixed label — package, "
                    f"account and repository names must never be emitted")


def _validate_oss_maintainers(obj: Any) -> None:
    _check_generated_at(obj, P)
    uni = _get(obj, "universe", P)
    edition = _get(uni, "edition", f"{P}.universe")
    _check_str(edition, f"{P}.universe.edition", _EDITION_RE)
    _check_int(_get(uni, "rule_version", f"{P}.universe"),
               f"{P}.universe.rule_version", minimum=1)
    _check_str(_get(uni, "selected_at", f"{P}.universe"),
               f"{P}.universe.selected_at", DATE_RE)
    per = _get(uni, "per_ecosystem", f"{P}.universe")
    _check_int(per, f"{P}.universe.per_ecosystem", minimum=1)
    _check_int(_get(uni, "download_floor", f"{P}.universe"),
               f"{P}.universe.download_floor", minimum=1)

    obs = _get(obj, "observed", P)
    first = _get(obs, "first", f"{P}.observed")
    last = _get(obs, "last", f"{P}.observed")
    _check_str(first, f"{P}.observed.first", DATE_RE)
    _check_str(last, f"{P}.observed.last", DATE_RE)
    if not first <= last <= obj["generated_at"][:10]:
        _fail(f"{P}.observed", "need first <= last <= the edition date")
    _check_int(_get(obs, "refresh_days", f"{P}.observed"),
               f"{P}.observed.refresh_days", minimum=1)
    max_age = _get(obs, "max_age_days", f"{P}.observed")
    _check_int(max_age, f"{P}.observed.max_age_days", minimum=1)
    # A carried-forward (stale) edition keeps its own observation dates,
    # which then lag the restamped generated_at; only a fresh edition must
    # hold the age rule.
    if obj.get("stale") is not True:
        from datetime import date
        age = (date.fromisoformat(obj["generated_at"][:10])
               - date.fromisoformat(first)).days
        if age > max_age:
            _fail(f"{P}.observed.first", f"{age} days old, over the "
                                         f"{max_age}-day publishing rule")

    dates = _get(obj, "scorecard_dates", P)
    sc_age = _get(dates, "max_age_days", f"{P}.scorecard_dates")
    _check_int(sc_age, f"{P}.scorecard_dates.max_age_days", minimum=1)
    for k in ("first", "last"):
        v = _get(dates, k, f"{P}.scorecard_dates")
        if v is not None:
            _check_str(v, f"{P}.scorecard_dates.{k}", DATE_RE)

    ecos = _check_list(_get(obj, "ecosystems", P), f"{P}.ecosystems")
    if [_get(e, "id", f"{P}.ecosystems[{i}]") for i, e in enumerate(ecos)] \
            != list(ECOSYSTEMS):
        _fail(f"{P}.ecosystems", f"must list exactly {list(ECOSYSTEMS)} "
                                 f"in that order")
    any_scored = False
    for i, (eco, e) in enumerate(zip(ECOSYSTEMS, ecos)):
        _validate_ecosystem(e, f"{P}.ecosystems[{i}]", eco, per)
        any_scored = any_scored or e["scorecard"]["scored"] > 0
    if (dates["first"] is None) != (not any_scored) or \
            (dates["last"] is None) != (not any_scored):
        _fail(f"{P}.scorecard_dates", "null exactly when nothing is scored")
    if any_scored and not (dates["first"] <= dates["last"]
                           <= obj["generated_at"][:10]):
        _fail(f"{P}.scorecard_dates", "need first <= last <= the edition")
    if any_scored and obj.get("stale") is not True:
        from datetime import date
        age = (date.fromisoformat(obj["generated_at"][:10])
               - date.fromisoformat(dates["first"])).days
        if age > sc_age:
            _fail(f"{P}.scorecard_dates.first",
                  f"a scored result is {age} days old, over {sc_age}")

    _scan_strings(obj, P)


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "oss_maintainers.json": _validate_oss_maintainers,
}


def validate(filename: str, obj: Any) -> None:
    VALIDATORS[filename](obj)
