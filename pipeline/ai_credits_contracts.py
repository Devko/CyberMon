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
                              GROUPS, KINDS, TIERS, WEAKNESS_KEYS,
                              WEAKNESS_LABELS, counts_toward_headline,
                              kind_of)
from .ai_credits_metrics import (POPULATIONS, RECENT_DAYS, SEVERITIES,
                                 TOP_SHARE_N, TOP_TARGETS)
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
    for k in ("credited", "scored", "high_or_critical", "poc", "kev"):
        _check_int(_get(funnel, k, path), f"{path}.{k}")
    for k in ("high_or_critical_pct", "poc_pct", "kev_pct"):
        _check_num(_get(funnel, k, path), f"{path}.{k}", 0.0, 100.0)
    total = sum(severity.values())
    if funnel["credited"] != total:
        _fail(f"{path}.credited", "must equal the summed severity cut")
    if funnel["scored"] != total - severity["unscored"]:
        _fail(f"{path}.scored", "must equal credited minus unscored")
    if funnel["high_or_critical"] != severity["critical"] + severity["high"]:
        _fail(f"{path}.high_or_critical", "must equal critical + high")
    for k in ("poc", "kev"):
        if funnel[k] > funnel["credited"]:
            _fail(f"{path}.{k}", "cannot exceed credited")


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
        for k in ("cves", "counted", *TIERS, "poc", "kev"):
            _check_int(_get(r, k, path), f"{path}.{k}")
        if r["cves"] < 1 or r["cves"] != sum(r[t] for t in TIERS):
            _fail(f"{path}.cves", f"must be >= 1 and equal the sum of {TIERS}")
        # counted is exactly the tiers the kind's rule admits — a fix credit
        # (patch, not find) can never be part of it
        if r["counted"] != sum(r[t] for t in TIERS
                               if counts_toward_headline(finder.group, t)):
            _fail(f"{path}.counted",
                  "must equal the tiers this finder's kind counts")
        if _check_severity(_get(r, "severity", path),
                           f"{path}.severity") != r["counted"]:
            _fail(f"{path}.severity", "must sum to counted")
        for k in ("poc", "kev"):
            if r[k] > r["counted"]:
                _fail(f"{path}.{k}", "cannot exceed counted")
        for k in ("first_month", "last_month"):
            _check_str(_get(r, k, path), f"{path}.{k}", MONTH_RE)
        if r["first_month"] > r["last_month"]:
            _fail(f"{path}.first_month", "is after last_month")
        cnas = _check_list(_get(r, "top_cnas", path), f"{path}.top_cnas")
        if sum(c.get("n", 0) for c in cnas if isinstance(c, dict)) > \
                r.get("counted", 0):
            _fail(f"{path}.top_cnas", "counts more CVEs than the row credits")
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
        for name in ("baseline", "profile", "weaknesses", "targets"):
            if _get(obj, name, "ai_credits") is not None:
                _fail(f"ai_credits.{name}", "must be null when nothing counts")
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

    sizes = {**{k: kinds[k]["funnel"]["credited"] for k in KINDS},
             "baseline": baseline["credited"]}
    _validate_profile(_get(obj, "profile", "ai_credits"), obj, sizes)
    _validate_weaknesses(_get(obj, "weaknesses", "ai_credits"), sizes)
    _validate_targets(_get(obj, "targets", "ai_credits"), sizes)


def _validate_profile(profile: Any, obj: Any, sizes: dict) -> None:
    """Side-by-side columns: sized like the funnels, and agreeing with them
    wherever they restate a funnel share."""
    if profile is None or list(profile) != list(POPULATIONS):
        _fail("ai_credits.profile",
              f"keys must be exactly {POPULATIONS}, in order")
    funnels = {**{k: obj["kinds"][k]["funnel"] for k in KINDS},
               "baseline": obj["baseline"]}
    for name in POPULATIONS:
        path = f"ai_credits.profile.{name}"
        col = profile[name]
        _check_int(_get(col, "n", path), f"{path}.n")
        if col["n"] != sizes[name]:
            _fail(f"{path}.n", "must equal that population's funnel.credited")
        _check_int(_get(col, "epss_scored", path), f"{path}.epss_scored")
        if col["epss_scored"] > col["n"]:
            _fail(f"{path}.epss_scored", "cannot exceed n")
        for k, hi in (("median_cvss", 10.0), ("median_epss_pctile", 100.0)):
            if _get(col, k, path) is not None:
                _check_num(col[k], f"{path}.{k}", 0.0, hi)
        for k in ("poc_pct", "kev_pct", "memory_pct", "cna_scored_pct",
                  "recent_pct"):
            _check_num(_get(col, k, path), f"{path}.{k}", 0.0, 100.0)
        if _get(col, "recent_days", path) != RECENT_DAYS:
            _fail(f"{path}.recent_days", f"must be {RECENT_DAYS}")
        for k in ("poc_pct", "kev_pct"):
            if col[k] != funnels[name][k]:
                _fail(f"{path}.{k}", "must equal the funnel's share")
        top = _get(col, "top_cwe", path)
        if top is not None:
            _check_str(_get(top, "cwe", f"{path}.top_cwe"),
                       f"{path}.top_cwe.cwe")
            _check_int(_get(top, "n", f"{path}.top_cwe"),
                       f"{path}.top_cwe.n", minimum=1)
            _check_num(_get(top, "pct", f"{path}.top_cwe"),
                       f"{path}.top_cwe.pct", 0.0, 100.0)


def _validate_weaknesses(weak: Any, sizes: dict) -> None:
    """Every family, in registry order, and each population's family counts
    must add back up to that population."""
    families = _check_list(_get(weak, "families", "ai_credits.weaknesses"),
                           "ai_credits.weaknesses.families")
    if [f.get("key") for f in families] != list(WEAKNESS_KEYS):
        _fail("ai_credits.weaknesses.families",
              f"keys must be exactly {WEAKNESS_KEYS}, in order")
    totals = dict.fromkeys(POPULATIONS, 0)
    for i, fam in enumerate(families):
        path = f"ai_credits.weaknesses.families[{i}]"
        if fam.get("label") != WEAKNESS_LABELS[fam["key"]]:
            _fail(f"{path}.label", "must match the committed family label")
        for name in POPULATIONS:
            cell = _get(fam, name, path)
            _check_int(_get(cell, "n", f"{path}.{name}"), f"{path}.{name}.n")
            _check_num(_get(cell, "pct", f"{path}.{name}"),
                       f"{path}.{name}.pct", 0.0, 100.0)
            totals[name] += cell["n"]
    for name in POPULATIONS:
        if totals[name] != sizes[name]:
            _fail("ai_credits.weaknesses.families",
                  f"{name} counts sum to {totals[name]}, not {sizes[name]}")


def _validate_targets(targets: Any, sizes: dict) -> None:
    if targets is None or list(targets) != list(KINDS):
        _fail("ai_credits.targets", f"keys must be exactly {KINDS}, in order")
    for kind in KINDS:
        path = f"ai_credits.targets.{kind}"
        t = targets[kind]
        for k in ("cves", "named", "distinct", "top_share_n"):
            _check_int(_get(t, k, path), f"{path}.{k}")
        if t["cves"] != sizes[kind]:
            _fail(f"{path}.cves", "must equal that kind's funnel.credited")
        if t["named"] > t["cves"] or t["distinct"] > t["named"]:
            _fail(path, "need distinct <= named <= cves")
        if t["top_share_n"] != TOP_SHARE_N:
            _fail(f"{path}.top_share_n", f"must be {TOP_SHARE_N}")
        _check_num(_get(t, "top_share_pct", path),
                   f"{path}.top_share_pct", 0.0, 100.0)
        projects = _check_list(_get(t, "projects", path), f"{path}.projects")
        if len(projects) != min(TOP_TARGETS, t["distinct"]):
            _fail(f"{path}.projects",
                  f"must list the top {TOP_TARGETS} (or every) product")
        counts = []
        for i, proj in enumerate(projects):
            pp = f"{path}.projects[{i}]"
            _check_str(_get(proj, "label", pp), f"{pp}.label")
            if "@" in proj["label"]:
                _fail(f"{pp}.label", "looks like an address, not a product")
            _check_int(_get(proj, "n", pp), f"{pp}.n", minimum=1)
            _check_num(_get(proj, "pct", pp), f"{pp}.pct", 0.0, 100.0)
            counts.append(proj["n"])
        _check_sorted(counts, f"{path}.projects (by n)", descending=True)


def _validate_ledger(obj: Any) -> None:
    """The record-level audit trail: ids, registry keys, tiers and schema
    roles only. Every row must name a registry finder, and ``counts_for``
    must be exactly what the counting rule derives from its matches."""
    _check_generated_at(obj, "ai_credits_ledger")
    rows = _check_list(_get(obj, "rows", "ai_credits_ledger"),
                       "ai_credits_ledger.rows")
    order = []
    for i, r in enumerate(rows):
        path = f"ai_credits_ledger.rows[{i}]"
        if set(r) != {"cve", "published", "cna", "counts_for", "matches"}:
            _fail(path, "unexpected keys (the ledger carries no credit text)")
        _check_str(_get(r, "cve", path), f"{path}.cve", CVE_RE)
        _check_str(_get(r, "published", path), f"{path}.published", DATE_RE)
        _check_str(_get(r, "cna", path), f"{path}.cna")
        matches = _check_list(_get(r, "matches", path), f"{path}.matches")
        if not matches:
            _fail(f"{path}.matches", "a ledger row must match something")
        kinds = set()
        for j, m in enumerate(matches):
            mp = f"{path}.matches[{j}]"
            if set(m) != {"finder", "tier", "roles"}:
                _fail(mp, "unexpected keys")
            if m["finder"] not in _FINDER_KEYS:
                _fail(f"{mp}.finder", "is not in the committed registry")
            if m["tier"] not in TIERS:
                _fail(f"{mp}.tier", f"must be one of {TIERS}")
            roles = _check_list(m["roles"], f"{mp}.roles")
            if not roles:
                _fail(f"{mp}.roles", "must list at least one role")
            for k, role in enumerate(roles):
                _check_str(role, f"{mp}.roles[{k}]")
                if "@" in role or len(role) > 40:
                    _fail(f"{mp}.roles[{k}]", "is not a schema role")
            group = _FINDER_KEYS[m["finder"]].group
            if counts_toward_headline(group, m["tier"]):
                kinds.add(kind_of(group))
        if _get(r, "counts_for", path) != sorted(kinds):
            _fail(f"{path}.counts_for", "must follow from the row's matches")
        order.append((r["published"], r["cve"]))
    _check_sorted(order, "ai_credits_ledger.rows (by published, cve)")
    if len({r["cve"] for r in rows}) != len(rows):
        _fail("ai_credits_ledger.rows", "duplicate CVE ids")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "ai_credits.json": _validate_ai_credits,
    "ai_credits_ledger.json": _validate_ledger,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the ai_credits contract for ``filename``.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no ai_credits contract.
    """
    VALIDATORS[filename](obj)
