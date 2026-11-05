"""Contracts for the naming.json output (Threat Group Aliases) and the
alias_graph.json output built from it (the Alias Graph instrument).

Same philosophy as pipeline/contracts.py — hand-rolled stdlib validators
that fail loudly — kept in its own module so the naming stage lands without
touching the core contracts file. The coordinator merges :data:`VALIDATORS`
into the pipeline's dispatch; failures raise the same
:class:`pipeline.contracts.ContractViolation` type.

The core module's private checking helpers are reused read-only.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from . import naming_schemes as ns
from .contracts import (DATE_RE, _check_generated_at, _check_int, _check_list,
                        _check_sorted, _check_str, _fail, _get)

VERSION_RE = re.compile(r"^\d+(?:\.\d+)+$")
HEADLINE_INT_KEYS = ("total_groups", "groups_with_aliases",
                     "total_alias_strings", "distinct_alias_strings",
                     "most_renamed_alt_count")


# --------------------------------------------------------------- naming.json

def _validate_naming(obj: Any) -> None:
    _check_generated_at(obj, "naming")
    _check_str(_get(obj, "version", "naming"), "naming.version", VERSION_RE)
    _check_str(_get(obj, "released", "naming"), "naming.released", DATE_RE)

    # groups = the most-renamed board: only groups with >=1 alternate name,
    # sorted by alternate count descending; aliases length must equal the
    # count (the board carries the actual names for the tooltip).
    groups = _check_list(_get(obj, "groups", "naming"), "naming.groups")
    alt_counts = []
    for i, g in enumerate(groups):
        path = f"naming.groups[{i}]"
        _check_str(_get(g, "name", path), f"{path}.name")
        alt = _get(g, "alt_count", path)
        _check_int(alt, f"{path}.alt_count", minimum=1)
        aliases = _check_list(_get(g, "aliases", path), f"{path}.aliases")
        if len(aliases) != alt:
            _fail(f"{path}.aliases",
                  f"length {len(aliases)} != alt_count {alt}")
        for j, a in enumerate(aliases):
            _check_str(a, f"{path}.aliases[{j}]")
        alt_counts.append(alt)
    _check_sorted(alt_counts, "naming.groups (by alt_count)", descending=True)

    # distribution = active groups per alternate-name count, gap-filled from
    # zero, one bucket per count, ascending and unique.
    dist = _check_list(_get(obj, "distribution", "naming"),
                       "naming.distribution")
    keys = []
    for i, d in enumerate(dist):
        path = f"naming.distribution[{i}]"
        k = _get(d, "alt_count", path)
        _check_int(k, f"{path}.alt_count")
        _check_int(_get(d, "n", path), f"{path}.n")
        keys.append(k)
    _check_sorted(keys, "naming.distribution (by alt_count)")
    if len(set(keys)) != len(keys):
        _fail("naming.distribution", "duplicate alt_count buckets")

    headline = _get(obj, "headline", "naming")
    if not groups:
        if headline is not None:
            _fail("naming.headline", "must be null when groups is empty")
        return
    if headline is None:
        _fail("naming.headline", "must be present when groups is non-empty")
    for k in HEADLINE_INT_KEYS:
        _check_int(_get(headline, k, "naming.headline"), f"naming.headline.{k}")
    _check_str(_get(headline, "most_renamed", "naming.headline"),
               "naming.headline.most_renamed")
    # The headline must agree with the board it summarizes.
    if headline["most_renamed"] != groups[0]["name"]:
        _fail("naming.headline.most_renamed", "must equal groups[0].name")
    if headline["most_renamed_alt_count"] != groups[0]["alt_count"]:
        _fail("naming.headline.most_renamed_alt_count",
              "must equal groups[0].alt_count")
    if headline["groups_with_aliases"] != len(groups):
        _fail("naming.headline.groups_with_aliases", "must equal len(groups)")
    # total_groups is the sum of the distribution, and can never be smaller
    # than the number of groups carrying aliases.
    if headline["total_groups"] != sum(d["n"] for d in dist):
        _fail("naming.headline.total_groups",
              "must equal the summed distribution")
    if headline["total_groups"] < headline["groups_with_aliases"]:
        _fail("naming.headline.total_groups",
              "cannot be smaller than groups_with_aliases")


# ---------------------------------------------------------- alias_graph.json

def _validate_alias_graph(obj: Any) -> None:
    """The Alias Graph's data: every name classified by the current rule
    table, and every count reconciled with the names actually shipped."""
    root = "alias_graph"
    _check_generated_at(obj, root)
    _check_str(_get(obj, "version", root), f"{root}.version", VERSION_RE)
    _check_str(_get(obj, "released", root), f"{root}.released", DATE_RE)
    if _get(obj, "rules_version", root) != ns.RULES_VERSION:
        _fail(f"{root}.rules_version",
              f"must equal naming_schemes.RULES_VERSION ({ns.RULES_VERSION})")

    # schemes: the rule table, in table order, with its own counts.
    schemes = _check_list(_get(obj, "schemes", root), f"{root}.schemes")
    if [s.get("id") if isinstance(s, dict) else None for s in schemes] \
            != list(ns.SCHEME_IDS):
        _fail(f"{root}.schemes", "must list the rule table's schemes in order")
    for i, s in enumerate(schemes):
        path = f"{root}.schemes[{i}]"
        spec = ns.SCHEME_BY_ID[s["id"]]
        for key in ("label", "doc", "forms"):
            if _get(s, key, path) != getattr(spec, key):
                _fail(f"{path}.{key}", "must equal the rule table's value")
        _check_int(_get(s, "actors", path), f"{path}.actors")
        _check_int(_get(s, "names", path), f"{path}.names")

    exceptions = [{"name": name, "scheme": scheme, "source": source}
                  for name, (scheme, source) in sorted(ns.EXCEPTIONS.items())]
    if _get(obj, "exceptions", root) != exceptions:
        _fail(f"{root}.exceptions", "must equal the rule table's exceptions")

    actors = _check_list(_get(obj, "actors", root), f"{root}.actors")
    tally = dict.fromkeys(ns.STATUSES, 0)
    per_actors = dict.fromkeys(ns.SCHEME_IDS, 0)
    per_names = dict.fromkeys(ns.SCHEME_IDS, 0)
    seen: set[str] = set()
    for i, a in enumerate(actors):
        path = f"{root}.actors[{i}]"
        name = _get(a, "name", path)
        _check_str(name, f"{path}.name")
        if name in seen:
            _fail(f"{path}.name", f"duplicate actor {name!r}")
        seen.add(name)
        names = _check_list(_get(a, "names", path), f"{path}.names")
        if len(names) < 2:
            _fail(f"{path}.names", "needs the ATT&CK name and an alias")
        hit: set[str] = set()
        for j, n in enumerate(names):
            npath = f"{path}.names[{j}]"
            _check_str(_get(n, "name", npath), f"{npath}.name")
            # Recomputed, not trusted: the shipped label must be what the
            # versioned rule table says today.
            c = ns.classify(n["name"])
            if _get(n, "status", npath) != c.status \
                    or _get(n, "scheme", npath) != c.scheme:
                _fail(npath, f"{n['name']!r} classifies as "
                             f"{c.status}/{c.scheme}, not "
                             f"{n['status']}/{n['scheme']}")
            if list(n.get("candidates", [])) != list(c.candidates):
                _fail(f"{npath}.candidates", "must list the matching schemes")
            tally[c.status] += 1
            if c.scheme is not None:
                per_names[c.scheme] += 1
                hit.add(c.scheme)
        if names[0]["name"] != name:
            _fail(f"{path}.names[0]", "must be the actor's ATT&CK name")
        if _get(a, "schemes", path) != [s for s in ns.SCHEME_IDS if s in hit]:
            _fail(f"{path}.schemes",
                  "must list the schemes of its classified names, in order")
        for s in hit:
            per_actors[s] += 1
    for s in schemes:
        if s["actors"] != per_actors[s["id"]] or s["names"] != per_names[s["id"]]:
            _fail(f"{root}.schemes[{s['id']}]",
                  "actors/names must count the classified names shipped")

    coverage = _get(obj, "coverage", root)
    expected = {"names": sum(tally.values()), **tally}
    if coverage != expected:
        _fail(f"{root}.coverage", f"must equal {expected}, got {coverage}")

    headline = _get(obj, "headline", root)
    if not actors:
        if headline is not None:
            _fail(f"{root}.headline", "must be null when actors is empty")
        return
    k = [len(a["schemes"]) for a in actors]
    expected_h = {"actors": len(actors), "placed": sum(n >= 1 for n in k),
                  "two_plus": sum(n >= 2 for n in k),
                  "three_plus": sum(n >= 3 for n in k), "max_schemes": max(k)}
    if headline != expected_h:
        _fail(f"{root}.headline", f"must equal {expected_h}, got {headline}")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "naming.json": _validate_naming,
    "alias_graph.json": _validate_alias_graph,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the naming contract for ``filename``.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no naming contract.
    """
    VALIDATORS[filename](obj)
