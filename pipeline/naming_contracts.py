"""Contract for the naming.json output (Threat-actor naming chaos).

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


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "naming.json": _validate_naming,
}


def validate(filename: str, obj: Any) -> None:
    """Validate ``obj`` against the naming contract for ``filename``.

    Raises :class:`pipeline.contracts.ContractViolation` on any mismatch,
    ``KeyError`` if the filename has no naming contract.
    """
    VALIDATORS[filename](obj)
