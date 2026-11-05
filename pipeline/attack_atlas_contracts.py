"""Contract for the Adversary Atlas export (attack_atlas.json).

Same philosophy as pipeline/contracts.py — a hand-rolled stdlib validator
that fails loudly — kept in its own module (the botnet_contracts pattern)
and merged into the pipeline's dispatch at the bottom of contracts.py.

What it holds the file to (docs/data-contracts.md has the format):

* the node tables line up: ``ids`` and ``names`` have one entry per node,
  ``counts`` gives the group / software / technique block sizes, and each
  block's ids have that kind's ATT&CK form (G0007, S0002, T1059.001), are
  unique and sorted;
* every ``uses`` row decodes to ascending, unique node indices of an
  allowed target kind (a group row: software or techniques; a software
  row: techniques), and the per-direction edge counts reconcile with the
  rows shipped;
* ``technique_tactics`` rows index into ``tactics``; ``software_types``
  and ``aliases`` have one entry per software node / group.

The page indexes straight into these arrays, so a file that passes here
cannot send it out of bounds.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .attack_contracts import VERSION_RE
from .contracts import (DATE_RE, _check_bool, _check_generated_at,
                        _check_int, _check_list, _check_str, _fail, _get)

ROOT = "attack_atlas"
NODE_ID_RES = {
    "groups": re.compile(r"^G\d{4}$"),
    "software": re.compile(r"^S\d{4}$"),
    "techniques": re.compile(r"^T\d{4}(?:\.\d{3})?$"),
}
TACTIC_ID_RE = re.compile(r"^TA\d{4}$")
BUNDLE_RE = re.compile(r"^https://\S+\.json$")
ROW_RE = re.compile(r"^(?:\d+(?: \d+)*)?$")
COUNT_KEYS = ("groups", "software", "techniques", "subtechniques", "edges",
              "group_software", "group_technique", "software_technique")


def _row(value: Any, path: str) -> list[int]:
    """One space-separated index row, decoded; ascending and unique."""
    if not isinstance(value, str) or not ROW_RE.match(value):
        _fail(path, f"expected space-separated integers, got {value!r}")
    out = [int(x) for x in value.split()] if value else []
    if any(b <= a for a, b in zip(out, out[1:])):
        _fail(path, "indices must be ascending and unique")
    return out


def _validate_attack_atlas(obj: Any) -> None:
    _check_generated_at(obj, ROOT)
    if "stale" in obj:
        _check_bool(obj["stale"], f"{ROOT}.stale")
    _check_str(_get(obj, "version", ROOT), f"{ROOT}.version", VERSION_RE)
    _check_str(_get(obj, "released", ROOT), f"{ROOT}.released", DATE_RE)
    _check_str(_get(obj, "bundle", ROOT), f"{ROOT}.bundle", BUNDLE_RE)

    counts = _get(obj, "counts", ROOT)
    for key in COUNT_KEYS:
        _check_int(_get(counts, key, f"{ROOT}.counts"),
                   f"{ROOT}.counts.{key}")
    n_g, n_s, n_t = (counts["groups"], counts["software"],
                     counts["techniques"])
    if n_g < 1 or n_t < 1:
        _fail(f"{ROOT}.counts", "needs at least one group and technique")
    n = n_g + n_s + n_t

    tactics = _check_list(_get(obj, "tactics", ROOT), f"{ROOT}.tactics")
    if not tactics:
        _fail(f"{ROOT}.tactics", "must list the matrix's tactics")
    seen_tactics = set()
    for i, tac in enumerate(tactics):
        path = f"{ROOT}.tactics[{i}]"
        _check_str(_get(tac, "id", path), f"{path}.id", TACTIC_ID_RE)
        _check_str(_get(tac, "name", path), f"{path}.name")
        if tac["id"] in seen_tactics:
            _fail(f"{path}.id", f"duplicate tactic {tac['id']}")
        seen_tactics.add(tac["id"])

    ids = _check_list(_get(obj, "ids", ROOT), f"{ROOT}.ids")
    names = _check_list(_get(obj, "names", ROOT), f"{ROOT}.names")
    if len(ids) != n or len(names) != n:
        _fail(ROOT, f"ids ({len(ids)}) and names ({len(names)}) must each "
                    f"hold counts.groups + software + techniques ({n})")
    blocks = (("groups", 0, n_g), ("software", n_g, n_g + n_s),
              ("techniques", n_g + n_s, n))
    for kind, lo, hi in blocks:
        block = ids[lo:hi]
        for i, aid in enumerate(block, start=lo):
            _check_str(aid, f"{ROOT}.ids[{i}]", NODE_ID_RES[kind])
        if block != sorted(block) or len(set(block)) != len(block):
            _fail(f"{ROOT}.ids", f"the {kind} block must be sorted and "
                                 f"unique")
    for i, name in enumerate(names):
        _check_str(name, f"{ROOT}.names[{i}]")
    subs = sum(1 for aid in ids[n_g + n_s:] if "." in aid)
    if subs != counts["subtechniques"]:
        _fail(f"{ROOT}.counts.subtechniques",
              f"{counts['subtechniques']} but {subs} ids are sub-techniques")

    types = _get(obj, "software_types", ROOT)
    if not isinstance(types, str) or len(types) != n_s \
            or set(types) - {"m", "t"}:
        _fail(f"{ROOT}.software_types",
              f"must be one 'm' or 't' per software node ({n_s})")

    aliases = _check_list(_get(obj, "aliases", ROOT), f"{ROOT}.aliases")
    if len(aliases) != n_g:
        _fail(f"{ROOT}.aliases", f"must hold one list per group ({n_g})")
    for i, row in enumerate(aliases):
        for j, alias in enumerate(_check_list(row, f"{ROOT}.aliases[{i}]")):
            _check_str(alias, f"{ROOT}.aliases[{i}][{j}]")

    tt = _check_list(_get(obj, "technique_tactics", ROOT),
                     f"{ROOT}.technique_tactics")
    if len(tt) != n_t:
        _fail(f"{ROOT}.technique_tactics",
              f"must hold one row per technique ({n_t})")
    for i, value in enumerate(tt):
        path = f"{ROOT}.technique_tactics[{i}]"
        if any(x >= len(tactics) for x in _row(value, path)):
            _fail(path, "tactic index out of range")

    uses = _check_list(_get(obj, "uses", ROOT), f"{ROOT}.uses")
    if len(uses) != n_g + n_s:
        _fail(f"{ROOT}.uses",
              f"must hold one row per group and software node ({n_g + n_s})")
    tally = {"group_software": 0, "group_technique": 0,
             "software_technique": 0}
    for i, value in enumerate(uses):
        path = f"{ROOT}.uses[{i}]"
        row = _row(value, path)
        if not row:
            continue
        lowest = n_g if i < n_g else n_g + n_s
        if row[0] < lowest or row[-1] >= n:
            _fail(path, "target index out of range for its source kind")
        if i < n_g:
            soft = sum(1 for x in row if x < n_g + n_s)
            tally["group_software"] += soft
            tally["group_technique"] += len(row) - soft
        else:
            tally["software_technique"] += len(row)
    for key, value in tally.items():
        if counts[key] != value:
            _fail(f"{ROOT}.counts.{key}",
                  f"{counts[key]} but the uses rows hold {value}")
    if counts["edges"] != sum(tally.values()):
        _fail(f"{ROOT}.counts.edges", "must equal the three directions' sum")


def check_meta_source(src: Any, path: str = "meta.sources.atlas") -> None:
    """``meta.sources.atlas``: ``{fetched_at, version, node_count,
    edge_count}`` plus ``stale: true`` on a carried-forward edition."""
    from .contracts import ISO_UTC_RE

    _check_str(_get(src, "fetched_at", path), f"{path}.fetched_at",
               ISO_UTC_RE)
    _check_str(_get(src, "version", path), f"{path}.version", VERSION_RE)
    _check_int(_get(src, "node_count", path), f"{path}.node_count",
               minimum=1)
    _check_int(_get(src, "edge_count", path), f"{path}.edge_count")
    if "stale" in src:
        _check_bool(src["stale"], f"{path}.stale")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "attack_atlas.json": _validate_attack_atlas,
}
