"""Adversary Atlas export (attack_atlas.json): the current enterprise ATT&CK
release's "uses" graph, for the Atlas instrument (site/atlas.html).

Nodes are the release's **active** groups (``intrusion-set``), software
(``malware`` + ``tool``) and techniques (``attack-pattern``, sub-techniques
included) — an object carrying ``revoked: true`` or
``x_mitre_deprecated: true`` is left out, matching the ATT&CK Releases
definitions in ``fetch_attack``. Edges are the ``uses`` relationships
between them, in three directions only: group → software, group →
technique and software → technique. A relationship that is itself revoked
or deprecated, or that touches an excluded object (or a campaign), is
dropped.

Compact encoding (docs/data-contracts.md; the page decodes it):

* a node is an integer — its index in ``ids`` / ``names``. Groups come
  first, then software, then techniques (``counts`` gives the block
  sizes), each block sorted by ATT&CK id, so an index is stable for a
  release and an ATT&CK id (G0007, S0002, T1059.001) is stable across
  releases (the page's links and its URL hash use the ATT&CK id);
* ``uses`` holds one row per group and per software node: the target node
  indices, ascending, as one space-separated string. Under the pipeline's
  ``indent=1`` writer an integer array would put every index on its own
  line and roughly double the file;
* ``technique_tactics`` holds one row per technique: indices into
  ``tactics`` (the enterprise matrix's tactic order), space-separated;
* ``software_types`` is one character per software node, ``m`` (malware)
  or ``t`` (tool); ``aliases`` lists each group's other names.

Snapshot, not a time series: only the latest bundle is read, once per
release. The graph is cached in ``.cache/attack_atlas_state.json`` keyed by
ATT&CK version and reconstructed from the previously published
``attack_atlas.json`` when the cache is lost (the naming-stage pattern), so
a normal night costs one ``index.json`` fetch and the tens-of-MB bundle
downloads only when a new release lands. ``--skip-attack`` and an upstream
outage carry the previous edition forward stale (``pipeline/__main__``).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable

from .fetch_attack import (SOFTWARE_TYPES, _is_active, fetch_bundle,
                           fetch_index, parse_index)

FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures"
OUTPUT_NAME = "attack_atlas.json"
STATE_FILENAME = "attack_atlas_state.json"
STATE_VERSION = 1

KINDS = ("groups", "software", "techniques")
ID_RES = {
    "groups": re.compile(r"^G\d{4}$"),
    "software": re.compile(r"^S\d{4}$"),
    "techniques": re.compile(r"^T\d{4}(?:\.\d{3})?$"),
}
KILL_CHAIN = "mitre-attack"
# The three edge directions the Atlas draws, keyed by (source kind, target
# kind). Anything else that "uses" (campaigns) is not a node here.
EDGE_KINDS = {
    ("groups", "software"): "group_software",
    ("groups", "techniques"): "group_technique",
    ("software", "techniques"): "software_technique",
}
# Every key of the output except the run stamp and the stale marker: the
# graph proper, which is what the state caches and what reconstruction
# reads back from a published file.
GRAPH_KEYS = ("version", "released", "bundle", "counts", "tactics", "ids",
              "names", "software_types", "aliases", "technique_tactics",
              "uses")


def _kind_of(obj: dict) -> str | None:
    kind = obj.get("type")
    if kind == "intrusion-set":
        return "groups"
    if kind in SOFTWARE_TYPES:
        return "software"
    if kind == "attack-pattern":
        return "techniques"
    return None


def attack_id(obj: dict) -> str | None:
    """The object's ATT&CK id (``G0007``, ``S0002``, ``T1059.001``,
    ``TA0001``): the ``external_id`` of its ``mitre-attack`` reference."""
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
            ext = ref.get("external_id")
            if isinstance(ext, str) and ext:
                return ext
    return None


# ------------------------------------------------------------- extraction

def _tactics(objects: list[dict]) -> list[dict]:
    """The enterprise matrix's tactics in matrix order, as ``[{id, name,
    short}]`` (``short`` is the kill-chain phase name techniques cite; it
    is used for the join and not published). Raises ``ValueError`` when the
    bundle carries no matrix or a matrix tactic is missing — an upstream
    shape change, never something to guess around."""
    by_stix = {o["id"]: o for o in objects
               if o.get("type") == "x-mitre-tactic" and _is_active(o)}
    matrices = [o for o in objects
                if o.get("type") == "x-mitre-matrix" and _is_active(o)]
    if len(matrices) != 1:
        raise ValueError(f"expected one active x-mitre-matrix, "
                         f"found {len(matrices)}")
    tactics = []
    for ref in matrices[0].get("tactic_refs") or []:
        obj = by_stix.get(ref)
        tid = attack_id(obj) if obj else None
        short = obj.get("x_mitre_shortname") if obj else None
        if not tid or not short or not obj.get("name"):
            raise ValueError(f"matrix tactic {ref!r} is missing or "
                             f"incomplete in the bundle")
        tactics.append({"id": tid, "name": str(obj["name"]),
                        "short": str(short)})
    if not tactics:
        raise ValueError("the matrix lists no tactics")
    return tactics


def extract_graph(bundle: dict,
                  log: Callable[[str], None] = print) -> dict:
    """Reduce one STIX bundle to the Atlas graph: every :data:`GRAPH_KEYS`
    entry except ``version`` / ``released`` / ``bundle``, which come from
    the index (see :func:`build_atlas`)."""
    objects = [o for o in bundle.get("objects", []) if isinstance(o, dict)]
    tactics = _tactics(objects)
    phase_index = {t["short"]: i for i, t in enumerate(tactics)}

    # ---- nodes: active objects of the three kinds with a well-formed id
    found: dict[str, dict[str, dict]] = {k: {} for k in KINDS}
    skipped_ids = 0
    for obj in objects:
        kind = _kind_of(obj)
        if kind is None or not _is_active(obj):
            continue
        aid = attack_id(obj)
        name = obj.get("name")
        if not aid or not ID_RES[kind].match(aid) \
                or not isinstance(name, str) or not name:
            skipped_ids += 1
            continue
        if aid in found[kind]:
            raise ValueError(f"two active objects share ATT&CK id {aid}")
        found[kind][aid] = obj
    if skipped_ids:
        log(f"  atlas: skipped {skipped_ids} active object(s) without a "
            f"well-formed ATT&CK id or name")

    ordered = [(kind, aid) for kind in KINDS for aid in sorted(found[kind])]
    index_of: dict[str, tuple[str, int]] = {}   # STIX id -> (kind, node)
    for i, (kind, aid) in enumerate(ordered):
        index_of[found[kind][aid]["id"]] = (kind, i)
    groups = [found["groups"][aid] for aid in sorted(found["groups"])]
    software = [found["software"][aid] for aid in sorted(found["software"])]
    techniques = [found["techniques"][aid]
                  for aid in sorted(found["techniques"])]

    # ---- edges: active "uses" relationships in the three directions
    targets: list[set[int]] = [set() for _ in range(len(groups)
                                                     + len(software))]
    edge_counts = dict.fromkeys(EDGE_KINDS.values(), 0)
    dropped = 0
    for rel in objects:
        if rel.get("type") != "relationship" \
                or rel.get("relationship_type") != "uses":
            continue
        src = index_of.get(rel.get("source_ref"))
        dst = index_of.get(rel.get("target_ref"))
        edge_kind = EDGE_KINDS.get((src[0], dst[0])) if src and dst else None
        if edge_kind is None or not _is_active(rel):
            dropped += 1
            continue
        if dst[1] not in targets[src[1]]:
            targets[src[1]].add(dst[1])
            edge_counts[edge_kind] += 1
    log(f"  atlas: {sum(edge_counts.values())} uses edge(s) kept, "
        f"{dropped} uses relationship(s) outside the three node kinds or "
        f"inactive")

    technique_tactics = []
    for obj in techniques:
        idx = sorted({phase_index[p["phase_name"]]
                      for p in obj.get("kill_chain_phases") or []
                      if isinstance(p, dict)
                      and p.get("kill_chain_name") == KILL_CHAIN
                      and p.get("phase_name") in phase_index})
        technique_tactics.append(" ".join(map(str, idx)))

    aliases = []
    for obj in groups:
        seen: list[str] = []
        for alias in obj.get("aliases") or []:
            if isinstance(alias, str) and alias and alias != obj["name"] \
                    and alias not in seen:
                seen.append(alias)
        aliases.append(seen)

    counts = {
        "groups": len(groups),
        "software": len(software),
        "techniques": len(techniques),
        "subtechniques": sum(1 for kind, aid in ordered
                             if kind == "techniques" and "." in aid),
        "edges": sum(edge_counts.values()),
        **edge_counts,
    }
    return {
        "counts": counts,
        "tactics": [{"id": t["id"], "name": t["name"]} for t in tactics],
        "ids": [aid for _, aid in ordered],
        "names": [str(found[kind][aid]["name"]) for kind, aid in ordered],
        "software_types": "".join("t" if o["type"] == "tool" else "m"
                                  for o in software),
        "aliases": aliases,
        "technique_tactics": technique_tactics,
        "uses": [" ".join(map(str, sorted(row))) for row in targets],
    }


# --------------------------------------------------------------- builder

def build_atlas(version: str, released: str, bundle_url: str, graph: dict,
                generated_at: str) -> dict:
    """The attack_atlas.json object: run stamp, release identity, graph."""
    return {"generated_at": generated_at, "version": version,
            "released": released, "bundle": bundle_url,
            **{key: graph[key] for key in GRAPH_KEYS
               if key not in ("version", "released", "bundle")}}


def source_block(obj: dict, fetched_at: str) -> dict:
    """``meta.sources.atlas`` for a freshly built edition."""
    counts = obj["counts"]
    return {"fetched_at": fetched_at, "version": obj["version"],
            "node_count": counts["groups"] + counts["software"]
            + counts["techniques"],
            "edge_count": counts["edges"]}


# ------------------------------------------------------------------ state I/O

def _state_path(cache_dir: Path) -> Path:
    return cache_dir / STATE_FILENAME


def load_state(cache_dir: Path,
               log: Callable[[str], None] = print) -> dict | None:
    """Cached graph state, or None when absent, unreadable or of another
    state version (the stage then reconstructs or re-fetches — the state
    is only ever a cache)."""
    path = _state_path(cache_dir)
    if not path.exists():
        return None
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log(f"warning: ignoring unreadable atlas state {path}: {exc!r}")
        return None
    if not isinstance(state, dict) or state.get("state_version") \
            != STATE_VERSION or not isinstance(state.get("graph"), dict):
        log("  atlas: discarding unrecognized cached state")
        return None
    return state


def save_state(cache_dir: Path, state: dict) -> None:
    """Write the state atomically (temp file, then ``replace``)."""
    path = _state_path(cache_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, separators=(",", ":")),
                   encoding="utf-8")
    tmp.replace(path)


def _state(graph: dict) -> dict:
    return {"state_version": STATE_VERSION, "graph": graph}


def _graph_valid(graph: dict, log: Callable[[str], None]) -> bool:
    """True when ``graph`` would publish as a valid attack_atlas.json —
    a cached or reconstructed graph is trusted only then."""
    from .contracts import ContractViolation, validate

    try:
        validate(OUTPUT_NAME, build_atlas(graph["version"], graph["released"],
                                          graph["bundle"], graph,
                                          "1970-01-01T00:00:00Z"))
    except (ContractViolation, KeyError, TypeError) as exc:
        log(f"  atlas: cached graph fails its contract ({exc}); refetching")
        return False
    return True


def reconstruct_state(out_dir: Path,
                      log: Callable[[str], None] = print) -> dict | None:
    """The graph state rebuilt from a previously published
    ``out_dir/attack_atlas.json`` when the cache is lost: the published
    file holds the whole graph, so a version match costs no bundle fetch.
    None when the file is absent, unreadable or fails its contract."""
    path = out_dir / OUTPUT_NAME
    if not path.exists():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        graph = {key: obj[key] for key in GRAPH_KEYS}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        log(f"warning: cannot reconstruct atlas state from {path}: {exc!r}")
        return None
    if not _graph_valid(graph, log):
        return None
    log(f"  atlas: reconstructed graph state from published {OUTPUT_NAME} "
        f"(v{graph['version']})")
    return _state(graph)


# -------------------------------------------------------------------- stage

def run_stage(out_dir: Path, cache_dir: Path, generated_at: str, *,
              offline_fixtures: bool, session=None,
              log: Callable[[str], None] = print) -> tuple[dict, dict]:
    """(attack_atlas.json object, meta.sources.atlas object).

    * ``offline_fixtures`` — read the latest fixture bundle from
      pipeline/tests/fixtures/attack/ through the real extraction path, with
      no network and no state writes (the CI smoke path).
    * live — fetch index.json, reuse the cached (or reconstructed) graph
      when its ATT&CK version is the latest one, otherwise fetch the latest
      bundle once, extract, and cache. Raises on a failed fetch or an
      upstream shape change; ``pipeline/__main__`` then carries the previous
      edition forward stale, so an ATT&CK outage degrades only this page.

    ``--skip-attack`` is handled by the caller (carry-forward, no fetch).
    """
    if offline_fixtures:
        fixture_dir = FIXTURES_DIR / "attack"
        index = json.loads((fixture_dir / "index.json")
                           .read_text(encoding="utf-8"))
        latest = parse_index(index)[-1]
        name = latest["url"].rsplit("/", 1)[-1]
        bundle = json.loads((fixture_dir / name).read_text(encoding="utf-8"))
        obj = build_atlas(latest["version"], latest["released"],
                          latest["url"], extract_graph(bundle, log=log),
                          generated_at)
        return obj, source_block(obj, generated_at)

    if session is None:
        import requests

        session = requests.Session()
    log("fetching ATT&CK index.json (atlas) ...")
    latest = parse_index(fetch_index(session, log=log))[-1]

    def _current(state: dict | None) -> bool:
        return bool(state) and state["graph"].get("version") \
            == latest["version"]

    state = load_state(cache_dir, log=log)
    if _current(state) and not _graph_valid(state["graph"], log):
        state = None
    if not _current(state):
        state = reconstruct_state(out_dir, log=log)
        if _current(state):
            save_state(cache_dir, state)
    if _current(state):
        graph = state["graph"]
        log(f"  atlas: v{latest['version']} unchanged; using the cached graph")
    else:
        log(f"  atlas: fetching enterprise bundle for "
            f"v{latest['version']} ...")
        bundle = fetch_bundle(session, latest["url"], log=log)
        graph = {"version": latest["version"],
                 "released": latest["released"], "bundle": latest["url"],
                 **extract_graph(bundle, log=log)}
        del bundle
        save_state(cache_dir, _state(graph))
    # The index stays authoritative for the release date.
    graph = {**graph, "released": latest["released"]}
    obj = build_atlas(graph["version"], graph["released"], graph["bundle"],
                      graph, generated_at)
    return obj, source_block(obj, generated_at)
