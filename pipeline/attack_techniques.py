"""ATT&CK technique timeline for Detection Rules (module 28).

The ATT&CK Releases stage (``attack_metrics`` / ``fetch_attack``) keeps the
enterprise release list with release dates, and per-release COUNTS — by
design it stores no technique ids (its state must round-trip through the
published ``attack_churn.json``). Joining Sigma tags to ATT&CK needs the
ids: which techniques exist today, and in which release each first
appeared. This module derives that once from the same versioned STIX
bundles, reusing ``fetch_attack``'s fetch primitives and taking the
version list and release dates from the ATT&CK stage's own output.

Definitions (the methodology on the page quotes these):

* **technique** — an active ``attack-pattern`` that is not a
  sub-technique (``revoked`` and ``x_mitre_deprecated`` both false), named
  by its ATT&CK id (``external_references[source_name=mitre-attack]``).
  Sub-technique ids (``T1059.001``) roll up to their parent (``T1059``).
* **debut** — the first indexed release whose bundle lists the id as an
  active technique. Techniques of the earliest indexed release (v1.0,
  January 2018) existed before it, so their debut is a ceiling, not a
  date (the lag measure leaves them out).
* **retired** — the first later release that no longer lists it as active.
* **revoked_to** — from the latest bundle's ``revoked-by`` relationships:
  old id -> replacement id (both may be sub-techniques). Sigma tags that
  still name a revoked id follow this map before rolling up.

State (key ``attack`` in ``.cache/sigma_state.json``)::

    {"synced": ["1.0", ..., "20.0"],                # releases processed, in order
     "techniques": {"T1059": {"debut": "1.0", "retired": null}, ...},
     "latest": {"version", "names", "tactics", "tactic_order",
                "tactic_names", "revoked_to"}}

Cost: released bundles never change, so each release is read exactly once.
A normal night reads no bundle at all; a new ATT&CK release costs one
bundle (plus the small ``index.json`` for its URL). A lost cache is rebuilt
from the published ``sigma_coverage.json`` (:func:`reconstruct`), which
carries every field above; only when that is missing too does the stage
walk every release once (~40 bundles, about 1.5 GB, a one-time backfill).
"""
from __future__ import annotations

from typing import Callable

from .fetch_attack import _is_active, version_key

MAX_BUNDLES_PER_RUN = 80   # the index lists ~42 releases; more = something broke


def mitre_id(obj: dict) -> str | None:
    """The ATT&CK id of a STIX object (``T1059``, ``T1059.001``), or None."""
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
            ext = ref.get("external_id")
            if isinstance(ext, str) and ext:
                return ext
    return None


def parent_id(technique: str) -> str:
    return technique.split(".", 1)[0]


def read_bundle(bundle: dict) -> dict:
    """Reduce one enterprise bundle to ``{active, names, tactics,
    tactic_order, tactic_names, revoked_to}`` (techniques only, no
    sub-techniques, in ``active``/``names``/``tactics``)."""
    objects = [o for o in bundle.get("objects", []) if isinstance(o, dict)]
    active: set[str] = set()
    names: dict[str, str] = {}
    tactics: dict[str, list[str]] = {}
    stix_to_ext: dict[str, str] = {}
    tactic_names: dict[str, str] = {}
    tactic_stix: dict[str, str] = {}
    matrix_refs: list[str] = []
    for obj in objects:
        kind = obj.get("type")
        if kind == "attack-pattern":
            ext = mitre_id(obj)
            if ext is None:
                continue
            stix_to_ext[obj.get("id", "")] = ext
            if not _is_active(obj) or obj.get("x_mitre_is_subtechnique",
                                               False):
                continue
            active.add(ext)
            names[ext] = str(obj.get("name") or ext)
            tactics[ext] = sorted({
                p["phase_name"] for p in obj.get("kill_chain_phases") or []
                if isinstance(p, dict) and p.get("kill_chain_name")
                == "mitre-attack" and isinstance(p.get("phase_name"), str)})
        elif kind == "x-mitre-tactic" and _is_active(obj):
            short = obj.get("x_mitre_shortname")
            if isinstance(short, str) and short:
                tactic_names[short] = str(obj.get("name") or short)
                tactic_stix[obj.get("id", "")] = short
        elif kind == "x-mitre-matrix" and _is_active(obj) \
                and not matrix_refs:
            matrix_refs = [r for r in obj.get("tactic_refs") or []
                           if isinstance(r, str)]
    revoked_to: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "relationship" \
                and obj.get("relationship_type") == "revoked-by":
            src = stix_to_ext.get(obj.get("source_ref", ""))
            dst = stix_to_ext.get(obj.get("target_ref", ""))
            if src and dst and src != dst:
                revoked_to[src] = dst
    order = [tactic_stix[r] for r in matrix_refs if r in tactic_stix]
    order += sorted(set(tactic_names) - set(order))
    return {"active": active, "names": names, "tactics": tactics,
            "tactic_order": order, "tactic_names": tactic_names,
            "revoked_to": revoked_to}


def resolve(technique: str, revoked_to: dict[str, str]) -> str:
    """Follow ``revoked_to`` (cycle-safe), then roll up to the parent id."""
    seen: set[str] = set()
    while technique in revoked_to and technique not in seen:
        seen.add(technique)
        technique = revoked_to[technique]
    if parent_id(technique) != technique:
        technique = resolve(parent_id(technique), revoked_to) \
            if parent_id(technique) in revoked_to else parent_id(technique)
    return technique


def _latest_block(version: str, info: dict) -> dict:
    return {"version": version,
            "names": dict(sorted(info["names"].items())),
            "tactics": {k: list(v) for k, v in sorted(info["tactics"].items())},
            "tactic_order": list(info["tactic_order"]),
            "tactic_names": dict(info["tactic_names"]),
            "revoked_to": dict(sorted(info["revoked_to"].items()))}


def _valid(state: object) -> bool:
    if not isinstance(state, dict):
        return False
    synced, techniques, latest = (state.get("synced"),
                                  state.get("techniques"),
                                  state.get("latest"))
    return (isinstance(synced, list) and isinstance(techniques, dict)
            and isinstance(latest, dict)
            and all(isinstance(v, str) for v in synced)
            and all(isinstance(e, dict) and isinstance(e.get("debut"), str)
                    for e in techniques.values()))


def sync(state: dict | None, versions: list[str],
         fetch_bundle: Callable[[str], dict],
         log: Callable[[str], None] = print) -> tuple[dict, int]:
    """(up-to-date timeline state, bundles read). ``versions`` is the
    enterprise release list in release order (from attack_churn.json).

    The prior state is reused when its ``synced`` list is a prefix of
    ``versions`` (the normal case: nothing new, or new releases appended);
    otherwise — a release withdrawn from the index, an unreadable state —
    the timeline is rebuilt from the first release."""
    versions = sorted(versions, key=version_key)
    if not versions:
        raise ValueError("attack techniques: no ATT&CK releases to join")
    if _valid(state) and state["synced"] == versions[:len(state["synced"])]:
        synced = list(state["synced"])
        techniques = {k: dict(v) for k, v in state["techniques"].items()}
        latest = dict(state["latest"])
    else:
        if state:
            log("  sigma: technique timeline does not match the ATT&CK "
                "release list; rebuilding it")
        synced, techniques, latest = [], {}, {}
    pending = versions[len(synced):]
    if len(pending) > MAX_BUNDLES_PER_RUN:
        raise ValueError(f"attack techniques: {len(pending)} bundles to "
                         f"read, cap {MAX_BUNDLES_PER_RUN}")
    reads = 0
    for version in pending:
        info = read_bundle(fetch_bundle(version))
        reads += 1
        for tid in info["active"]:
            entry = techniques.get(tid)
            if entry is None:
                techniques[tid] = {"debut": version, "retired": None}
            elif entry.get("retired"):
                entry["retired"] = None      # re-activated; debut stands
        for tid, entry in techniques.items():
            if entry.get("retired") is None and tid not in info["active"]:
                entry["retired"] = version
        synced.append(version)
        if version == versions[-1]:
            latest = _latest_block(version, info)
        log(f"  sigma: ATT&CK v{version}: {len(info['active'])} techniques")
    if latest.get("version") != versions[-1]:
        # Cannot happen for a state this module wrote; guards a hand-edited
        # or truncated cache. One bundle read restores the latest block.
        latest = _latest_block(versions[-1],
                               read_bundle(fetch_bundle(versions[-1])))
        reads += 1
    return {"synced": synced, "techniques": dict(sorted(techniques.items())),
            "latest": latest}, reads


def reconstruct(published: object) -> dict | None:
    """The timeline state rebuilt from a published ``sigma_coverage.json``
    object, or None when it is missing or does not carry the fields."""
    try:
        attack = published["attack"]
        synced = [str(v) for v in attack["synced"]]
        techniques = {}
        names, tactics = {}, {}
        for t in published["techniques"]:
            techniques[t["id"]] = {"debut": str(t["debut"]), "retired": None}
            names[t["id"]] = str(t["name"])
            tactics[t["id"]] = [str(x) for x in t["tactics"]]
        for t in published["retired_techniques"]:
            techniques[t["id"]] = {"debut": str(t["debut"]),
                                   "retired": str(t["retired"])}
        latest = {"version": str(attack["version"]), "names": names,
                  "tactics": tactics,
                  "tactic_order": [str(t["id"]) for t in attack["tactics"]],
                  "tactic_names": {str(t["id"]): str(t["name"])
                                   for t in attack["tactics"]},
                  "revoked_to": {str(k): str(v) for k, v
                                 in attack["revoked_to"].items()}}
    except (KeyError, TypeError, AttributeError):
        return None
    state = {"synced": synced, "techniques": techniques, "latest": latest}
    if not _valid(state) or not synced or latest["version"] != synced[-1]:
        return None
    return state
