"""Threat-actor naming chaos metrics (naming.json).

One adversary, many names. MITRE ATT&CK's ``intrusion-set`` objects each
carry an ``aliases`` list — the other names a group is tracked under across
vendors (APT28 is also Fancy Bear, Forest Blizzard, Sofacy, STRONTIUM…).
This stage reduces the current enterprise bundle to a most-renamed
leaderboard and an alias-count distribution.

Snapshot, not a time series: only the *latest* enterprise bundle is read.
The alias data for that version is cached (``.cache/naming_state.json``,
keyed by the ATT&CK version) and reconstructed from the previously
published ``naming.json`` when the cache is lost — so a normal night costs
only the ``index.json`` fetch the ATT&CK Churn stage already makes, and the
tens-of-MB bundle is downloaded only when a new ATT&CK release lands (or on
the very first run). The fetch primitives are reused from ``fetch_attack``;
this module adds no new upstream.

``aliases[0]`` is the group's canonical ``name``; the alternates are every
alias that isn't the canonical name (compared by value, not position, so an
upstream reordering can never fold the canonical name into the count). Only
active intrusion-sets count — neither ``revoked`` nor ``x_mitre_deprecated``
— matching the ATT&CK Churn group definition.

Honest limit (stated in the site methodology): ATT&CK's alias list is
MITRE's own curation, not the full vendor-naming universe, and many groups
carry no alternate name at all — the leaderboard is driven by the famous
few.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Callable

from .fetch_attack import (_is_active, fetch_bundle, fetch_index, parse_index)

FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures"
STATE_FILENAME = "naming_state.json"


# ------------------------------------------------------------- extraction

def extract_groups(bundle: dict) -> list[dict]:
    """Active intrusion-sets reduced to ``{name, aliases, alt_count}``, where
    ``aliases`` is the alternate names only — every alias that isn't the
    canonical ``name``. Order is arbitrary; the builder sorts."""
    groups: list[dict] = []
    for obj in bundle.get("objects", []):
        if not isinstance(obj, dict) or obj.get("type") != "intrusion-set":
            continue
        if not _is_active(obj):
            continue
        name = obj.get("name")
        if not isinstance(name, str) or not name:
            continue
        raw = obj.get("aliases") or []
        alternates = [a for a in raw
                      if isinstance(a, str) and a and a != name]
        groups.append({"name": name, "aliases": alternates,
                       "alt_count": len(alternates)})
    return groups


def board_and_distribution(groups: list[dict]) -> tuple[list[dict], list[dict]]:
    """(most-renamed board, alias-count distribution) from extracted groups.

    The board keeps only groups carrying at least one alternate name, sorted
    by alternate count descending, ties broken by name. The distribution
    counts *all* active groups by alternate-name count, gap-filled from zero
    so the axis never silently skips a bucket."""
    board = sorted((g for g in groups if g["alt_count"] > 0),
                   key=lambda g: (-g["alt_count"], g["name"]))
    counts: Counter[int] = Counter(g["alt_count"] for g in groups)
    max_alt = max(counts, default=0)
    distribution = [{"alt_count": k, "n": counts.get(k, 0)}
                    for k in range(max_alt + 1)]
    return board, distribution


# --------------------------------------------------------------- builder

def build_naming(version: str, released: str, board: list[dict],
                 distribution: list[dict], generated_at: str) -> dict:
    """Assemble the naming.json object from a version's board + distribution.

    ``headline`` is None only when no active group carries an alternate name
    (degenerate; the site renders "not enough data yet" instead of an
    invented leaderboard)."""
    total_groups = sum(d["n"] for d in distribution)
    headline = None
    if board:
        distinct = {a for g in board for a in g["aliases"]}
        headline = {
            "total_groups": total_groups,
            "groups_with_aliases": len(board),
            "total_alias_strings": sum(g["alt_count"] for g in board),
            "distinct_alias_strings": len(distinct),
            "most_renamed": board[0]["name"],
            "most_renamed_alt_count": board[0]["alt_count"],
        }
    return {
        "generated_at": generated_at,
        "version": version,
        "released": released,
        "groups": board,
        "distribution": distribution,
        "headline": headline,
    }


def _source(fetched_at: str, obj: dict) -> dict:
    return {"fetched_at": fetched_at, "version": obj["version"],
            "group_count": (obj["headline"]["total_groups"]
                            if obj["headline"] else 0)}


# ------------------------------------------------------------------ state I/O

def _state_path(cache_dir: Path) -> Path:
    return cache_dir / STATE_FILENAME


def load_state(cache_dir: Path,
               log: Callable[[str], None] = print) -> dict | None:
    """Cached alias state, or None when absent/unreadable (the stage then
    reconstructs from the published output, or fetches the bundle — the
    state is only ever a cache)."""
    path = _state_path(cache_dir)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log(f"warning: ignoring unreadable naming state {path}: {exc!r}")
        return None


def save_state(cache_dir: Path, state: dict) -> None:
    """Write the state atomically (temp file, then ``replace``)."""
    path = _state_path(cache_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
    tmp.replace(path)


def reconstruct_state(out_dir: Path,
                      log: Callable[[str], None] = print) -> dict | None:
    """Best-effort alias state rebuilt from a previously published
    ``out_dir/naming.json`` when the cache is lost (fresh CI cache, eviction).
    The published board + distribution are exactly what the state holds, so a
    version match means no bundle re-fetch. None when the file is absent or
    unusable; the stage then fetches the current bundle, exactly like the
    first run ever."""
    path = out_dir / "naming.json"
    if not path.exists():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        board = [{"name": str(g["name"]),
                  "aliases": [str(a) for a in g["aliases"]],
                  "alt_count": int(g["alt_count"])}
                 for g in obj["groups"]]
        distribution = [{"alt_count": int(d["alt_count"]), "n": int(d["n"])}
                        for d in obj["distribution"]]
        state = {"version": str(obj["version"]),
                 "released": str(obj["released"]),
                 "board": board, "distribution": distribution}
    except (OSError, KeyError, TypeError, ValueError) as exc:
        log(f"warning: cannot reconstruct naming state from {path}: {exc!r}")
        return None
    log("  naming: reconstructed alias state from published naming.json "
        f"(v{state['version']})")
    return state


# -------------------------------------------------------------------- stage

def run_stage(out_dir: Path, cache_dir: Path, generated_at: str, *,
              offline_fixtures: bool, session=None,
              log: Callable[[str], None] = print) -> tuple[dict, dict]:
    """(naming.json object, meta.sources.naming object).

    * ``offline_fixtures`` — read the latest fixture bundle from
      pipeline/tests/fixtures/attack/, exercising the real extraction path
      with no network and no disk-state writes (the CI smoke path).
    * live — fetch index.json (reusing ``fetch_attack``), find the latest
      enterprise version, and reuse the cached/reconstructed alias data when
      that version is unchanged; otherwise fetch the current bundle, extract
      aliases, and persist the state. No skip flag: a normal night is one
      cheap index fetch, and a bundle fetch happens only on a new release.
    """
    if offline_fixtures:
        fixture_dir = FIXTURES_DIR / "attack"
        index = json.loads((fixture_dir / "index.json")
                           .read_text(encoding="utf-8"))
        latest = parse_index(index)[-1]
        name = latest["url"].rsplit("/", 1)[-1]
        bundle = json.loads((fixture_dir / name).read_text(encoding="utf-8"))
        board, distribution = board_and_distribution(extract_groups(bundle))
        obj = build_naming(latest["version"], latest["released"],
                           board, distribution, generated_at)
        return obj, _source(generated_at, obj)

    if session is None:
        import requests

        session = requests.Session()
    log("fetching ATT&CK index.json (naming) ...")
    latest = parse_index(fetch_index(session, log=log))[-1]
    state = load_state(cache_dir, log=log)
    if state is None:
        state = reconstruct_state(out_dir, log=log)
    if state and state.get("version") == latest["version"]:
        board = state["board"]
        distribution = state["distribution"]
        released = state["released"]
        log(f"  naming: v{latest['version']} unchanged; using cached aliases")
    else:
        log(f"  naming: fetching enterprise bundle for "
            f"v{latest['version']} ...")
        bundle = fetch_bundle(session, latest["url"], log=log)
        board, distribution = board_and_distribution(extract_groups(bundle))
        released = latest["released"]
        save_state(cache_dir, {"version": latest["version"],
                               "released": released, "board": board,
                               "distribution": distribution})
    obj = build_naming(latest["version"], released, board, distribution,
                       generated_at)
    return obj, _source(generated_at, obj)
