"""MITRE ATT&CK fetchers: per-release derived stats from versioned STIX bundles.

The ``mitre-attack/attack-stix-data`` GitHub repo publishes every release of
the enterprise ATT&CK matrix as an immutable STIX 2.1 bundle
(``enterprise-attack/enterprise-attack-<major.minor>.json``, tens of MB
each), plus a small ``index.json`` at the repo root listing each
collection's versions with their release timestamps. Fetching every bundle
nightly is out of the question, and never necessary: released bundles never
change, so each version's derived stats are computed **exactly once** and
kept in a sync-state file (``.cache/attack_state.json``, plain JSON — the
market-state pattern):

* **Normal night** — one ``index.json`` fetch (~100 KB). Every version in
  the index already has stats in the state; no bundle is downloaded.
* **New release (~2x/year)** — the new version is missing from the state:
  its bundle is fetched and reduced to stats. Diffing needs the previous
  release's technique ids too, so the predecessor bundle is re-fetched for
  that one run (two bundle downloads total; the state deliberately stores
  only the published per-version stats, never id sets, so it stays small
  and reconstructable — see below).
* **Lost cache** — the state is first reconstructed from the previously
  published ``site/data/attack_churn.json``: the per-version stats in the
  output round-trip losslessly into state entries (:func:`reconstruct_state`;
  the output format is designed for this). Only versions absent from both
  the cache and the published output are fetched — so the expensive
  full-history backfill (all ~40 bundles) happens exactly once ever, and a
  fresh CI cache costs one small JSON read, not a half-gigabyte sweep.

Counting rules (the methodology on the site quotes these):

* technique          = ``attack-pattern`` with ``x_mitre_is_subtechnique``
                       false (or absent);
* sub-technique      = ``attack-pattern`` with the flag true;
* group              = ``intrusion-set``;
* software           = ``malware`` + ``tool``;
* **active**         = neither ``revoked: true`` nor
                       ``x_mitre_deprecated: true``. Published counts are
                       active objects only.
* churn (per release vs its predecessor, techniques and sub-techniques
  together, keyed by STIX object id): ``added`` = ids new to the release;
  ``deprecated`` / ``revoked`` = ids present in both releases whose flag
  flipped false→true. An object arriving already deprecated counts once,
  as an addition; an object deprecated in an earlier release is never
  re-counted. The index's earliest release has no predecessor: churn None.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

INDEX_URL = ("https://raw.githubusercontent.com/mitre-attack/"
             "attack-stix-data/master/index.json")
COLLECTION_NAME = "Enterprise ATT&CK"
USER_AGENT = "CyberMon/1.0 (+https://github.com/Devko/CyberMon)"
STATE_VERSION = 1
STATE_FILENAME = "attack_state.json"

STAT_KEYS = ("techniques", "subtechniques", "groups", "software")
CHURN_KEYS = ("added", "deprecated", "revoked")
SOFTWARE_TYPES = ("malware", "tool")

_HEADERS = {"User-Agent": USER_AGENT}
_INDEX_TIMEOUT = 60.0
_BUNDLE_TIMEOUT = 300.0   # bundles are tens of MB; raw.githubusercontent is fast
_RETRY_STATUSES = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 3


def version_key(version: str) -> tuple[int, ...]:
    """``"19.1"`` -> ``(19, 1)`` — the sort key for release order. ATT&CK
    versions are strictly ``major.minor``; anything unparsable is an
    upstream format change and must fail loudly, not sort arbitrarily."""
    return tuple(int(part) for part in version.split("."))


# -------------------------------------------------------------- index parsing

def parse_index(index: dict) -> list[dict]:
    """The enterprise collection's versions from a raw ``index.json`` object,
    as ``[{version, url, released}]`` sorted ascending by release order
    (the file lists newest first). ``released`` is the date part of the
    version's ``modified`` timestamp — the collection entry carries no
    other release-date field. Raises ``ValueError`` when the enterprise
    collection or a required field is missing (upstream shape change)."""
    collection = next((c for c in index.get("collections", [])
                       if c.get("name") == COLLECTION_NAME), None)
    if collection is None:
        raise ValueError(
            f"index.json has no {COLLECTION_NAME!r} collection")
    versions = []
    for entry in collection.get("versions", []):
        version = str(entry["version"])
        version_key(version)  # fail loudly on an unparsable version string
        modified = str(entry["modified"])
        if len(modified) < 10:
            raise ValueError(f"version {version}: bad modified {modified!r}")
        versions.append({"version": version, "url": str(entry["url"]),
                         "released": modified[:10]})
    if not versions:
        raise ValueError(f"{COLLECTION_NAME!r} collection lists no versions")
    versions.sort(key=lambda v: version_key(v["version"]))
    return versions


# ------------------------------------------------------------- bundle reading

def _is_active(obj: dict) -> bool:
    return not obj.get("revoked", False) \
        and not obj.get("x_mitre_deprecated", False)


def version_stats(bundle: dict) -> dict:
    """Active-object counts for one STIX bundle: ``{techniques,
    subtechniques, groups, software}`` (see the module docstring for the
    exact object/flag rules)."""
    stats = dict.fromkeys(STAT_KEYS, 0)
    for obj in bundle.get("objects", []):
        if not _is_active(obj):
            continue
        kind = obj.get("type")
        if kind == "attack-pattern":
            if obj.get("x_mitre_is_subtechnique", False):
                stats["subtechniques"] += 1
            else:
                stats["techniques"] += 1
        elif kind == "intrusion-set":
            stats["groups"] += 1
        elif kind in SOFTWARE_TYPES:
            stats["software"] += 1
    return stats


def technique_flags(bundle: dict) -> dict[str, dict]:
    """Lifecycle flags per technique/sub-technique STIX id:
    ``{id: {deprecated, revoked}}`` over every ``attack-pattern`` object
    (active or not) — the input to :func:`churn_counts`."""
    return {obj["id"]: {"deprecated": bool(obj.get("x_mitre_deprecated",
                                                   False)),
                        "revoked": bool(obj.get("revoked", False))}
            for obj in bundle.get("objects", [])
            if obj.get("type") == "attack-pattern"}


def churn_counts(prev_flags: dict[str, dict],
                 cur_flags: dict[str, dict]) -> dict:
    """Diff two releases' technique-flag maps by STIX id:
    ``{added, deprecated, revoked}`` per the module-docstring rules."""
    added = deprecated = revoked = 0
    for stix_id, cur in cur_flags.items():
        prev = prev_flags.get(stix_id)
        if prev is None:
            added += 1  # arriving already-deprecated still counts here only
            continue
        if cur["deprecated"] and not prev["deprecated"]:
            deprecated += 1
        if cur["revoked"] and not prev["revoked"]:
            revoked += 1
    return {"added": added, "deprecated": deprecated, "revoked": revoked}


# ------------------------------------------------------------------ state I/O

def _state_path(cache_dir: Path) -> Path:
    return cache_dir / STATE_FILENAME


def load_state(cache_dir: Path,
               log: Callable[[str], None] = print) -> dict | None:
    """Cached ATT&CK sync state, or None when absent/unreadable (the sync
    then reconstructs from the published output, or backfills — the state
    is only ever a cache)."""
    path = _state_path(cache_dir)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log(f"warning: ignoring unreadable attack state {path}: {exc!r}")
        return None


def save_state(cache_dir: Path, state: dict) -> None:
    """Write the state atomically (temp file, then ``replace``) so an
    interrupted run leaves either the old file or the new one."""
    path = _state_path(cache_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, separators=(",", ":")),
                   encoding="utf-8")
    tmp.replace(path)


def _entry_from(obj: dict) -> dict:
    """One state entry from a mapping carrying the per-version stat fields
    (a published ``versions[]`` element or a cached state value). Raises
    on any malformed field — callers decide how loudly to fail."""
    churn = obj["churn"]
    if churn is not None:
        churn = {key: int(churn[key]) for key in CHURN_KEYS}
        if any(n < 0 for n in churn.values()):
            raise ValueError("negative churn count")
    entry = {"released": str(obj["released"]),
             **{key: int(obj[key]) for key in STAT_KEYS},
             "churn": churn}
    if any(entry[key] < 0 for key in STAT_KEYS):
        raise ValueError("negative stat count")
    return entry


def reconstruct_state(out_dir: Path,
                      log: Callable[[str], None] = print) -> dict | None:
    """Best-effort sync state rebuilt from a previously published
    ``out_dir/attack_churn.json``, for when the cached state is lost (first
    run on a fresh CI cache, actions/cache eviction). The output's
    per-version stats are exactly the state's per-version entries — the
    output format guarantees the round-trip — so a lost cache never
    re-triggers the ~40-bundle backfill. None when the file is absent or
    unusable; the sync then backfills every version from the bundles,
    exactly as on the first run ever."""
    path = out_dir / "attack_churn.json"
    if not path.exists():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        last_sync = str(obj["generated_at"])
        versions = {str(v["version"]): _entry_from(v)
                    for v in obj["versions"]}
    except (OSError, KeyError, TypeError, ValueError) as exc:
        log(f"warning: cannot reconstruct attack state from {path}: {exc!r}")
        return None
    log("  attack: reconstructed sync state from published "
        f"attack_churn.json ({len(versions)} version(s))")
    return {"version": STATE_VERSION, "last_sync": last_sync,
            "versions": versions}


def _pruned_versions(state: dict | None, index_versions: list[dict],
                     log: Callable[[str], None]) -> dict[str, dict]:
    """Carry prior per-version entries forward, keeping only versions the
    index still lists (the index is authoritative) and dropping malformed
    entries (they will simply be re-fetched)."""
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
        if state:
            log("  attack: discarding unrecognized cached state")
        return {}
    listed = {iv["version"] for iv in index_versions}
    kept: dict[str, dict] = {}
    for version, entry in (state.get("versions") or {}).items():
        if version not in listed:
            log(f"  attack: dropping cached version {version} "
                f"(no longer in index.json)")
            continue
        try:
            kept[version] = _entry_from(entry)
        except (KeyError, TypeError, ValueError):
            log(f"  attack: dropping malformed cached version {version}")
    return kept


# ----------------------------------------------------------------------- sync

def sync_state(state: dict | None, index_versions: list[dict],
               fetch_bundle: Callable[[str], dict],
               last_sync: str = "",
               log: Callable[[str], None] = print) -> dict:
    """Return up-to-date ATT&CK sync state ``{version, last_sync,
    versions}``: prune the prior state against ``index_versions`` (as
    returned by :func:`parse_index`, ascending), then compute stats for
    every index version missing from the state — each one costs one bundle
    fetch, plus one predecessor-bundle fetch when the churn diff needs
    technique ids the state deliberately does not keep. Versions already
    in the state cost nothing (bundles are immutable; only their
    ``released`` date is refreshed from the index)."""
    versions = _pruned_versions(state, index_versions, log)
    missing = [iv for iv in index_versions if iv["version"] not in versions]
    if missing:
        log(f"  attack: {len(missing)} version(s) missing from state: "
            + ", ".join(iv["version"] for iv in missing))
    flags_cache: dict[str, dict] = {}
    fetched = 0
    for i, iv in enumerate(index_versions):
        version = iv["version"]
        if version in versions:
            # Immutable bundle, stats already known; the index stays
            # authoritative for the release date.
            versions[version]["released"] = iv["released"]
            continue
        bundle = fetch_bundle(iv["url"])
        fetched += 1
        flags = technique_flags(bundle)
        flags_cache[version] = flags
        if i == 0:
            churn = None  # the earliest indexed release has no predecessor
        else:
            prev = index_versions[i - 1]
            prev_flags = flags_cache.get(prev["version"])
            if prev_flags is None:
                # Predecessor stats exist but its technique ids don't live
                # in the state — one extra (rare) fetch buys the diff.
                log(f"  attack: fetching predecessor {prev['version']} "
                    f"bundle to diff against {version}")
                prev_flags = technique_flags(fetch_bundle(prev["url"]))
                flags_cache[prev["version"]] = prev_flags
                fetched += 1
            churn = churn_counts(prev_flags, flags)
        versions[version] = {"released": iv["released"],
                             **version_stats(bundle), "churn": churn}
        log(f"  attack: computed stats for v{version} "
            f"({iv['released']})")
    if missing:
        log(f"  attack: {fetched} bundle fetch(es) this run")
    return {"version": STATE_VERSION, "last_sync": last_sync,
            "versions": versions}


# --------------------------------------------------------------- live fetches

def fetch_index(session, log: Callable[[str], None] = print) -> dict:
    """The live ``index.json`` object. Fails loudly after the retry budget:
    without the index nothing can be computed truthfully, and the nightly
    workflow treats a failed pipeline as 'deploy nothing'."""
    return _get_json(session, INDEX_URL, _INDEX_TIMEOUT, log)


def fetch_bundle(session, url: str,
                 log: Callable[[str], None] = print) -> dict:
    """One STIX bundle (tens of MB). Same loud-failure policy as the index."""
    return _get_json(session, url, _BUNDLE_TIMEOUT, log)


def _get_json(session, url: str, timeout: float,
              log: Callable[[str], None]) -> dict:
    import time

    message = "no attempt made"
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            resp = session.get(url, headers=_HEADERS, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            retryable = resp.status_code in _RETRY_STATUSES
            message = f"HTTP {resp.status_code}"
        except (OSError, ValueError) as exc:
            retryable = True
            message = f"request failed: {exc!r}"
        if not retryable or attempt == _MAX_ATTEMPTS:
            break
        backoff = 15.0 * attempt
        log(f"  attack: {message} for {url}; retrying in {backoff:.0f}s "
            f"(attempt {attempt}/{_MAX_ATTEMPTS})")
        time.sleep(backoff)
    raise RuntimeError(f"attack fetch failed for {url}: {message}")
