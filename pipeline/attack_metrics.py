"""ATT&CK Churn metrics: the taxonomy's own release history as a time series.

Per-version derived stats arrive as sync state maintained by
``fetch_attack`` (``{"versions": {version: {released, techniques,
subtechniques, groups, software, churn}}}``); this module is a thin,
pure assembly layer plus stage orchestration:

* :func:`build_attack_churn` — orders the versions by release
  (``major.minor`` ascending) and emits the attack_churn.json object. The
  per-version fields in the output are EXACTLY the state's per-version
  entries plus the version string — that identity is a designed guarantee:
  ``fetch_attack.reconstruct_state`` rebuilds the full sync state from the
  published file, so a lost CI cache never re-triggers the ~40-bundle
  backfill (docs/data-contracts.md documents the round-trip);
* :func:`run_stage` — the __main__-facing stage: offline fixtures,
  --skip carry-forward, or a live sync via ``fetch_attack``.

``headline`` is derived (first vs latest release) and recomputed on every
build; reconstruction ignores it. It is None only when the state holds no
versions at all — the site renders "not enough data yet" rather than an
invented comparison.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from .fetch_attack import (STAT_KEYS, fetch_bundle, fetch_index, load_state,
                           parse_index, reconstruct_state, save_state,
                           sync_state, version_key)

FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures"


# ------------------------------------------------------------------ builder

def build_attack_churn(state: dict, generated_at: str) -> dict:
    """Assemble the full attack_churn.json object from sync state."""
    ordered = sorted((state.get("versions") or {}).items(),
                     key=lambda kv: version_key(kv[0]))
    versions = [{"version": version,
                 "released": entry["released"],
                 **{key: entry[key] for key in STAT_KEYS},
                 "churn": entry["churn"]}
                for version, entry in ordered]
    headline = None
    if versions:
        first, latest = versions[0], versions[-1]
        headline = {
            "latest_version": latest["version"],
            "released_latest": latest["released"],
            "techniques_latest": latest["techniques"],
            "subtechniques_latest": latest["subtechniques"],
            "first_version": first["version"],
            "released_first": first["released"],
            "techniques_first": first["techniques"],
            "subtechniques_first": first["subtechniques"],
        }
    return {"generated_at": generated_at, "versions": versions,
            "headline": headline}


def _source(fetched_at: str, versions: list[dict]) -> dict:
    return {"fetched_at": fetched_at,
            "latest_version": versions[-1]["version"],
            "version_count": len(versions)}


# -------------------------------------------------------------------- stage

def run_stage(out_dir: Path, cache_dir: Path, generated_at: str, *,
              skip: bool, offline_fixtures: bool, session=None,
              log: Callable[[str], None] = print
              ) -> tuple[dict | None, dict | None]:
    """(attack_churn.json object or None, meta.sources.attack object or None).

    Mirrors the market stage's handling:

    * ``skip`` — carry the previous run's ``out_dir/attack_churn.json``
      forward untouched, marked ``"stale": true``, with ``fetched_at``
      kept at its old value; (None, None) plus a warning when no prior
      file exists (a duplicated-but-relabeled snapshot would fake data).
      Checked first (the NVD-stage precedent): skipping must win even in
      an offline-fixtures run;
    * ``offline_fixtures`` — sync from pipeline/tests/fixtures/attack/
      (a tiny index.json plus hand-written STIX bundles resolved from the
      fixture directory), exercising the real extraction/diff path with no
      network and no disk-state writes (the CI smoke test path);
    * live — fetch index.json, load the sync state from ``cache_dir`` (a
      lost cache is first reconstructed from the previously published
      ``out_dir``/attack_churn.json, so only versions absent from both
      cost a bundle download), sync, persist the state, and build.
    """
    if skip:
        prior_path = out_dir / "attack_churn.json"
        if not prior_path.exists():
            log("warning: --skip-attack with no previous attack_churn.json; "
                "omitting attack_churn.json and meta.sources.attack this run")
            return None, None
        prior = json.loads(prior_path.read_text(encoding="utf-8"))
        fetched_at = prior.get("generated_at", generated_at)
        carried = dict(prior)
        carried["generated_at"] = generated_at
        carried["stale"] = True
        log(f"  --skip-attack: carrying forward attack_churn.json "
            f"from {fetched_at}")
        # meta.sources.attack must stay contract-complete even when stale.
        return carried, {**_source(fetched_at, carried["versions"]),
                         "stale": True}

    if offline_fixtures:
        fixture_dir = FIXTURES_DIR / "attack"
        index = json.loads((fixture_dir / "index.json")
                           .read_text(encoding="utf-8"))
        index_versions = parse_index(index)

        def _local_bundle(url: str) -> dict:
            name = url.rsplit("/", 1)[-1]
            return json.loads((fixture_dir / name).read_text(encoding="utf-8"))

        state = sync_state(None, index_versions, _local_bundle,
                           last_sync=generated_at, log=log)
        obj = build_attack_churn(state, generated_at)
        return obj, _source(generated_at, obj["versions"])

    # Live sync. requests is imported lazily so the offline/skip paths
    # (and this module's unit tests) never require it to be importable.
    if session is None:
        import requests

        session = requests.Session()
    log("fetching ATT&CK index.json ...")
    index_versions = parse_index(fetch_index(session, log=log))
    log(f"  ATT&CK enterprise: {len(index_versions)} version(s), latest "
        f"v{index_versions[-1]['version']} ({index_versions[-1]['released']})")
    state = load_state(cache_dir, log=log)
    if state is None:
        state = reconstruct_state(out_dir, log=log)
    state = sync_state(state, index_versions,
                       lambda url: fetch_bundle(session, url, log=log),
                       last_sync=generated_at, log=log)
    save_state(cache_dir, state)
    obj = build_attack_churn(state, generated_at)
    return obj, _source(generated_at, obj["versions"])
