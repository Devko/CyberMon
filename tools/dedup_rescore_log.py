"""One-time repair + migration for the Silent Rescores history.

The incident: the rescore fingerprint state used to live in
``.cache/rescore_state.json.gz`` behind actions/cache, which only saves
on job success. Two failing nights in a row kept restoring the same stale
state, so each night re-diffed the same corpus transition and appended
identical events to the irreplaceable append-only
``site/data/history/rescore_log.csv`` (the same 4 events on 2026-07-15
and 2026-07-16). The state is now COMMITTED at
``site/data/history/rescore_state.json`` (pipeline/rescore_tracker.py);
this tool repairs the log and seeds that committed state:

1. Dedup: drop exact-duplicate events — the same (cve, change_type, old
   fields, new fields) appearing again with no intervening transition for
   that CVE — keeping the EARLIEST observation. A legitimate
   a->b -> b->a -> a->b re-transition sequence is untouched: between the
   two identical a->b events there is an intervening b->a, so neither is
   dropped. The rewrite is atomic (temp file + replace).
2. Seed ``rescore_state.json``: translated from
   ``.cache/rescore_state.json.gz`` when that file exists (full corpus
   fingerprint map; ``last_observed`` parsed from the release tag), else
   reconstructed from the deduped log itself (per-CVE latest fingerprint;
   partial map, but enough that the first committed-state run does not
   full-baseline and lose a night). An existing committed state is never
   overwritten.

Usage:  python tools/dedup_rescore_log.py [--out site/data]
                                          [--cache-dir .cache]
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline import rescore_tracker  # noqa: E402

# The release tag from-log seeds carry: must never equal a real cvelistV5
# release tag, so the release-skew guard cannot skip the next live diff.
SEEDED_RELEASE = "seeded-from-rescore-log"

_RELEASE_DATE = re.compile(r"(\d{4}-\d{2}-\d{2})")


def _key(row: dict) -> tuple:
    """Event identity minus the observation date — what a stale-state
    re-diff reproduces verbatim on a later date."""
    return (row["change_type"], row["version_old"], row["score_old"],
            row["version_new"], row["score_new"])


def dedup_events(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """(kept rows, dropped rows), file order preserved, earliest kept.

    A row is a duplicate when it is identical (change_type, old, new) to
    the immediately preceding KEPT event for the same CVE: after a real
    a->b the CVE's state is b, so the next genuine event for it must
    depart from b — an identical a->b can only be a stale-state re-diff.
    An intervening opposite transition (b->a) resets the comparison, so
    genuine re-transitions survive.
    """
    last_kept: dict[str, tuple] = {}
    kept: list[dict] = []
    dropped: list[dict] = []
    for row in rows:
        if last_kept.get(row["cve"]) == _key(row):
            dropped.append(row)
        else:
            last_kept[row["cve"]] = _key(row)
            kept.append(row)
    return kept, dropped


def seed_state_from_gz(gz_path: Path) -> dict | None:
    """Translate the legacy gzipped cache state into the committed-state
    schema, or None when the file is absent/unreadable/misshapen.
    ``last_observed`` is recovered from the date embedded in the release
    tag (cve_YYYY-MM-DD_HHMMZ); when unparseable it is left empty, which
    the double-count guard treats as maximally stale (conservative)."""
    if not gz_path.exists():
        return None
    try:
        with gzip.open(gz_path, "rt", encoding="utf-8") as f:
            legacy = json.load(f)
    except (OSError, ValueError) as exc:
        print(f"warning: unreadable legacy state {gz_path}: {exc!r}")
        return None
    if not isinstance(legacy, dict) or \
            not isinstance(legacy.get("release"), str) or \
            not isinstance(legacy.get("fingerprints"), dict):
        print(f"warning: misshapen legacy state {gz_path}")
        return None
    match = _RELEASE_DATE.search(legacy["release"])
    return {"release": legacy["release"],
            "last_observed": match.group(1) if match else "",
            "fingerprints": legacy["fingerprints"]}


def seed_state_from_log(rows: list[dict]) -> dict:
    """Reconstruct a (partial) fingerprint state from the event log: each
    CVE's latest new-side fingerprint, in the rescore_tracker state schema.
    Only CVEs that ever produced an event are covered — enough that the
    first committed-state run diffs instead of full-baselining. The
    release is a sentinel that can never match a real corpus tag."""
    fingerprints: dict[str, list] = {}
    for row in rows:  # file order == chronological; last write wins
        fingerprints[row["cve"]] = [row["version_new"], row["score_new"]]
    return {"release": SEEDED_RELEASE,
            "last_observed": max((row["observed_date"] for row in rows),
                                 default=""),
            "fingerprints": fingerprints}


def repair(out_dir: Path, cache_dir: Path) -> int:
    log_path = rescore_tracker.csv_path(out_dir)
    rows = rescore_tracker.read_events(log_path)
    if not rows:
        print(f"{log_path}: no events; nothing to dedup")
    kept, dropped = dedup_events(rows)
    if dropped:
        print(f"{log_path}: dropping {len(dropped)} duplicate event(s), "
              f"keeping {len(kept)}:")
        for row in dropped:
            print(f"  - {row['observed_date']} {row['cve']} "
                  f"{row['change_type']} "
                  f"{row['version_old']} {row['score_old']} -> "
                  f"{row['version_new']} {row['score_new']}")
        rescore_tracker.write_events(log_path, kept)
        print(f"{log_path}: rewritten atomically")
    else:
        print(f"{log_path}: no duplicates found; log left untouched")

    state_file = rescore_tracker.state_path(out_dir)
    if state_file.exists():
        print(f"{state_file}: already exists; not overwriting")
        return 0
    gz_path = cache_dir / "rescore_state.json.gz"
    state = seed_state_from_gz(gz_path)
    if state is not None:
        print(f"{state_file}: seeding from {gz_path} "
              f"({len(state['fingerprints'])} fingerprint(s), release "
              f"{state['release']}, last observed "
              f"{state['last_observed'] or 'unknown'})")
    elif kept:
        state = seed_state_from_log(kept)
        print(f"{state_file}: no legacy cache state; seeding partial "
              f"state from the log ({len(state['fingerprints'])} "
              f"fingerprint(s), last observed {state['last_observed']})")
    else:
        print(f"{state_file}: no legacy state and an empty log — nothing "
              f"to seed; the next run baselines")
        return 0
    rescore_tracker.write_state(state_file, state)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Dedup rescore_log.csv and seed the committed "
                    "rescore_state.json (one-time migration).")
    parser.add_argument("--out", type=Path, default=Path("site/data"))
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache"))
    args = parser.parse_args()
    sys.exit(repair(args.out, args.cache_dir))
