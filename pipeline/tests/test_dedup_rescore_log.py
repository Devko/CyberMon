"""tools/dedup_rescore_log.py: the one-time log repair + state seeding.

Fixture CSVs are written through rescore_tracker.write_events (the same
serializer the pipeline uses) so the tool is exercised against real file
shapes: a true stale-state duplicate must be dropped (earliest kept), a
legitimate a->b -> b->a -> a->b re-transition sequence must be KEPT.
"""
from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.dedup_rescore_log import (SEEDED_RELEASE,  # noqa: E402
                                     dedup_events, repair,
                                     seed_state_from_gz,
                                     seed_state_from_log)

from pipeline import rescore_tracker  # noqa: E402


def _ev(observed_date, cve, change_type="rescore", cna="VendorX",
        version_old="v3", score_old=9.8, version_new="v3", score_new=7.5):
    return {"observed_date": observed_date, "cve": cve, "cna": cna,
            "change_type": change_type, "version_old": version_old,
            "score_old": score_old, "version_new": version_new,
            "score_new": score_new}


# ------------------------------------------------------------------- dedup

def test_true_duplicate_dropped_earliest_kept():
    # The actual incident shape: the same corpus transition re-diffed on
    # two later nights because the state kept restoring stale.
    rows = [
        _ev("2026-07-15", "CVE-2026-0001"),
        _ev("2026-07-15", "CVE-2026-0002", change_type="first_score",
            version_old=None, score_old=None, version_new="v4",
            score_new=6.9),
        _ev("2026-07-16", "CVE-2026-0001"),                    # dupe
        _ev("2026-07-16", "CVE-2026-0002",                     # dupe
            change_type="first_score", version_old=None, score_old=None,
            version_new="v4", score_new=6.9),
        _ev("2026-07-16", "CVE-2026-0003", version_old="v4", score_old=5.1,
            version_new="v4", score_new=5.9),                  # legit
        _ev("2026-07-17", "CVE-2026-0001"),                    # 3rd copy
    ]
    kept, dropped = dedup_events(rows)
    assert [(r["observed_date"], r["cve"]) for r in kept] == [
        ("2026-07-15", "CVE-2026-0001"),  # earliest observation kept
        ("2026-07-15", "CVE-2026-0002"),
        ("2026-07-16", "CVE-2026-0003"),
    ]
    assert [(r["observed_date"], r["cve"]) for r in dropped] == [
        ("2026-07-16", "CVE-2026-0001"),
        ("2026-07-16", "CVE-2026-0002"),
        ("2026-07-17", "CVE-2026-0001"),
    ]


def test_legitimate_retransition_sequence_is_kept():
    # a->b, b->a, a->b, b->a: identical events recur, but every recurrence
    # has an intervening opposite transition — nothing may be dropped.
    rows = [
        _ev("2026-07-10", "CVE-2026-0001", score_old=9.8, score_new=7.5),
        _ev("2026-07-11", "CVE-2026-0001", score_old=7.5, score_new=9.8),
        _ev("2026-07-12", "CVE-2026-0001", score_old=9.8, score_new=7.5),
        _ev("2026-07-13", "CVE-2026-0001", score_old=7.5, score_new=9.8),
    ]
    kept, dropped = dedup_events(rows)
    assert kept == rows and dropped == []


def test_dedup_is_per_cve_and_change_type_sensitive():
    # Same old/new numbers on different CVEs, and a version_shift vs a
    # rescore with identical fields: none are duplicates of each other.
    rows = [
        _ev("2026-07-15", "CVE-2026-0001"),
        _ev("2026-07-15", "CVE-2026-0002"),  # other CVE, same numbers
        _ev("2026-07-16", "CVE-2026-0001", change_type="version_shift",
            version_new="v4", score_new=8.8),
    ]
    kept, dropped = dedup_events(rows)
    assert kept == rows and dropped == []


# ----------------------------------------------------------------- seeding

def test_seed_state_from_log_reconstructs_latest_fingerprints():
    rows = [
        _ev("2026-07-15", "CVE-2026-0001", score_old=9.8, score_new=7.5),
        _ev("2026-07-15", "CVE-2026-0002", change_type="first_score",
            version_old=None, score_old=None, version_new="v4",
            score_new=6.9),
        _ev("2026-07-16", "CVE-2026-0001", change_type="score_removed",
            version_old="v3", score_old=7.5, version_new=None,
            score_new=None),
    ]
    state = seed_state_from_log(rows)
    assert state == {
        "release": SEEDED_RELEASE,  # can never match a real corpus tag
        "last_observed": "2026-07-16",
        "fingerprints": {"CVE-2026-0001": [None, None],  # removed = unscored
                         "CVE-2026-0002": ["v4", 6.9]},
    }


def test_seed_state_from_gz_translates_legacy_format(tmp_path):
    gz = tmp_path / "rescore_state.json.gz"
    legacy = {"release": "cve_2026-07-14_0500Z",
              "fingerprints": {"CVE-2026-0001": ["v3", 9.8]}}
    with gzip.open(gz, "wt", encoding="utf-8") as f:
        json.dump(legacy, f)
    state = seed_state_from_gz(gz)
    assert state == {"release": "cve_2026-07-14_0500Z",
                     "last_observed": "2026-07-14",  # from the release tag
                     "fingerprints": {"CVE-2026-0001": ["v3", 9.8]}}

    assert seed_state_from_gz(tmp_path / "missing.json.gz") is None
    bad = tmp_path / "bad.json.gz"
    bad.write_bytes(b"not gzip")
    assert seed_state_from_gz(bad) is None


# ------------------------------------------------------------ end to end

def test_repair_dedups_file_and_seeds_state_from_log(tmp_path, capsys):
    out, cache = tmp_path / "out", tmp_path / "cache"
    rows = [
        _ev("2026-07-15", "CVE-2026-0001"),
        _ev("2026-07-16", "CVE-2026-0001"),  # dupe
    ]
    rescore_tracker.write_events(rescore_tracker.csv_path(out), rows)

    assert repair(out, cache) == 0
    kept = rescore_tracker.read_events(rescore_tracker.csv_path(out))
    assert [(r["observed_date"], r["cve"]) for r in kept] == [
        ("2026-07-15", "CVE-2026-0001")]
    printed = capsys.readouterr().out
    assert "dropping 1 duplicate event(s)" in printed
    assert "2026-07-16 CVE-2026-0001" in printed

    # no legacy .cache state -> seeded from the (deduped) log
    state = rescore_tracker.load_state(out, log=lambda m: None)
    assert state["release"] == SEEDED_RELEASE
    assert state["last_observed"] == "2026-07-15"
    assert state["fingerprints"] == {"CVE-2026-0001": ["v3", 7.5]}

    # a second run finds nothing to do and never clobbers the state
    (rescore_tracker.state_path(out)).write_text(
        json.dumps({"release": "keep-me", "fingerprints": {}}),
        encoding="utf-8")
    assert repair(out, cache) == 0
    assert "no duplicates found" in capsys.readouterr().out
    assert rescore_tracker.load_state(
        out, log=lambda m: None)["release"] == "keep-me"


def test_repair_prefers_legacy_gz_state(tmp_path, capsys):
    out, cache = tmp_path / "out", tmp_path / "cache"
    cache.mkdir()
    rescore_tracker.write_events(rescore_tracker.csv_path(out),
                                 [_ev("2026-07-15", "CVE-2026-0001")])
    legacy = {"release": "cve_2026-07-14_0500Z",
              "fingerprints": {"CVE-2026-0001": ["v3", 9.8],
                               "CVE-2026-0002": [None, None]}}
    with gzip.open(cache / "rescore_state.json.gz", "wt",
                   encoding="utf-8") as f:
        json.dump(legacy, f)

    assert repair(out, cache) == 0
    state = rescore_tracker.load_state(out, log=lambda m: None)
    assert state == {"release": "cve_2026-07-14_0500Z",
                     "last_observed": "2026-07-14",
                     "fingerprints": legacy["fingerprints"]}
