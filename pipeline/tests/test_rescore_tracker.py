"""Silent Rescores: diff engine, state, event log, builder, stage.

The diff engine is driven directly with hand-built fingerprint maps —
every change type, the no-event cases, and the same-release guard. The
fixture corpus already carries scored records, so the Aggregator hook is
exercised against it too (the fingerprint/inflation identity guarantee).
"""
from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from pipeline import rescore_tracker
from pipeline.metrics import CveFacts
from pipeline.rescore_tracker import (build_rescore_log, delta_bucket,
                                      diff_events, load_state, make_state,
                                      read_events, run_stage, save_state,
                                      write_events)

DAY1 = "2026-07-10"


def _ev(change_type, *, observed_date=DAY1, cve="CVE-2024-0001",
        cna="VendorX", version_old=None, score_old=None,
        version_new=None, score_new=None):
    return {"observed_date": observed_date, "cve": cve, "cna": cna,
            "change_type": change_type, "version_old": version_old,
            "score_old": score_old, "version_new": version_new,
            "score_new": score_new}


# ---------------------------------------------------- fingerprint identity

def test_fingerprint_and_inflation_score_cannot_disagree():
    facts = CveFacts(cve_id="CVE-2024-1", state="PUBLISHED", year=2024,
                     cna="x", cna_scores={"v2": 5.0, "v3": 7.1, "v4": 6.3})
    assert facts.newest_cna_fingerprint == ("v4", 6.3)
    assert facts.newest_cna_score == 6.3  # derived from the fingerprint

    unscored = CveFacts(cve_id="CVE-2024-2", state="PUBLISHED", year=2024,
                        cna="x")
    assert unscored.newest_cna_fingerprint is None
    assert unscored.newest_cna_score is None


def test_aggregator_collects_published_fingerprints(agg):
    fps = agg.rescore_fingerprints
    # published records only: the fixture corpus has 11 records, 1 REJECTED
    assert len(fps) == 10
    assert "CVE-2024-0003" not in fps  # the REJECTED record
    # scored record: (cna, newest family, that family's score)
    assert fps["CVE-2023-0001"] == ("VendorX", "v3", 9.8)
    # unscored published records are kept with a null fingerprint — that is
    # what makes first_score distinguishable from a brand-new record
    assert any(family is None and score is None
               for (_cna, family, score) in fps.values())
    # the fingerprint score is exactly the inflation chart's blended score
    for _cve, (_cna, family, score) in fps.items():
        assert (family is None) == (score is None)


# -------------------------------------------------------------- diff engine

def test_diff_every_change_type_and_every_no_event_case():
    old = {
        "CVE-2024-0001": ["v3", 9.8],   # -> rescore (down)
        "CVE-2024-0002": [None, None],  # -> first_score
        "CVE-2024-0003": ["v3", 7.5],   # -> version_shift (v3 -> v4)
        "CVE-2024-0004": ["v2", 5.0],   # -> score_removed
        "CVE-2024-0005": ["v3", 6.5],   # unchanged -> no event
        "CVE-2024-0006": [None, None],  # unscored both nights -> no event
        "CVE-2024-0007": ["v3", 4.4],   # left the corpus -> no event
    }
    new = {
        "CVE-2024-0001": ("VendorX", "v3", 7.5),
        "CVE-2024-0002": ("mitre", "v2", 5.0),
        "CVE-2024-0003": ("VendorX", "v4", 9.1),
        "CVE-2024-0004": ("mitre", None, None),
        "CVE-2024-0005": ("mitre", "v3", 6.5),
        "CVE-2024-0006": ("mitre", None, None),
        "CVE-2024-0008": ("mitre", "v3", 9.9),  # brand new -> no event
    }
    events = diff_events(old, new, DAY1)
    assert [(e["cve"], e["change_type"]) for e in events] == [
        ("CVE-2024-0001", "rescore"),
        ("CVE-2024-0002", "first_score"),
        ("CVE-2024-0003", "version_shift"),
        ("CVE-2024-0004", "score_removed"),
    ]
    by_cve = {e["cve"]: e for e in events}
    assert by_cve["CVE-2024-0001"] == _ev(
        "rescore", version_old="v3", score_old=9.8,
        version_new="v3", score_new=7.5)
    assert by_cve["CVE-2024-0002"] == _ev(
        "first_score", cve="CVE-2024-0002", cna="mitre",
        version_new="v2", score_new=5.0)
    assert by_cve["CVE-2024-0004"] == _ev(
        "score_removed", cve="CVE-2024-0004", cna="mitre",
        version_old="v2", score_old=5.0)
    # every event carries the observation date
    assert all(e["observed_date"] == DAY1 for e in events)


def test_version_shift_never_carries_a_direction_reading():
    # A score change riding a version change is ONE version_shift event,
    # never a rescore: v3 7.5 and v4 9.1 are different scales.
    events = diff_events({"CVE-2024-0001": ["v3", 7.5]},
                         {"CVE-2024-0001": ("x", "v4", 9.1)}, DAY1)
    assert [e["change_type"] for e in events] == ["version_shift"]
    # A newer-version score being withdrawn (v4 -> v3) is also a shift.
    events = diff_events({"CVE-2024-0001": ["v4", 9.1]},
                         {"CVE-2024-0001": ("x", "v3", 7.5)}, DAY1)
    assert [e["change_type"] for e in events] == ["version_shift"]


# -------------------------------------------------------------------- state

def test_state_round_trip(tmp_path):
    fps = {"CVE-2024-0001": ("VendorX", "v3", 9.8),
           "CVE-2024-0002": ("mitre", None, None)}
    state = make_state("release-1", fps)
    assert state == {"release": "release-1",
                     "fingerprints": {"CVE-2024-0001": ["v3", 9.8],
                                      "CVE-2024-0002": [None, None]}}
    save_state(tmp_path, state)
    assert load_state(tmp_path, log=lambda m: None) == state


def test_missing_unreadable_or_misshapen_state_is_none(tmp_path):
    assert load_state(tmp_path, log=lambda m: None) is None  # missing

    path = tmp_path / "rescore_state.json.gz"
    path.write_bytes(b"not gzip at all")
    assert load_state(tmp_path, log=lambda m: None) is None  # unreadable

    with gzip.open(path, "wt", encoding="utf-8") as f:
        f.write('{"release": 42}')  # wrong shape
    assert load_state(tmp_path, log=lambda m: None) is None


# ---------------------------------------------------------------- event log

def test_event_csv_round_trip(tmp_path):
    path = tmp_path / "history" / "rescore_log.csv"
    rows = [
        _ev("rescore", version_old="v3", score_old=9.8,
            version_new="v3", score_new=7.5),
        _ev("first_score", cve="CVE-2024-0002", cna="mitre",
            version_new="v2", score_new=5.0),
        _ev("score_removed", cve="CVE-2024-0004",
            version_old="v4", score_old=10.0),
    ]
    write_events(path, rows)
    assert read_events(path) == rows
    # None round-trips through empty CSV cells, scores stay 1-decimal
    text = path.read_text(encoding="utf-8")
    assert "9.8" in text and "10.0" in text and "None" not in text


def test_event_csv_missing_file_and_malformed_row(tmp_path):
    assert read_events(tmp_path / "rescore_log.csv") == []
    path = tmp_path / "rescore_log.csv"
    path.write_text("observed_date,cve,cna,change_type,version_old,"
                    "score_old,version_new,score_new\n"
                    "2026-07-10,CVE-2024-0001,x,not_a_type,,,v3,9.8\n",
                    encoding="utf-8")
    with pytest.raises(ValueError, match="malformed rescore event"):
        read_events(path)


# ------------------------------------------------------------------ builder

def test_delta_bucket_edges():
    assert delta_bucket(-4.0) == "<=-4.0"
    assert delta_bucket(-3.9) == "-3.9..-2.0"
    assert delta_bucket(-2.0) == "-3.9..-2.0"
    assert delta_bucket(-1.9) == "-1.9..-0.1"
    assert delta_bucket(-0.1) == "-1.9..-0.1"
    assert delta_bucket(0.1) == "+0.1..+1.9"
    assert delta_bucket(1.9) == "+0.1..+1.9"
    assert delta_bucket(2.0) == "+2.0..+3.9"
    assert delta_bucket(3.9) == "+2.0..+3.9"
    assert delta_bucket(4.0) == ">=+4.0"


def _sample_rows():
    return [
        _ev("rescore", observed_date="2026-07-06", version_old="v3",
            score_old=5.0, version_new="v3", score_new=9.8),   # up +4.8
        _ev("rescore", observed_date="2026-07-07", cve="CVE-2024-0002",
            cna="mitre", version_old="v3", score_old=9.8,
            version_new="v3", score_new=9.1),                  # down -0.7
        _ev("first_score", observed_date="2026-07-07",
            cve="CVE-2024-0004", cna="mitre",
            version_new="v3", score_new=6.0),
        # two calendar weeks later — the week between must gap-fill
        _ev("rescore", observed_date="2026-07-20", cve="CVE-2024-0005",
            version_old="v2", score_old=4.0, version_new="v2",
            score_new=5.1),                                    # up +1.1
        _ev("version_shift", observed_date="2026-07-20",
            cve="CVE-2024-0006", version_old="v3", score_old=7.5,
            version_new="v4", score_new=9.1),
        _ev("score_removed", observed_date="2026-07-20",
            cve="CVE-2024-0007", cna="mitre",
            version_old="v3", score_old=2.0),
    ]


def test_build_weeks_split_directions_and_gap_fill():
    obj = build_rescore_log(_sample_rows(), state_size=7, release="r2",
                            generated_at="2026-07-21T00:00:00Z",
                            min_n=1, min_cna_events=1)
    assert obj["weeks"] == [
        {"week": "2026-W28", "rescore_up": 1, "rescore_down": 1,
         "first_score": 1, "version_shift": 0, "score_removed": 0},
        {"week": "2026-W29", "rescore_up": 0, "rescore_down": 0,
         "first_score": 0, "version_shift": 0, "score_removed": 0},
        {"week": "2026-W30", "rescore_up": 1, "rescore_down": 0,
         "first_score": 0, "version_shift": 1, "score_removed": 1},
    ]
    assert obj["catalog"] == {
        "state_size": 7, "corpus_release": "r2",
        "totals": {"rescore": 3, "version_shift": 1,
                   "first_score": 1, "score_removed": 1},
        "events_total": 6, "first_observed": "2026-07-06"}


def test_build_magnitude_gate_and_distribution():
    rows = _sample_rows()
    gated = build_rescore_log(rows, state_size=7, release="r2",
                              generated_at="2026-07-21T00:00:00Z",
                              min_n=10, min_cna_events=1)
    # below min_n: an honest placeholder, driven by the data
    assert gated["magnitude"] == {"min_n": 10, "n": 3, "up": 2, "down": 1,
                                  "buckets": None, "median_delta": None}

    open_ = build_rescore_log(rows, state_size=7, release="r2",
                              generated_at="2026-07-21T00:00:00Z",
                              min_n=3, min_cna_events=1)
    mag = open_["magnitude"]
    assert mag["n"] == 3 and mag["median_delta"] == 1.1
    buckets = {b["bucket"]: b["n"] for b in mag["buckets"]}
    assert buckets == {"<=-4.0": 0, "-3.9..-2.0": 0, "-1.9..-0.1": 1,
                       "+0.1..+1.9": 1, "+2.0..+3.9": 0, ">=+4.0": 1}


def test_build_cna_board_filter_and_sort():
    rows = _sample_rows()
    obj = build_rescore_log(rows, state_size=7, release="r2",
                            generated_at="2026-07-21T00:00:00Z",
                            min_n=1, min_cna_events=1)
    # VendorX: 2 rescores (both up); mitre: 1 (down). Rescore events only —
    # mitre's first_score and score_removed never count toward the board.
    assert obj["cna_board"]["cnas"] == [
        {"cna": "VendorX", "rescores": 2, "up": 2, "down": 0},
        {"cna": "mitre", "rescores": 1, "up": 0, "down": 1},
    ]
    filtered = build_rescore_log(rows, state_size=7, release="r2",
                                 generated_at="2026-07-21T00:00:00Z",
                                 min_n=1, min_cna_events=2)
    assert [c["cna"] for c in filtered["cna_board"]["cnas"]] == ["VendorX"]


def test_build_empty_log_is_the_launch_shape():
    obj = build_rescore_log([], state_size=0, release="r1",
                            generated_at="2026-07-21T00:00:00Z")
    assert obj["weeks"] == []
    assert obj["magnitude"]["buckets"] is None
    assert obj["cna_board"]["cnas"] == []
    assert obj["catalog"]["events_total"] == 0
    assert obj["catalog"]["first_observed"] is None


# -------------------------------------------------------------------- stage

def _persist(out: Path, cache: Path, result):
    obj, source, rows, state = result
    write_events(out / "history" / "rescore_log.csv", rows)
    if state is not None:
        save_state(cache, state)
    return obj, source


def _stage(out, cache, fps, release, generated_at):
    return run_stage(out, cache, fps, release, generated_at,
                     offline_fixtures=False, min_n=1, min_cna_events=1,
                     log=lambda m: None)


def test_stage_two_run_synthetic_with_release_guard(tmp_path):
    out, cache = tmp_path / "out", tmp_path / "cache"

    # Night 1: no state — self-healing baseline, zero events.
    fps1 = {"CVE-2024-0001": ("VendorX", "v3", 9.8),
            "CVE-2024-0002": ("mitre", None, None)}
    obj, source = _persist(out, cache, _stage(
        out, cache, fps1, "r1", "2026-07-10T02:43:00Z"))
    assert obj["catalog"]["events_total"] == 0
    assert obj["catalog"]["state_size"] == 2
    assert source == {"events_total": 0, "state_release": "r1"}

    # Night 2: a rescore, a first score, and a brand-new record (no event).
    fps2 = {"CVE-2024-0001": ("VendorX", "v3", 7.5),
            "CVE-2024-0002": ("mitre", "v2", 5.0),
            "CVE-2024-0003": ("mitre", "v3", 9.9)}
    obj, source = _persist(out, cache, _stage(
        out, cache, fps2, "r2", "2026-07-11T02:43:00Z"))
    assert obj["catalog"]["totals"] == {"rescore": 1, "first_score": 1,
                                        "version_shift": 0,
                                        "score_removed": 0}
    assert source["events_total"] == 2

    # Same-release re-run: the guard skips the diff — no double-count.
    obj, source = _persist(out, cache, _stage(
        out, cache, fps2, "r2", "2026-07-11T03:00:00Z"))
    assert source["events_total"] == 2

    # Night 3: a version shift and a score removal append to the log.
    fps3 = {"CVE-2024-0001": ("VendorX", "v4", 9.1),
            "CVE-2024-0002": ("mitre", None, None),
            "CVE-2024-0003": ("mitre", "v3", 9.9)}
    obj, source = _persist(out, cache, _stage(
        out, cache, fps3, "r3", "2026-07-12T02:43:00Z"))
    assert obj["catalog"]["totals"] == {"rescore": 1, "first_score": 1,
                                        "version_shift": 1,
                                        "score_removed": 1}
    assert obj["catalog"]["first_observed"] == "2026-07-11"
    # the committed log has everything, dates monotonic
    rows = read_events(out / "history" / "rescore_log.csv")
    dates = [r["observed_date"] for r in rows]
    assert dates == sorted(dates) and len(rows) == 4


def test_stage_unreadable_state_self_heals(tmp_path):
    out, cache = tmp_path / "out", tmp_path / "cache"
    cache.mkdir()
    (cache / "rescore_state.json.gz").write_bytes(b"corrupt")
    fps = {"CVE-2024-0001": ("VendorX", "v3", 9.8)}
    obj, _source, rows, state = _stage(out, cache, fps, "r1",
                                       "2026-07-10T02:43:00Z")
    assert obj["catalog"]["events_total"] == 0 and rows == []
    assert state == make_state("r1", fps)  # rebuilt from tonight's corpus


def test_stage_offline_fixtures_is_stateless(tmp_path):
    out, cache = tmp_path / "out", tmp_path / "cache"
    fps = {"CVE-2024-0001": ("VendorX", "v3", 9.8)}
    obj, source, rows, state = run_stage(
        out, cache, fps, "fixtures", "2026-07-10T02:43:00Z",
        offline_fixtures=True, log=lambda m: None)
    assert state is None and rows == []  # never touches .cache
    assert not cache.exists()
    assert obj["magnitude"]["min_n"] == 1  # fixture-mode defaults
    assert source == {"events_total": 0, "state_release": "fixtures"}
