"""Claims audit for the Silent Rescores copy (test_claims_audit.py pattern).

Unlike the other modules' audits, every check here is RANGE-FREE: the
module launches with no accumulated record, so there is no number a range
could honestly bound. The copy makes structural promises instead — events
split cleanly by type, version shifts and first scores never chart as
up/down, the log only ever grows forward — and those are asserted as
structural truths against whatever data has accumulated. Never silence a
failure here: fix the copy or the pipeline, never the test.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parents[2] / "site" / "data"

_meta_path = DATA_DIR / "meta.json"
if not _meta_path.exists():
    pytest.skip(
        "site/data/meta.json missing — no committed data to audit",
        allow_module_level=True,
    )
if json.loads(_meta_path.read_text("utf-8")).get("sample") is True:
    pytest.skip(
        "site/data holds sample data — claims audit only judges real data",
        allow_module_level=True,
    )


def load_log() -> dict:
    path = DATA_DIR / "rescore_log.json"
    if not path.exists():
        pytest.skip("rescore_log.json missing — nothing to audit")
    return json.loads(path.read_text("utf-8"))


def load_csv() -> list[dict]:
    path = DATA_DIR / "history" / "rescore_log.csv"
    if not path.exists():
        pytest.skip("history/rescore_log.csv missing — nothing to audit")
    with path.open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_events_by_type_sum_to_total():
    # editorial.js (rescores.html): the catalog block is quoted as the
    # audit trail — "every event is exactly one of four change types".
    d = load_log()
    totals = d["catalog"]["totals"]
    assert set(totals) == {"rescore", "version_shift", "first_score",
                           "score_removed"}
    assert sum(totals.values()) == d["catalog"]["events_total"]


def test_weekly_series_carry_the_same_events():
    # hero caption: the muted series are "visible but never conflated" —
    # each type's weekly counts must reproduce its catalog total exactly.
    d = load_log()
    weeks = d["weeks"]
    totals = d["catalog"]["totals"]
    assert sum(w["rescore_up"] + w["rescore_down"] for w in weeks) == \
        totals["rescore"]
    for key in ("first_score", "version_shift", "score_removed"):
        assert sum(w[key] for w in weeks) == totals[key]


def test_direction_exists_only_for_rescores():
    # methodology: "a version shift is never charted as up or down, and a
    # first score has no direction to chart" — on the committed log, only
    # rescore rows may read as a same-version score movement.
    rows = load_csv()
    for row in rows:
        t = row["change_type"]
        if t == "rescore":
            assert row["version_old"] == row["version_new"] != ""
            assert row["score_old"] != row["score_new"]
        elif t == "version_shift":
            assert row["version_old"] != row["version_new"]
            assert row["version_old"] and row["version_new"]
        elif t == "first_score":
            assert row["version_old"] == "" and row["score_old"] == ""
            assert row["version_new"] and row["score_new"]
        elif t == "score_removed":
            assert row["version_new"] == "" and row["score_new"] == ""
            assert row["version_old"] and row["score_old"]
        else:
            raise AssertionError(f"unknown change_type {t!r}")


def test_log_dates_monotonic():
    # note: "the record starts on {first_date} and grows every night" —
    # an append-only log's dates never go backward.
    rows = load_csv()
    dates = [row["observed_date"] for row in rows]
    assert dates == sorted(dates)


def test_json_and_csv_agree_on_the_record():
    # the JSON is rebuilt from the committed CSV nightly; the two must
    # describe the same record (guards the "the log IS the dataset" copy).
    d = load_log()
    rows = load_csv()
    assert d["catalog"]["events_total"] == len(rows)
    if rows:
        assert d["catalog"]["first_observed"] == \
            min(row["observed_date"] for row in rows)
    else:
        assert d["catalog"]["first_observed"] is None
