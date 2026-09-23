"""Claims audit for the Silent Rescores copy (test_claims_audit.py pattern).

Unlike the other modules' audits, every check here is RANGE-FREE: the
module launches with no accumulated record, so there is no number a range
could honestly bound. The copy makes structural promises instead — events
split cleanly by type, version shifts and first scores never chart as
up/down, every rescore compares the same CVSS version, the log only ever
grows forward — and those are asserted as structural truths against
whatever data has accumulated. Each CLAIMS entry quotes the copy verbatim
(test_claims_anchors.py checks the quote still exists in editorial.js).
Never silence a failure here: fix the copy or the pipeline, never the test.
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


def _family(label: str) -> str:
    """"v3.1" -> "v3"; the pre-2026-09-20 family label "v3" -> "v3"."""
    return label.split(".", 1)[0]


def test_events_by_type_sum_to_total():
    # editorial.js (rescores.html): the catalog block is quoted as the
    # audit trail — "every event is exactly one of four change types".
    d = load_log()
    totals = d["catalog"]["totals"]
    assert set(totals) == {"rescore", "version_shift", "first_score",
                           "score_removed"}
    assert sum(totals.values()) == d["catalog"]["events_total"]


def test_weekly_series_carry_the_same_events():
    # hero caption: "backfilled first scores and CVSS version changes ride
    # along as separate muted counts" — each type's weekly counts must
    # reproduce its catalog total exactly.
    d = load_log()
    weeks = d["weeks"]
    totals = d["catalog"]["totals"]
    assert sum(w["rescore_up"] + w["rescore_down"] for w in weeks) == \
        totals["rescore"]
    for key in ("first_score", "version_shift", "score_removed"):
        assert sum(w[key] for w in weeks) == totals[key]


def check_direction_exists_only_for_rescores(rows: list[dict]) -> None:
    # magnitude caption: "the new score minus the old, always on the same
    # CVSS version — an edit that changes version, 3.0 to 3.1 included, is
    # a version shift and never lands here". On the committed log only
    # rescore rows may read as a same-version score movement. Rows written
    # before 2026-09-20 carry the version family only ("v3"); a rescore
    # row diffed on the migration night pairs that family label with the
    # exact one ("v3" -> "v3.1"), so the invariant is: both cells filled,
    # same family, and — once both sides are exact — identical.
    for row in rows:
        t = row["change_type"]
        if t == "rescore":
            old, new = row["version_old"], row["version_new"]
            assert old and new
            assert _family(old) == _family(new), row
            if "." in old and "." in new:
                assert old == new, row
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


def check_log_dates_monotonic(rows: list[dict]) -> None:
    # hero caption: "This record starts at first deploy and deepens
    # nightly." — an append-only log's dates never go backward.
    dates = [row["observed_date"] for row in rows]
    assert dates == sorted(dates)


def check_every_event_names_a_cna(rows: list[dict]) -> None:
    # editors caption: each rescore "is filed under the CNA named as
    # assigner on the record the night the edit was seen" — every logged
    # row carries that name; the log never attributes an edit to nobody.
    for row in rows:
        assert row["cna"], row


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


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion) — the quotes are
# anchored by test_claims_anchors.py; the checks read the committed CSV.
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "an edit that changes version, 3.0 to 3.1 included, is a version "
        "shift and never lands here",
        "history/rescore_log.csv",
        check_direction_exists_only_for_rescores,
    ),
    (
        "The log starts at first deploy and grows nightly.",
        "history/rescore_log.csv",
        check_log_dates_monotonic,
    ),
    (
        "filed under the CNA named as assigner on the record the night "
        "the edit was seen",
        "history/rescore_log.csv",
        check_every_event_names_a_cna,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load_csv())
