"""Claims audit for the NVD throughput section (test_claims_audit.py
pattern). Enforced on every committed edition:

* the irreplaceable history CSV keeps exactly its contracted columns,
* every transition count is a non-negative integer,
* the median stays null until the documented threshold of known-duration
  transitions is reached — the copy promises "median publishes only past
  the threshold", and this is that promise's standing guard,
* the CLAIMS below: the headline's deferred share (added 2026-11-04, when
  the record held 110 nightly comparisons; until then the headline only
  described the section).

A new quantitative claim in the throughput copy gets its check here in the
same commit as the copy — never the copy alone.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from . import claims_support

from pipeline import contracts, nvd_throughput

DATA_DIR = claims_support.DATA_DIR

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


def _load_json() -> dict:
    path = DATA_DIR / "nvd_throughput.json"
    if not path.exists():
        pytest.skip("nvd_throughput.json missing — record not started yet")
    return claims_support.read_json(path)


def _load_csv_rows() -> list[dict]:
    path = DATA_DIR / "history" / "nvd_throughput.csv"
    if not path.exists():
        pytest.skip("history/nvd_throughput.csv missing — record not "
                    "started yet")
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert tuple(reader.fieldnames or ()) == nvd_throughput.COLUMNS, (
            "nvd_throughput.csv columns drifted from the contract — this "
            "file is the irreplaceable historical record; never rewrite "
            "its shape without a migration"
        )
        return list(reader)


def test_csv_columns_and_row_shapes() -> None:
    rows = _load_csv_rows()
    for row in rows:
        for col in ("received_new", "entered_awaiting",
                    "analyzed_from_awaiting", "deferred_from_awaiting",
                    "n_known_duration"):
            assert int(row[col]) >= 0, (
                f"{col} must be a non-negative count; "
                f"row {row['date']} says {row[col]!r}"
            )
        assert row["resweep"] in ("0", "1"), (
            f"resweep is a 0/1 flag; row {row['date']} says "
            f"{row['resweep']!r}"
        )
        if row["median_queue_days"]:
            assert float(row["median_queue_days"]) >= 0


def test_csv_median_stays_null_until_threshold() -> None:
    # The methodology promises: no median on a small sample. Every
    # committed row must honor it.
    for row in _load_csv_rows():
        if int(row["n_known_duration"]) < nvd_throughput.MIN_KNOWN_DURATIONS:
            assert row["median_queue_days"] == "", (
                f"row {row['date']} publishes a median from only "
                f"{row['n_known_duration']} known durations (threshold "
                f"{nvd_throughput.MIN_KNOWN_DURATIONS})"
            )


def test_json_validates_and_thresholds_match_the_pipeline() -> None:
    obj = _load_json()
    contracts.validate("nvd_throughput.json", obj)
    assert obj["min_known_duration"] == nvd_throughput.MIN_KNOWN_DURATIONS, (
        "the committed threshold drifted from the pipeline's documented "
        "MIN_KNOWN_DURATIONS — copy and data must move together"
    )


# The Analyzed count missed Received -> Analyzed exits before this date
# (throughput methodology); the share is checked on the rows after it too,
# so the headline does not rest on the undercount.
ANALYZED_FIX_DATE = "2026-09-23"


def _deferred_share(rows: list[dict]) -> float:
    analyzed = sum(r["analyzed_from_awaiting"] for r in rows)
    deferred = sum(r["deferred_from_awaiting"] for r in rows)
    assert analyzed + deferred > 0, "no queue exits in the record"
    return 100.0 * deferred / (analyzed + deferred)


def check_close_to_half_deferred(d: dict) -> None:
    # throughput headline: "Since July 2026, NVD has deferred close to half
    # of the CVEs leaving its analysis queue." Deferred over Analyzed plus
    # Deferred exits, summed over the record (the methodology's definition),
    # "Close to half" is 40-55%. The undercount of Analyzed exits before the
    # fix can only inflate the deferred share, so the rows after the fix
    # must clear the 40% floor on their own. (2026-11-04: 13,136 of 29,456 =
    # 44.6% over the record, 43-47% since mid-September; about 47% after
    # 2026-09-23, down from 55-58% while that subset held a few thousand
    # exits.)
    hist = d["history"]
    assert hist and hist[0]["date"].startswith("2026-07"), (
        f"'Since July 2026' vs a record starting {hist[0]['date'] if hist else None}")
    share = _deferred_share(hist)
    claims_support.record(share, lo=40, hi=55, unit="%",
                          note="deferred, whole record")
    assert 40 <= share <= 55, (
        f"'close to half of the CVEs leaving its analysis queue' vs "
        f"{share:.1f}% deferred over the record")
    after = _deferred_share([r for r in hist if r["date"] > ANALYZED_FIX_DATE])
    claims_support.record(after, lo=40, unit="%",
                          note=f"deferred, after {ANALYZED_FIX_DATE}")
    assert after >= 40, (
        f"'close to half' rests on the pre-{ANALYZED_FIX_DATE} Analyzed "
        f"undercount: {after:.1f}% deferred after the fix")


CLAIMS = [
    (
        "Since July 2026, NVD has deferred close to half of the CVEs leaving its analysis queue.",
        "nvd_throughput.json",
        check_close_to_half_deferred,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(_load_json())
