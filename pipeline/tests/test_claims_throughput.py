"""Claims audit for the NVD throughput section (test_claims_audit.py
pattern) — structural assertions only, deliberately: the record starts at
first deploy and carries no accumulated data yet, so there is no number
for the copy to over-claim. What IS enforced, on every committed edition:

* the irreplaceable history CSV keeps exactly its contracted columns,
* every transition count is a non-negative integer,
* the median stays null until the documented threshold of known-duration
  transitions is reached — the copy promises "median publishes only past
  the threshold", and this is that promise's standing guard.

When the record has accumulated enough history for the copy to make
quantitative claims (a real median, a trend), add range-based checks here
in the same commit as the copy — never the copy alone.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from pipeline import contracts, nvd_throughput

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


def _load_json() -> dict:
    path = DATA_DIR / "nvd_throughput.json"
    if not path.exists():
        pytest.skip("nvd_throughput.json missing — record not started yet")
    return json.loads(path.read_text("utf-8"))


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
