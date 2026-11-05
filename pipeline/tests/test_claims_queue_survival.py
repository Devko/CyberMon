"""Claims audit for the NVD queue survival section (cve.html, section key
``queue_survival``), read from the ``queue_survival`` block of
nvd_throughput.json.

The record behind the curve starts with the first nightly run after the
section shipped (2026-11-05), so most guards skip until the block exists
and the curve is published (``ready``). Two kinds of check never skip
once the block exists:

* structure: the curve never rises, stays within 0-100%, every step has
  at least ``min_at_risk`` CVEs under watch, and the censored counts (the
  CVEs still waiting) are present — the point of a survival curve;
* thresholds: the numbers the copy quotes (28 days, 30 exits, 30 CVEs
  under watch) are the pipeline's and the block's.

The headline is a template filled from the 30-day checkpoint; its guard
checks that the checkpoint it reads agrees with the curve.
"""
from __future__ import annotations

import json

import pytest

from . import claims_support

from pipeline import contracts, nvd_throughput

DATA_DIR = claims_support.DATA_DIR

_meta_path = DATA_DIR / "meta.json"
if not _meta_path.exists():
    pytest.skip("site/data/meta.json missing — no committed data to audit",
                allow_module_level=True)
if json.loads(_meta_path.read_text("utf-8")).get("sample") is True:
    pytest.skip("site/data holds sample data — claims audit only judges "
                "real data", allow_module_level=True)


def _block() -> dict:
    path = DATA_DIR / "nvd_throughput.json"
    if not path.exists():
        pytest.skip("nvd_throughput.json missing — record not started yet")
    obj = claims_support.read_json(path)
    if "queue_survival" not in obj:
        pytest.skip("no queue_survival block yet — the exit log starts with "
                    "the first nightly run after 2026-11-05")
    return obj["queue_survival"]


def _ready_block() -> dict:
    block = _block()
    if not block["ready"]:
        pytest.skip(f"curve not published yet: {block['log_days']} days, "
                    f"{sum(block['exits'].values())} exits logged")
    return block


def test_structure_whenever_the_block_exists() -> None:
    block = _block()
    contracts._validate_queue_survival(block)  # the full contract
    for key in ("waiting", "requeued"):
        assert isinstance(block["censored"][key], int) \
            and block["censored"][key] >= 0, block["censored"]
    pcts = [p["pct_waiting"] for p in block["curve"]]
    assert all(0.0 <= p <= 100.0 for p in pcts), pcts
    assert all(a >= b for a, b in zip(pcts, pcts[1:])), (
        "the share still waiting rose between two days")
    assert all(p["at_risk"] >= block["min_at_risk"] for p in block["curve"])
    if block["curve"]:
        # Censoring is what the curve adds over the median of finished
        # waits: once anything has exited, someone must still be watched.
        assert block["censored"]["waiting"] + block["censored"]["requeued"] \
            > 0, "the curve counts no CVE still waiting"


def check_thresholds(_d: dict) -> None:
    # nodata + methodology: "The curve is published once the exit log covers
    # 28 days and 30 exits." / "stops at the first day with fewer than 30
    # CVEs under watch". The copy states the numbers; the pipeline and the
    # published block must use the same ones.
    assert nvd_throughput.MIN_LOG_DAYS == 28
    assert nvd_throughput.MIN_KNOWN_DURATIONS == 30
    assert nvd_throughput.MIN_AT_RISK == 30
    block = _block()
    assert (block["min_log_days"], block["min_exits"],
            block["min_at_risk"]) == (28, 30, 30)


def check_day_30_share(_d: dict) -> None:
    # headlineTemplate: "{pct} of the CVEs that enter NVD's analysis queue
    # are still in it 30 days later." cve.js fills it only when the curve is
    # ready and has a day-30 checkpoint; that checkpoint must be the curve's
    # own value at day 30, with enough CVEs under watch there.
    assert 30 in nvd_throughput.CHECKPOINT_DAYS
    block = _ready_block()
    day30 = next((c for c in block["checkpoints"] if c["day"] == 30), None)
    if day30 is None:
        pytest.skip(f"curve reaches day {block['horizon_days']}, not 30: "
                    f"the static headline stays")
    at_or_before = [p for p in block["curve"] if p["day"] <= 30]
    expected = at_or_before[-1]["pct_waiting"] if at_or_before else 100.0
    assert day30["pct_waiting"] == expected
    assert day30["at_risk"] >= block["min_at_risk"]


def check_median_card(_d: dict) -> None:
    # stat card: "{days} days" — "median wait in the analysis queue, CVEs
    # still waiting included" — or "over {days} days" when the curve has
    # not reached 50% by its last day.
    block = _ready_block()
    curve = block["curve"]
    if block["median_days"] is None:
        assert all(p["pct_waiting"] >= 50.0 for p in curve)
        assert block["horizon_days"] == curve[-1]["day"]
    else:
        first = next(p for p in curve if p["pct_waiting"] <= 50.0)
        assert first["day"] == block["median_days"]


def check_stat_note_counts(_d: dict) -> None:
    # stat note: "from {exits} exits ({deferred} of them deferred) and
    # {waiting} CVEs still waiting, followed since {log_start}".
    block = _ready_block()
    exits = sum(block["exits"].values())
    assert 0 <= block["exits"]["deferred"] <= exits
    assert exits >= block["min_exits"]
    assert block["log_start"] is not None


CLAIMS = [
    (
        "The curve is published once the exit log covers 28 days and 30 exits.",
        "nvd_throughput.json",
        check_thresholds,
    ),
    (
        "stops at the first day with fewer than 30 CVEs under watch",
        "nvd_throughput.json",
        check_thresholds,
    ),
    (
        "{pct} of the CVEs that enter NVD's analysis queue are still in it 30 "
        "days later.",
        "nvd_throughput.json",
        check_day_30_share,
    ),
    (
        "median wait in the analysis queue, CVEs still waiting included",
        "nvd_throughput.json",
        check_median_card,
    ),
    (
        "from {exits} exits ({deferred} of them deferred) and {waiting} CVEs "
        "still waiting, followed since {log_start}",
        "nvd_throughput.json",
        check_stat_note_counts,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[f"{c[2].__name__}:{i}" for i, c in enumerate(CLAIMS)],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(None)
