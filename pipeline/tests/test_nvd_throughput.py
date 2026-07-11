"""NVD throughput: state diff/migration, queue-day math, CSV round-trip,
row merging (last run per date wins), and the JSON builder's contract."""
from __future__ import annotations

import pytest

from pipeline import contracts, nvd_throughput

TODAY = "2026-07-09"
GENERATED_AT = "2026-07-09T00:00:00Z"


def _state(statuses, since=None, last_full="2026-07-01T06:00:00Z",
           durations=None):
    state = {"version": 1, "last_full_sync": last_full,
             "last_sync": "2026-07-08T06:00:00Z", "statuses": statuses}
    if since is not None:
        state["status_since"] = since
    if durations is not None:
        state["queue_durations"] = durations
    return state


# --------------------------------------------------------------- diffing --

def test_every_transition_kind_is_counted_once():
    prev = _state({"CVE-1": "Awaiting Analysis",     # -> Analyzed
                   "CVE-2": "Awaiting Analysis",     # -> Deferred
                   "CVE-3": "Analyzed",              # -> Modified
                   "CVE-4": "Received",              # unchanged
                   "CVE-5": "Undergoing Analysis"},  # -> Analyzed
                  since={"CVE-1": "2026-07-01"})
    now = _state({"CVE-1": "Analyzed", "CVE-2": "Deferred",
                  "CVE-3": "Modified", "CVE-4": "Received",
                  "CVE-5": "Analyzed",
                  "CVE-6": "Received",              # brand new
                  "CVE-7": "Awaiting Analysis"})    # brand new
    t = nvd_throughput.diff_transitions(prev, now, TODAY)
    assert t["counts"] == {"received_new": 1, "entered_awaiting": 1,
                           "analyzed_from_awaiting": 2,
                           "deferred_from_awaiting": 1, "modified_re": 1}
    assert t["resweep"] is False


def test_queue_days_only_for_known_since_dates():
    prev = _state({"CVE-1": "Awaiting Analysis",
                   "CVE-2": "Awaiting Analysis"},
                  since={"CVE-1": "2026-07-01"})  # CVE-2's since unknown
    now = _state({"CVE-1": "Analyzed", "CVE-2": "Analyzed"})
    t = nvd_throughput.diff_transitions(prev, now, TODAY)
    assert t["counts"]["analyzed_from_awaiting"] == 2  # both count as flow
    assert t["durations"] == [8]  # but only the known since yields days


def test_old_format_state_migrates_cleanly():
    """A pre-tracker state (plain statuses, no status_since) must diff
    without crashing: transitions count, all since-dates read unknown, no
    duration is ever faked."""
    prev = {"version": 1, "last_full_sync": "2026-07-01T06:00:00Z",
            "last_sync": "2026-07-08T06:00:00Z",
            "statuses": {"CVE-1": "Awaiting Analysis",
                         "CVE-2": "Analyzed"}}
    now = _state({"CVE-1": "Analyzed", "CVE-2": "Analyzed"})
    t = nvd_throughput.diff_transitions(prev, now, TODAY)
    assert t["counts"]["analyzed_from_awaiting"] == 1
    assert t["durations"] == []          # never fake a since_date
    assert t["status_since"] == {"CVE-1": TODAY}  # observed change only


def test_foreign_status_since_shape_reads_as_unknown():
    prev = _state({"CVE-1": "Awaiting Analysis"}, since=None)
    prev["status_since"] = ["not", "a", "dict"]
    now = _state({"CVE-1": "Analyzed"})
    t = nvd_throughput.diff_transitions(prev, now, TODAY)
    assert t["counts"]["analyzed_from_awaiting"] == 1
    assert t["durations"] == []


def test_unchanged_status_carries_since_forward():
    prev = _state({"CVE-1": "Awaiting Analysis", "CVE-2": "Received"},
                  since={"CVE-1": "2026-07-01"})
    now = _state({"CVE-1": "Awaiting Analysis", "CVE-2": "Received"})
    t = nvd_throughput.diff_transitions(prev, now, TODAY)
    assert t["status_since"] == {"CVE-1": "2026-07-01"}  # CVE-2 stays unknown
    assert all(v == 0 for v in t["counts"].values())


def test_no_previous_state_yields_no_transitions():
    """Diffing against nothing would count the whole corpus as one day's
    flow — the first run must instead produce no row at all."""
    now = _state({"CVE-1": "Received", "CVE-2": "Awaiting Analysis"})
    assert nvd_throughput.diff_transitions(None, now, TODAY) is None
    assert nvd_throughput.diff_transitions({}, now, TODAY) is None
    assert nvd_throughput.diff_transitions(
        {"statuses": {}}, now, TODAY) is None


def test_new_cve_arriving_as_modified_is_not_re_modified():
    """A CVE we never saw before that appears as Modified is healed drift
    (a resweep catching up), not a re-modification we observed."""
    prev = _state({"CVE-1": "Analyzed"})
    now = _state({"CVE-1": "Analyzed", "CVE-2": "Modified"},
                 last_full="2026-07-09T06:00:00Z")
    t = nvd_throughput.diff_transitions(prev, now, TODAY)
    assert t["counts"]["modified_re"] == 0
    assert t["resweep"] is True  # last_full_sync changed


def test_negative_and_malformed_since_dates_never_yield_durations():
    prev = _state({"CVE-1": "Awaiting Analysis",
                   "CVE-2": "Awaiting Analysis"},
                  since={"CVE-1": "2026-12-31",   # after today: clock skew
                         "CVE-2": "not-a-date"})
    now = _state({"CVE-1": "Analyzed", "CVE-2": "Analyzed"})
    t = nvd_throughput.diff_transitions(prev, now, TODAY)
    assert t["counts"]["analyzed_from_awaiting"] == 2
    assert t["durations"] == []


# ------------------------------------------------------- attach_tracking --

def test_attach_tracking_accumulates_durations_on_the_new_state():
    prev = _state({"CVE-1": "Awaiting Analysis"},
                  since={"CVE-1": "2026-07-01"}, durations=[3, 5])
    now = _state({"CVE-1": "Analyzed"})
    t = nvd_throughput.diff_transitions(prev, now, TODAY)
    accumulated = nvd_throughput.attach_tracking(now, prev, t)
    assert accumulated == [3, 5, 8]
    assert now["queue_durations"] == [3, 5, 8]
    assert now["status_since"] == {"CVE-1": TODAY}


def test_attach_tracking_without_transitions_adds_no_keys():
    now = _state({"CVE-1": "Received"})
    assert nvd_throughput.attach_tracking(now, None, None) == []
    assert "status_since" not in now       # never bulk-initialized
    assert "queue_durations" not in now


def test_attach_tracking_drops_corrupt_prior_durations():
    prev = _state({"CVE-1": "Received"}, durations=[2, -1, "x", True])
    now = _state({"CVE-1": "Received"})
    t = nvd_throughput.diff_transitions(prev, now, TODAY)
    assert nvd_throughput.attach_tracking(now, prev, t) == [2]


# ------------------------------------------------------------------- CSV --

def _row(date=TODAY, **overrides):
    row = nvd_throughput.throughput_row(
        {"received_new": 4, "entered_awaiting": 3,
         "analyzed_from_awaiting": 2, "deferred_from_awaiting": 1},
        [5, 7], date, False)
    row.update(overrides)
    return row


def test_csv_round_trip_preserves_null_median(tmp_path):
    path = tmp_path / "nvd_throughput.csv"
    rows = [_row("2026-07-08"), _row("2026-07-09")]
    nvd_throughput.write_rows(path, rows)
    header = path.read_text(encoding="utf-8").splitlines()[0]
    assert header == ",".join(nvd_throughput.COLUMNS)
    back = nvd_throughput.read_rows(path)
    assert back == rows
    assert back[0]["median_queue_days"] is None  # 2 known < threshold


def test_csv_round_trip_preserves_published_median(tmp_path):
    path = tmp_path / "nvd_throughput.csv"
    durations = [3] * 20 + [8] * 20  # 40 known -> median publishes
    row = nvd_throughput.throughput_row(
        {"received_new": 0, "entered_awaiting": 0,
         "analyzed_from_awaiting": 1, "deferred_from_awaiting": 0},
        durations, TODAY, True)
    assert row["median_queue_days"] == 5.5
    assert row["n_known_duration"] == 40
    assert row["resweep"] == 1
    nvd_throughput.write_rows(path, [row])
    assert nvd_throughput.read_rows(path) == [row]


def test_same_date_last_run_wins():
    rows = [_row("2026-07-08"), _row("2026-07-09")]
    replacement = _row("2026-07-09", received_new=99)
    merged = nvd_throughput.merge_row(rows, replacement)
    assert [r["date"] for r in merged] == ["2026-07-08", "2026-07-09"]
    assert merged[-1]["received_new"] == 99


def test_missing_file_reads_empty_and_malformed_rows_fail_loudly(tmp_path):
    assert nvd_throughput.read_rows(tmp_path / "absent.csv") == []
    path = tmp_path / "nvd_throughput.csv"
    path.write_text(",".join(nvd_throughput.COLUMNS)
                    + "\n2026-07-09,1,2,x,4,,0,0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed throughput row"):
        nvd_throughput.read_rows(path)


# --------------------------------------------------------------- builder --

def test_median_stays_null_below_threshold():
    row = nvd_throughput.throughput_row(
        {"received_new": 0, "entered_awaiting": 0,
         "analyzed_from_awaiting": 1, "deferred_from_awaiting": 0},
        [4] * (nvd_throughput.MIN_KNOWN_DURATIONS - 1), TODAY, False)
    assert row["median_queue_days"] is None
    row = nvd_throughput.throughput_row(
        {"received_new": 0, "entered_awaiting": 0,
         "analyzed_from_awaiting": 1, "deferred_from_awaiting": 0},
        [4] * nvd_throughput.MIN_KNOWN_DURATIONS, TODAY, False)
    assert row["median_queue_days"] == 4.0


def test_build_validates_and_reads_the_latest_row():
    rows = [_row("2026-07-08"), _row("2026-07-09")]
    obj = nvd_throughput.build_nvd_throughput(rows, GENERATED_AT)
    contracts.validate("nvd_throughput.json", obj)
    assert obj["min_known_duration"] == nvd_throughput.MIN_KNOWN_DURATIONS
    assert obj["queue"] == {"median_days": None, "n_known_duration": 2}
    assert [h["date"] for h in obj["history"]] == ["2026-07-08", "2026-07-09"]
    assert obj["history"][0]["resweep"] is False


def test_build_with_empty_history_is_valid():
    """The record starts at first deploy: an empty history must build and
    validate — the site renders the thin-launch note, not an error."""
    obj = nvd_throughput.build_nvd_throughput([], GENERATED_AT)
    contracts.validate("nvd_throughput.json", obj)
    assert obj["queue"] == {"median_days": None, "n_known_duration": 0}
    assert obj["history"] == []


def test_contract_rejects_premature_median():
    obj = nvd_throughput.build_nvd_throughput([_row()], GENERATED_AT)
    obj["queue"]["median_days"] = 4.0  # with n_known_duration = 2
    with pytest.raises(contracts.ContractViolation, match="median"):
        contracts.validate("nvd_throughput.json", obj)
