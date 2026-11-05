"""NVD queue survival curve: the Kaplan–Meier arithmetic on synthetic
histories (censoring, delayed entry, the at-risk cut), the exit log the
nightly diff keeps on the state, and the block's contract."""
from __future__ import annotations

import copy

import pytest

from pipeline import contracts, nvd_throughput
from pipeline.nvd_throughput import (attach_tracking, build_queue_survival,
                                     diff_transitions, kaplan_meier)

GENERATED_AT = "2026-07-09T00:00:00Z"


def _steps(result):
    return [(day, n, d, round(s, 6)) for day, n, d, s in result["steps"]]


# ------------------------------------------------------------ the KM math --

def test_km_without_censoring_is_the_empirical_survival():
    km = kaplan_meier([(0, 1, True), (0, 2, True), (0, 3, True),
                       (0, 4, True)])
    assert _steps(km) == [(1, 4, 1, 0.75), (2, 3, 1, 0.5), (3, 2, 1, 0.25),
                          (4, 1, 1, 0.0)]
    assert km["horizon"] == 4


def test_km_censored_subjects_stay_at_risk_through_their_last_day():
    # Textbook case: exits at 1, 3, 4; still waiting at 2 and 5.
    km = kaplan_meier([(0, 1, True), (0, 2, False), (0, 3, True),
                       (0, 4, True), (0, 5, False)])
    assert _steps(km) == [(1, 5, 1, 0.8), (3, 3, 1, 0.533333),
                          (4, 2, 1, 0.266667)]
    assert km["at_risk"] == [0, 5, 4, 3, 2, 1]
    assert km["horizon"] == 5


def test_km_censoring_on_an_exit_day_counts_the_censored_subject():
    # Censored at day 2 means "still in at day 2": in the risk set there.
    km = kaplan_meier([(0, 2, True), (0, 2, False)])
    assert _steps(km) == [(2, 2, 1, 0.5)]


def test_km_dropping_censored_subjects_would_understate_the_wait():
    # The bias the curve exists to remove: three CVEs still waiting at day
    # 10 are left out of a median of finished waits, not out of the curve.
    finished = [(0, 2, True), (0, 3, True)]
    waiting = [(0, 10, False)] * 3
    km = kaplan_meier(finished + waiting)
    assert round(km["steps"][-1][3], 6) == 0.6   # 60% still waiting at 3
    assert km["horizon"] == 10


def test_km_delayed_entry_counts_a_subject_only_from_its_entry_age():
    # Two episodes watched from their first sighting; two picked up at
    # age 3 when the log started. The late ones are not at risk at day 2.
    km = kaplan_meier([(0, 2, True), (3, 5, True), (3, 6, False),
                       (0, 4, False)])
    assert km["at_risk"] == [0, 2, 2, 1, 3, 2, 1]
    assert _steps(km) == [(2, 2, 1, 0.5), (5, 2, 1, 0.25)]


def test_km_cuts_the_curve_where_the_risk_set_runs_thin():
    obs = [(0, day, True) for day in range(1, 11)]  # one exit a day
    km = kaplan_meier(obs, min_at_risk=4)
    # at risk on day u: 11 - u; day 8 has 3 < 4 under watch
    assert km["horizon"] == 7
    assert [s[0] for s in km["steps"]] == list(range(1, 8))
    assert kaplan_meier(obs, min_at_risk=20)["horizon"] == 0


def test_km_skips_malformed_observations():
    km = kaplan_meier([(0, 0, True), (2, 1, True), (-1, 3, True),
                       ("0", 2, True), (0, 2, True)])
    assert _steps(km) == [(2, 1, 1, 0.0)]


def test_km_with_no_observations_is_empty():
    km = kaplan_meier([])
    assert km == {"steps": [], "horizon": 0, "at_risk": [0]}


# --------------------------------------------- the exit log on the state --

def _state(statuses, since=None, **extra):
    state = {"version": 1, "last_full_sync": "2026-07-01T06:00:00Z",
             "last_sync": "2026-07-08T06:00:00Z", "statuses": statuses}
    if since is not None:
        state["status_since"] = since
    state.update(extra)
    return state


def _night(prev, statuses, today):
    """Run one nightly diff + attach, as the pipeline does."""
    new = _state(statuses)
    transitions = diff_transitions(prev, new, today)
    attach_tracking(new, prev, transitions)
    return new


def test_diff_lists_every_end_of_a_timed_episode():
    prev = _state({"CVE-1": "Awaiting Analysis", "CVE-2": "Undergoing Analysis",
                   "CVE-3": "Awaiting Analysis", "CVE-4": "Awaiting Analysis",
                   "CVE-5": "Awaiting Analysis", "CVE-6": "Awaiting Analysis",
                   "CVE-7": "Awaiting Analysis"},
                  since={"CVE-1": "2026-07-01", "CVE-2": "2026-07-02",
                         "CVE-3": "2026-07-03", "CVE-4": "2026-07-04",
                         "CVE-5": "2026-07-05",
                         "CVE-7": "2026-07-06"})       # CVE-6 untimed
    now = _state({"CVE-1": "Analyzed", "CVE-2": "Deferred",
                  "CVE-3": "Rejected", "CVE-4": "Received",
                  "CVE-5": "Undergoing Analysis",    # same episode
                  "CVE-6": "Analyzed",               # untimed: not listed
                  "CVE-7": "Awaiting Analysis"})     # still waiting
    t = diff_transitions(prev, now, "2026-07-09")
    assert sorted(t["queue_exits"]) == [("2026-07-01", 8, "A"),
                                        ("2026-07-02", 7, "D"),
                                        ("2026-07-03", 6, "O"),
                                        ("2026-07-04", 5, "R")]
    assert t["date"] == "2026-07-09"


def test_first_run_with_tracking_starts_the_log_and_logs_nothing():
    prev = _state({"CVE-1": "Awaiting Analysis", "CVE-2": "Awaiting Analysis"},
                  since={"CVE-1": "2026-07-01", "CVE-2": "2026-07-02"})
    new = _night(prev, {"CVE-1": "Analyzed", "CVE-2": "Awaiting Analysis"},
                 "2026-07-09")
    assert new["queue_log_start"] == "2026-07-09"
    assert new["queue_exits"] == []
    block = build_queue_survival(new, "2026-07-09")
    contracts._validate_queue_survival(block)
    # CVE-2 is open but the log has watched it for zero nights.
    assert block["log_start"] == "2026-07-09" and block["log_days"] == 0
    assert block["censored"] == {"waiting": 0, "requeued": 0}
    assert block["curve"] == [] and block["ready"] is False


def test_no_previous_state_leaves_no_log():
    new = _state({"CVE-1": "Awaiting Analysis"})
    attach_tracking(new, None, diff_transitions(None, new, "2026-07-09"))
    assert "queue_log_start" not in new
    block = build_queue_survival(new, "2026-07-09")
    contracts._validate_queue_survival(block)
    assert block["log_start"] is None and block["curve"] == []
    assert block["exits"] == {"analyzed": 0, "deferred": 0, "other": 0}


def test_logged_exits_carry_their_entry_age():
    # The log started on 07-05 with CVE-1 (seen since 07-01, age 4) and
    # CVE-2 (since 07-06, after the start) both open.
    prev = _state({"CVE-1": "Awaiting Analysis", "CVE-2": "Awaiting Analysis",
                   "CVE-3": "Awaiting Analysis"},
                  since={"CVE-1": "2026-07-01", "CVE-2": "2026-07-06",
                         "CVE-3": "2026-07-03"},
                  queue_log_start="2026-07-05", queue_exits=[[3, 0, "A"]])
    new = _night(prev, {"CVE-1": "Deferred", "CVE-2": "Analyzed",
                        "CVE-3": "Received"}, "2026-07-09")
    assert new["queue_log_start"] == "2026-07-05"
    assert sorted(new["queue_exits"]) == [[3, 0, "A"], [3, 0, "A"],
                                          [6, 2, "R"], [8, 4, "D"]]


def test_same_date_rerun_on_the_start_night_logs_nothing():
    prev = _state({"CVE-1": "Awaiting Analysis"}, since={"CVE-1": "2026-07-01"},
                  queue_log_start="2026-07-09", queue_exits=[])
    new = _night(prev, {"CVE-1": "Analyzed"}, "2026-07-09")
    assert new["queue_exits"] == []  # wait 8 == entry 8: never watched


def test_corrupt_log_entries_are_dropped():
    prev = _state({"CVE-1": "Received"},
                  queue_log_start="2026-07-01",
                  queue_exits=[[5, 0, "A"], [2, 2, "A"], [-1, 0, "D"],
                               [4, 0, "X"], [True, 0, "A"], "junk",
                               [7, 1, "R"]])
    new = _night(prev, {"CVE-1": "Received"}, "2026-07-09")
    assert new["queue_exits"] == [[5, 0, "A"], [7, 1, "R"]]


def test_a_week_of_nights_matches_the_hand_computed_curve():
    """Five episodes, each followed from its first sighting (the log
    starts on 07-01, the night E is first seen; 07-07 has no run):
    A: 07-02 -> Analyzed 07-04 (2 days)    B: 07-02 -> Deferred 07-05 (3)
    C: 07-03 -> still waiting 07-09 (6)    D: 07-04 -> Received 07-06 (2)
    E: 07-01 -> Analyzed 07-08 (7)
    Hand KM (exits at 2, 3, 7; censored D at 2, C at 6):
    day 2: n=5, d=1 -> 0.8; day 3: n=3, d=1 -> 0.5333; day 7: n=1, d=1 -> 0
    """
    s = _state({"CVE-E": "Awaiting Analysis"}, since={"CVE-E": "2026-07-01"},
               queue_log_start="2026-07-01", queue_exits=[])
    nights = [
        ("2026-07-02", {"CVE-A": "Awaiting Analysis",
                        "CVE-B": "Awaiting Analysis"}),
        ("2026-07-03", {"CVE-A": "Awaiting Analysis",
                        "CVE-B": "Undergoing Analysis",
                        "CVE-C": "Awaiting Analysis"}),
        ("2026-07-04", {"CVE-A": "Analyzed", "CVE-B": "Undergoing Analysis",
                        "CVE-C": "Awaiting Analysis",
                        "CVE-D": "Awaiting Analysis"}),
        ("2026-07-05", {"CVE-A": "Analyzed", "CVE-B": "Deferred",
                        "CVE-C": "Awaiting Analysis",
                        "CVE-D": "Awaiting Analysis"}),
        ("2026-07-06", {"CVE-A": "Analyzed", "CVE-B": "Deferred",
                        "CVE-C": "Awaiting Analysis", "CVE-D": "Received"}),
        ("2026-07-08", {"CVE-A": "Analyzed", "CVE-B": "Deferred",  # 07-07
                        "CVE-C": "Awaiting Analysis",              # missed
                        "CVE-D": "Received", "CVE-E": "Analyzed"}),
        ("2026-07-09", {"CVE-A": "Analyzed", "CVE-B": "Deferred",
                        "CVE-C": "Awaiting Analysis", "CVE-D": "Received",
                        "CVE-E": "Analyzed"}),
    ]
    for today, statuses in nights:
        statuses = {"CVE-E": "Awaiting Analysis", **statuses}
        s = _night(s, statuses, today)
    assert sorted(s["queue_exits"]) == [[2, 0, "A"], [2, 0, "R"],
                                        [3, 0, "D"], [7, 0, "A"]]
    block = build_queue_survival(s, "2026-07-09", min_exits=1,
                                 min_log_days=1, min_at_risk=1)
    contracts._validate_queue_survival(block)
    assert block["exits"] == {"analyzed": 2, "deferred": 1, "other": 0}
    assert block["censored"] == {"waiting": 1, "requeued": 1}
    assert [(p["day"], p["pct_waiting"], p["at_risk"], p["exits"])
            for p in block["curve"]] == [(2, 80.0, 5, 1), (3, 53.3, 3, 1),
                                         (7, 0.0, 1, 1)]
    assert block["median_days"] == 7
    assert block["horizon_days"] == 7
    assert block["checkpoints"] == [{"day": 7, "pct_waiting": 0.0,
                                     "at_risk": 1}]
    assert block["log_days"] == 8 and block["ready"] is True


def test_open_episodes_from_before_the_log_enter_late():
    # Log started 07-05. CVE-1 has waited since 06-25 (age 10 at the start)
    # and is still waiting on 07-09 (age 14); it is under watch only for
    # days 11-14. CVE-2 left at age 3 having been seen from age 0.
    state = _state({"CVE-1": "Awaiting Analysis", "CVE-2": "Analyzed"},
                   since={"CVE-1": "2026-06-25", "CVE-2": "2026-07-09"},
                   queue_log_start="2026-07-05", queue_exits=[[3, 0, "A"]])
    block = build_queue_survival(state, "2026-07-09", min_exits=1,
                                 min_log_days=1, min_at_risk=1)
    contracts._validate_queue_survival(block)
    assert block["censored"]["waiting"] == 1
    # day 3: only CVE-2 at risk -> 0%; the curve stops where nobody is
    # under watch (days 4-10), so CVE-1's late entry cannot extend it.
    assert [(p["day"], p["pct_waiting"]) for p in block["curve"]] == [(3, 0.0)]
    assert block["horizon_days"] == 3


def test_ready_needs_the_log_age_and_the_exit_count():
    exits = [[d, 0, "A"] for d in range(1, 41)]
    waiting = {f"CVE-{i}": "Awaiting Analysis" for i in range(40)}
    since = {cve: "2026-06-01" for cve in waiting}
    base = _state(waiting, since=since, queue_log_start="2026-06-01",
                  queue_exits=exits)
    young = build_queue_survival(base, "2026-06-20")
    assert young["log_days"] == 19 and young["ready"] is False
    assert young["curve"]  # the curve is published, flagged not ready
    old = build_queue_survival(base, "2026-07-09")
    assert old["log_days"] == 38 and old["ready"] is True
    few = copy.deepcopy(base)
    few["queue_exits"] = exits[:nvd_throughput.MIN_KNOWN_DURATIONS - 1]
    assert build_queue_survival(few, "2026-07-09")["ready"] is False
    for block in (young, old):
        contracts._validate_queue_survival(block)
    # Checkpoints only within the horizon: the open episodes are 19 days
    # old on 06-20, so the curve cannot yet say anything about day 30.
    assert young["horizon_days"] == 19
    assert [c["day"] for c in young["checkpoints"]] == [7]
    assert old["horizon_days"] == 38
    assert [c["day"] for c in old["checkpoints"]] == [7, 30]


def test_survival_block_rides_in_nvd_throughput_json():
    block = build_queue_survival(None, "2026-07-09")
    obj = nvd_throughput.build_nvd_throughput([], GENERATED_AT, block)
    contracts.validate("nvd_throughput.json", obj)
    assert obj["queue_survival"]["ready"] is False
    legacy = nvd_throughput.build_nvd_throughput([], GENERATED_AT)
    assert "queue_survival" not in legacy  # older editions stay valid
    contracts.validate("nvd_throughput.json", legacy)


def test_a_fault_in_the_curve_drops_the_block_not_the_night(
        tmp_path, monkeypatch, capsys):
    import json

    from pipeline.__main__ import main

    def broken(*_args, **_kwargs):
        raise ValueError("synthetic fault")

    monkeypatch.setattr(nvd_throughput, "build_queue_survival", broken)
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    obj = json.loads((tmp_path / "nvd_throughput.json").read_text())
    assert "queue_survival" not in obj
    assert len(obj["history"]) == 1  # the night's flow row still lands
    assert "queue survival skipped" in capsys.readouterr().err


# ------------------------------------------------------------- contract --

def _ready_block():
    exits = [[d, 0, "A"] for d in range(1, 41)]
    waiting = {f"CVE-{i}": "Awaiting Analysis" for i in range(40)}
    state = _state(waiting, since={c: "2026-06-01" for c in waiting},
                   queue_log_start="2026-06-01", queue_exits=exits)
    return build_queue_survival(state, "2026-07-09")


@pytest.mark.parametrize("mutate, match", [
    (lambda b: b["curve"][3].update(pct_waiting=99.9), "rises"),
    (lambda b: b["curve"][2].update(pct_waiting=120.0), "pct_waiting"),
    (lambda b: b["curve"][1].update(day=1), "ascending"),
    (lambda b: b["censored"].pop("waiting"), "waiting"),
    (lambda b: b.update(log_days=3), "ready"),
    (lambda b: b["curve"][0].update(at_risk=2), "at_risk"),
    (lambda b: b["checkpoints"][0].update(pct_waiting=1.0), "disagrees"),
    (lambda b: b.update(median_days=1), "median"),
    (lambda b: b.update(horizon_days=999), "horizon"),
])
def test_contract_rejects_a_malformed_curve(mutate, match):
    block = _ready_block()
    contracts._validate_queue_survival(block)
    mutate(block)
    with pytest.raises(contracts.ContractViolation, match=match):
        contracts._validate_queue_survival(block)
