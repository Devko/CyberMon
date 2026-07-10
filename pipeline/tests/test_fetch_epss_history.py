"""fetch_epss_history: era labeling, response parsing, sync, round-trip."""
from __future__ import annotations

import json

import pytest

from pipeline import fetch_epss_history as feh


# ------------------------------------------------------------------ model eras

@pytest.mark.parametrize(("score_date", "label"), [
    ("2021-04-13", None),          # the day before EPSS existed
    ("2021-04-14", "v1"),          # first daily scores
    ("2021-11-02", "v1"),          # KEV launch eve
    ("2022-02-03", "v1"), ("2022-02-04", "v2"),
    ("2023-03-06", "v2"), ("2023-03-07", "v3"),
    ("2025-03-16", "v3"), ("2025-03-17", "v4"),
    ("2026-06-14", "v4"), ("2026-06-15", "v5"),
    ("2030-01-01", "v5"),          # open-ended newest era
])
def test_model_label_transitions(score_date, label):
    assert feh.model_label(score_date) == label


def test_known_model_version_tripwire():
    assert feh.known_model_version("v2026.06.15")
    assert feh.known_model_version("v2022.01.01")
    assert not feh.known_model_version("v2027.01.01")  # a future model


def test_model_eras_block_is_contiguous_and_open_ended():
    block = feh.model_eras_block()
    assert [e["label"] for e in block] == list(feh.MODEL_LABELS)
    assert block[0]["from"] == feh.EPSS_FIRST_DAY
    assert block[-1]["to"] is None
    for cur, nxt in zip(block, block[1:]):
        assert cur["to"] < nxt["from"]  # day-before, so strictly earlier


def test_score_date_is_day_before():
    assert feh.score_date_for("2021-11-03") == "2021-11-02"
    assert feh.score_date_for("2024-03-01") == "2024-02-29"  # leap year
    with pytest.raises(ValueError):
        feh.score_date_for("not-a-date")


# ------------------------------------------------------------- response parse

def _envelope(rows):
    return {"status": "OK", "status-code": 200, "total": len(rows),
            "data": rows}


def test_parse_response_scored_and_missing():
    payload = _envelope([{"cve": "CVE-2021-40438", "epss": "0.350640000",
                          "percentile": "0.989232468",
                          "date": "2021-11-02"}])
    entries = feh.parse_response(payload,
                                 ["CVE-2021-40438", "CVE-2021-44228"],
                                 "2021-11-02")
    assert entries["CVE-2021-40438"] == {
        "score_date": "2021-11-02", "epss": 0.35064,
        "percentile": 0.98923, "model": "v1", "reason": None}
    assert entries["CVE-2021-44228"] == {
        "score_date": "2021-11-02", "epss": None, "percentile": None,
        "model": None, "reason": "no_score_for_date"}


def test_parse_response_pre_epss_reason():
    entries = feh.parse_response(_envelope([]), ["CVE-2020-0001"],
                                 "2021-04-13")
    assert entries["CVE-2020-0001"]["reason"] == "pre_epss"


def test_parse_response_missing_percentile_tolerated():
    payload = _envelope([{"cve": "CVE-2021-0001", "epss": "0.01",
                          "date": "2021-05-01"}])
    entry = feh.parse_response(payload, ["CVE-2021-0001"],
                               "2021-05-01")["CVE-2021-0001"]
    assert entry["epss"] == 0.01 and entry["percentile"] is None


def test_parse_response_rejects_shape_changes():
    with pytest.raises(ValueError):
        feh.parse_response({"status": "OK"}, ["CVE-2021-1"], "2022-01-01")
    with pytest.raises(ValueError):
        feh.parse_response({"data": ["not-a-dict"]}, ["CVE-2021-1"],
                           "2022-01-01")


# ------------------------------------------------------------------ state I/O

def test_state_round_trips_through_disk(tmp_path):
    state = {"version": 1, "last_sync": "2026-07-10T00:00:00Z",
             "entries": {"CVE-2023-0001|2023-02-14": {
                 "score_date": "2023-02-13", "epss": 0.00234,
                 "percentile": 0.45123, "model": "v2", "reason": None}}}
    feh.save_state(tmp_path, state)
    assert feh.load_state(tmp_path) == state


def test_load_state_absent_or_corrupt_is_none(tmp_path):
    assert feh.load_state(tmp_path) is None
    (tmp_path / feh.STATE_FILENAME).write_text("{broken", encoding="utf-8")
    assert feh.load_state(tmp_path, log=lambda _msg: None) is None


def test_reconstruct_state_from_published_output(tmp_path):
    published = {
        "generated_at": "2026-07-10T02:43:00Z",
        "entries": [
            {"cve": "CVE-2023-0003", "date_added": "2021-12-01",
             "score_date": "2021-11-30", "epss": 0.35064,
             "percentile": 0.98923, "model": "v1", "reason": None},
            {"cve": "CVE-2024-0002", "date_added": "2024-03-30",
             "score_date": "2024-03-29", "epss": None, "percentile": None,
             "model": None, "reason": "no_score_for_date"},
        ],
    }
    (tmp_path / "epss_report.json").write_text(json.dumps(published),
                                               encoding="utf-8")
    state = feh.reconstruct_state(tmp_path, log=lambda _msg: None)
    assert state["last_sync"] == "2026-07-10T02:43:00Z"
    assert state["entries"]["CVE-2023-0003|2021-12-01"]["epss"] == 0.35064
    assert state["entries"]["CVE-2024-0002|2024-03-30"]["reason"] == \
        "no_score_for_date"


def test_reconstruct_state_absent_or_broken_is_none(tmp_path):
    assert feh.reconstruct_state(tmp_path) is None
    (tmp_path / "epss_report.json").write_text('{"entries": [{}]}',
                                               encoding="utf-8")
    assert feh.reconstruct_state(tmp_path, log=lambda _msg: None) is None


# ----------------------------------------------------------------------- sync

def _fake_fetch(scored: dict[str, dict[str, str]]):
    """A fetch function backed by {score_date: {cve: epss_str}}; counts
    calls so tests can assert request economy."""
    calls = []

    def fetch(cves, score_date):
        calls.append((tuple(cves), score_date))
        rows = [{"cve": c, "epss": scored[score_date][c],
                 "percentile": "0.5"}
                for c in cves if c in scored.get(score_date, {})]
        return _envelope(rows)

    fetch.calls = calls
    return fetch


def test_sync_looks_up_only_missing_pairs():
    fetch = _fake_fetch({"2023-02-13": {"CVE-2023-0001": "0.01"}})
    prior = {"version": 1, "last_sync": "",
             "entries": {"CVE-2023-0003|2021-12-01": {
                 "score_date": "2021-11-30", "epss": 0.35064,
                 "percentile": 0.98923, "model": "v1", "reason": None}}}
    state = feh.sync_state(
        prior,
        [("CVE-2023-0003", "2021-12-01"), ("CVE-2023-0001", "2023-02-14")],
        fetch, backfill_batch=30, last_sync="now", log=lambda _msg: None)
    assert len(state["entries"]) == 2
    assert fetch.calls == [(("CVE-2023-0001",), "2023-02-13")]


def test_sync_prunes_entries_gone_from_kev():
    prior = {"version": 1, "last_sync": "",
             "entries": {"CVE-1999-0001|2022-01-01": {
                 "score_date": "2021-12-31", "epss": 0.5,
                 "percentile": 0.5, "model": "v1", "reason": None}}}
    state = feh.sync_state(prior, [], _fake_fetch({}), backfill_batch=30,
                           log=lambda _msg: None)
    assert state["entries"] == {}


def test_sync_batch_cap_fills_oldest_dates_first():
    fetch = _fake_fetch({"2021-11-02": {"CVE-2021-0001": "0.1"},
                         "2024-01-01": {"CVE-2023-0009": "0.2"}})
    pairs = [("CVE-2023-0009", "2024-01-02"),
             ("CVE-2021-0001", "2021-11-03")]
    state = feh.sync_state(None, pairs, fetch, backfill_batch=1,
                           log=lambda _msg: None)
    # only the OLDEST score date was looked up; the other stays pending
    assert list(state["entries"]) == ["CVE-2021-0001|2021-11-03"]
    assert fetch.calls == [(("CVE-2021-0001",), "2021-11-02")]
    # zero batch: nothing is ever looked up
    state = feh.sync_state(None, pairs, fetch, backfill_batch=0,
                           log=lambda _msg: None)
    assert state["entries"] == {}


def test_sync_chunks_large_dates_at_request_cap():
    n = feh.MAX_CVES_PER_REQUEST + 7
    cves = [f"CVE-2021-{10000 + i}" for i in range(n)]
    fetch = _fake_fetch({"2021-11-02": {c: "0.001" for c in cves}})
    state = feh.sync_state(None, [(c, "2021-11-03") for c in cves], fetch,
                           backfill_batch=1000, log=lambda _msg: None)
    assert len(state["entries"]) == n
    assert [len(c) for c, _d in fetch.calls] == \
        [feh.MAX_CVES_PER_REQUEST, 7]


def test_sync_saves_progress_and_reraises_on_fetch_failure():
    saves = []

    def fetch(cves, score_date):
        if score_date == "2024-01-01":
            raise RuntimeError("boom")
        return _envelope([{"cve": cves[0], "epss": "0.1",
                           "percentile": "0.9"}])

    pairs = [("CVE-2021-0001", "2021-11-03"),
             ("CVE-2023-0009", "2024-01-02")]
    with pytest.raises(RuntimeError):
        feh.sync_state(None, pairs, fetch, backfill_batch=1000,
                       save=lambda s: saves.append(json.loads(json.dumps(s))),
                       log=lambda _msg: None)
    # the completed older date was persisted before the failure surfaced
    assert saves and \
        "CVE-2021-0001|2021-11-03" in saves[-1]["entries"]


def test_sync_skips_undated_kev_entries():
    state = feh.sync_state(None, [("CVE-2021-0001", "garbage")],
                           _fake_fetch({}), backfill_batch=30,
                           log=lambda _msg: None)
    assert state["entries"] == {}


def test_fetch_scores_refuses_oversized_chunks():
    with pytest.raises(ValueError):
        feh.fetch_scores(None,
                         [f"CVE-2021-{i}" for i in
                          range(feh.MAX_CVES_PER_REQUEST + 1)],
                         "2022-01-01")


class _Resp:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _Session:
    def __init__(self, responses):
        self._responses = list(responses)
        self.requests = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.requests.append(params)
        return self._responses.pop(0)


def test_fetch_scores_422_is_authoritative_empty():
    session = _Session([_Resp(422)])
    assert feh.fetch_scores(session, ["CVE-2021-1"], "2021-04-13",
                            log=lambda _msg: None) == {"data": []}


def test_fetch_scores_raises_after_non_retryable_status():
    session = _Session([_Resp(403)])
    with pytest.raises(RuntimeError):
        feh.fetch_scores(session, ["CVE-2021-1"], "2022-01-01",
                         log=lambda _msg: None)
