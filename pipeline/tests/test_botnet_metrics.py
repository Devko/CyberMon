"""Unit tests for the Botnet Weather count engine, sections, stage, and
CSV discipline (pipeline/botnet_metrics.py)."""
from __future__ import annotations

from pathlib import Path

import pytest

# contracts must load before botnet_contracts: the coordinator registers
# module contracts from its own module bottom, so importing the contract
# file first would hit the registration mid-initialization.
from pipeline import contracts
from pipeline import botnet_metrics as bm
from pipeline.fetch_feodo import C2Entry, C2Snapshot, load_blocklist_file

FIX = Path(__file__).parent / "fixtures"


def c2(ip="203.0.113.7", *, port=443, status="online", family="QakBot",
       first_seen="2026-01-13", country="US", as_name="EXAMPLE-AS",
       as_number=64496) -> C2Entry:
    return C2Entry(ip=ip, port=port, status=status, family=family,
                   first_seen=first_seen, country=country, as_name=as_name,
                   as_number=as_number)


def snap(*entries) -> C2Snapshot:
    return C2Snapshot(entry_count=len(entries), entries=list(entries))


# ------------------------------------------------------------- CSV rows

def test_rows_for_snapshot_families_sorted_total_last():
    rows = bm.rows_for_snapshot(
        snap(c2(), c2("203.0.113.8", status="offline"),
             c2("203.0.113.9", family="Emotet", status="offline")),
        "2026-07-21")
    assert rows == [
        {"date": "2026-07-21", "family": "Emotet", "online": 0, "listed": 1},
        {"date": "2026-07-21", "family": "QakBot", "online": 1, "listed": 2},
        {"date": "2026-07-21", "family": "_total", "online": 1, "listed": 3},
    ]


def test_rows_for_empty_snapshot_is_the_zero_total_row():
    # The zero IS the weather: an empty blocklist still records its day.
    assert bm.rows_for_snapshot(snap(), "2026-07-21") == [
        {"date": "2026-07-21", "family": "_total", "online": 0, "listed": 0}]


def test_merge_day_replaces_same_date_and_sorts():
    day1 = bm.rows_for_snapshot(snap(c2()), "2026-07-20")
    day2 = bm.rows_for_snapshot(snap(c2(), c2("203.0.113.8")), "2026-07-21")
    rows = bm.merge_day(day1, day2)
    # same-day re-run with different counts replaces, never duplicates
    rerun = bm.rows_for_snapshot(snap(c2(status="offline")), "2026-07-21")
    rows = bm.merge_day(rows, rerun)
    assert [(r["date"], r["family"]) for r in rows] == [
        ("2026-07-20", "QakBot"), ("2026-07-20", "_total"),
        ("2026-07-21", "QakBot"), ("2026-07-21", "_total")]
    assert rows[-2]["online"] == 0 and rows[-2]["listed"] == 1


def test_rows_roundtrip(tmp_path):
    path = tmp_path / "botnet_c2.csv"
    rows = bm.rows_for_snapshot(snap(c2(), c2("203.0.113.9",
                                              family="Emotet")), "2026-07-21")
    bm.write_rows(path, rows)
    assert bm.read_rows(path) == rows


def test_read_rows_missing_file_is_empty(tmp_path):
    assert bm.read_rows(tmp_path / "botnet_c2.csv") == []


@pytest.mark.parametrize("body", [
    "date,family,online,listed\n2026-07-21,QakBot,two,3\n",   # non-int
    "date,family,online,listed\n2026-07-21,QakBot,-1,3\n",    # negative
    "date,family,online,listed\n2026-07-21,QakBot,4,3\n",     # online > listed
    "date,family,online,listed\n2026-07-21,,1,3\n",           # empty family
    "date,family,online,listed\nlately,QakBot,1,3\n",         # bad date
    "date,family\n2026-07-21,QakBot\n",                       # missing columns
])
def test_read_rows_fails_loudly_on_malformed_history(tmp_path, body):
    path = tmp_path / "botnet_c2.csv"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ValueError):
        bm.read_rows(path)


# ------------------------------------------------------------- series/build

def _built(rows, snapshot, generated_at="2026-07-21T00:00:00Z"):
    obj = bm.build_botnet_weather(rows, snapshot, generated_at)
    contracts.validate("botnet_weather.json", obj)
    return obj


def _merged(snapshot, day, prior=()):
    return bm.merge_day(list(prior), bm.rows_for_snapshot(snapshot, day))


def test_build_weather_series_union_families_and_totals():
    s1 = snap(c2(), c2("203.0.113.8", family="TrickBot", status="offline"))
    s2 = snap(c2(status="offline"))
    rows = _merged(s2, "2026-07-21",
                   prior=_merged(s1, "2026-07-20"))
    obj = _built(rows, s2)
    w = obj["c2_weather"]
    assert w["families"] == ["QakBot", "TrickBot"]  # union over the record
    assert w["first_observed"] == "2026-07-20"
    assert [pt["date"] for pt in w["series"]] == ["2026-07-20", "2026-07-21"]
    assert w["series"][0]["online"] == {"QakBot": 1, "TrickBot": 0}
    assert w["series"][1]["listed"] == {"QakBot": 1}
    assert w["current_online"] == 0 and w["current_listed"] == 1
    assert obj["catalog"]["days_observed"] == 2
    # tonight's snapshot names only its own families
    assert obj["catalog"]["families"] == ["QakBot"]


def test_build_weather_missing_total_row_fails_loudly():
    rows = [{"date": "2026-07-21", "family": "QakBot",
             "online": 1, "listed": 1}]
    with pytest.raises(ValueError):
        bm.build_weather_series(rows)


def test_build_c2_today_composition_and_sorting():
    s = snap(
        c2("203.0.113.1", family="QakBot", country="US",
           as_name="CLOUD-A"),
        c2("203.0.113.2", family="QakBot", status="offline", country="GB",
           as_name="CLOUD-A"),
        c2("203.0.113.3", family="Emotet", status="offline", country="US",
           as_name="EXAMPLE-BACKBONE"),
        c2("203.0.113.4", family="Pikabot", status="offline", country="DE",
           as_name="RHEIN"),
    )
    today = bm.build_c2_today(s, "2026-07-21")
    assert today["listed_total"] == 4 and today["online_total"] == 1
    # listed desc, ties label asc
    assert [f["label"] for f in today["families"]] == \
        ["QakBot", "Emotet", "Pikabot"]
    assert today["families"][0] == {"label": "QakBot", "listed": 2,
                                    "online": 1}
    assert today["countries"] == [{"label": "US", "n": 2},
                                  {"label": "DE", "n": 1},
                                  {"label": "GB", "n": 1}]
    assert today["asns"][0] == {"label": "CLOUD-A", "n": 2}


def test_build_c2_age_buckets_median_and_clamp():
    s = snap(
        c2("203.0.113.1", first_seen="2026-07-20"),                 # 1 day
        c2("203.0.113.2", first_seen="2026-05-01", status="offline"),  # 81d
        c2("203.0.113.3", first_seen="2022-06-04", status="offline"),  # >2y
        c2("203.0.113.4", first_seen="2026-08-01", status="offline"),  # future
    )
    age = bm.build_c2_age(s, "2026-07-21")
    assert age["n"] == 4
    counts = {b["label"]: b["n"] for b in age["buckets"]}
    assert counts["under 30 days"] == 2   # the future stamp clamps to 0
    assert counts["30–90 days"] == 1
    assert counts["over 2 years"] == 1
    assert age["median_age_days"] == 41   # median of [0, 1, 81, 1508] -> 41
    assert age["oldest_age_days"] == (
        __import__("datetime").date(2026, 7, 21)
        - __import__("datetime").date(2022, 6, 4)).days


def test_empty_snapshot_builds_honest_empty_sections():
    rows = _merged(snap(), "2026-07-21")
    obj = _built(rows, snap())
    assert obj["c2_today"]["listed_total"] == 0
    assert obj["c2_today"]["families"] == []
    assert obj["c2_today"]["countries"] == []
    assert obj["c2_age"]["median_age_days"] is None
    assert obj["c2_age"]["oldest_age_days"] is None
    assert sum(b["n"] for b in obj["c2_age"]["buckets"]) == 0
    assert obj["c2_weather"]["current_listed"] == 0
    assert obj["catalog"]["snapshot_size"] == 0
    assert obj["catalog"]["families"] == []


# -------------------------------------------------------------------- the stage

def _fixture_snapshot():
    return load_blocklist_file(FIX / "feodo_c2.json")


def test_run_stage_first_night_is_a_one_day_record(tmp_path):
    s = _fixture_snapshot()
    obj, source, rows = bm.run_stage(
        tmp_path, "2026-07-21T00:00:00Z", snapshot=s,
        offline_fixtures=False, log=lambda *_: None)
    contracts.validate("botnet_weather.json", obj)
    assert obj["catalog"]["days_observed"] == 1  # honestly thin
    assert obj["c2_weather"]["first_observed"] == "2026-07-21"
    assert obj["c2_today"]["listed_total"] == 6
    assert source == {"fetched_at": "2026-07-21T00:00:00Z",
                      "listed": 6, "online": 2}
    bm.persist(tmp_path, rows, log=lambda *_: None)
    assert bm.read_rows(bm.csv_path(tmp_path)) == rows


def test_run_stage_appends_and_same_day_replaces(tmp_path):
    s = _fixture_snapshot()
    _o, _s, rows = bm.run_stage(tmp_path, "2026-07-20T00:00:00Z",
                                snapshot=s, offline_fixtures=False,
                                log=lambda *_: None)
    bm.persist(tmp_path, rows, log=lambda *_: None)

    # next night: the record deepens
    obj, _s2, rows = bm.run_stage(tmp_path, "2026-07-21T00:00:00Z",
                                  snapshot=snap(), offline_fixtures=False,
                                  log=lambda *_: None)
    assert obj["catalog"]["days_observed"] == 2
    assert obj["c2_weather"]["current_listed"] == 0  # the cliff is data
    bm.persist(tmp_path, rows, log=lambda *_: None)

    # same-day re-run: replaced, never duplicated
    obj2, _s3, rows = bm.run_stage(tmp_path, "2026-07-21T12:00:00Z",
                                   snapshot=s, offline_fixtures=False,
                                   log=lambda *_: None)
    assert obj2["catalog"]["days_observed"] == 2
    assert obj2["c2_weather"]["current_listed"] == 6


def test_run_stage_offline_seeds_fixture_history_once(tmp_path):
    s = _fixture_snapshot()
    obj, _src, rows = bm.run_stage(
        tmp_path, "2026-07-21T00:00:00Z", snapshot=s, offline_fixtures=True,
        log=lambda *_: None)
    contracts.validate("botnet_weather.json", obj)
    # 2 fixture days + tonight; TrickBot only lives in the fixture record
    assert obj["catalog"]["days_observed"] == 3
    assert obj["c2_weather"]["first_observed"] == "2026-07-01"
    assert "TrickBot" in obj["c2_weather"]["families"]
    assert "TrickBot" not in obj["catalog"]["families"]
    bm.persist(tmp_path, rows, log=lambda *_: None)

    # second offline run: the committed file wins over the fixture seed
    obj2, _s2, _r2 = bm.run_stage(
        tmp_path, "2026-07-21T00:00:00Z", snapshot=s, offline_fixtures=True,
        log=lambda *_: None)
    assert obj2["catalog"]["days_observed"] == 3


def test_run_stage_never_refuses_a_collapse(tmp_path):
    # The documented guard rule: unlike the roster's shrink guard, a count
    # collapse — even to zero — is recorded, because the collapse is the
    # takedown signal this module exists to capture. (Broken fetches are
    # guarded structurally in fetch_feodo instead.)
    big = snap(*[c2(f"203.0.113.{i}") for i in range(1, 61)])
    _o, _s, rows = bm.run_stage(tmp_path, "2026-07-20T00:00:00Z",
                                snapshot=big, offline_fixtures=False,
                                log=lambda *_: None)
    bm.persist(tmp_path, rows, log=lambda *_: None)
    obj, _s2, _r = bm.run_stage(tmp_path, "2026-07-21T00:00:00Z",
                                snapshot=snap(), offline_fixtures=False,
                                log=lambda *_: None)
    assert obj["c2_weather"]["series"][-2]["listed_total"] == 60
    assert obj["c2_weather"]["current_listed"] == 0  # the cliff, on record
