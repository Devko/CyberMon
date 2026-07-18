"""Unit tests for the CNA Roster History diff engine, size/flux/mix metrics,
the stage, and the contract (pipeline/cna_roster.py)."""
from __future__ import annotations

from pathlib import Path

import pytest

# contracts must load before roster_contracts: the coordinator registers
# module contracts from its own module bottom, so importing the contract
# file first would hit the registration mid-initialization.
from pipeline import contracts
from pipeline import cna_roster as cr
from pipeline.contracts import ContractViolation
from pipeline.fetch_cna_roster import RosterOrg, RosterSnapshot, load_roster_file

FIX = Path(__file__).parent / "fixtures"


def org(short, *, types=("Vendor",), tlr="mitre", root="n/a",
        country="USA", scope="scope.", name=None, roles=("CNA",),
        is_root=False) -> RosterOrg:
    return RosterOrg(short_name=short, org_name=name or short.title(),
                     cna_id="CNA-2020-0001", country=country, scope=scope,
                     types=tuple(types), roles=tuple(roles), tlr=tlr,
                     root=root, is_root=is_root)


def snap(*orgs) -> RosterSnapshot:
    return RosterSnapshot(org_count=len(orgs), orgs=list(orgs))


# ------------------------------------------------------------- fingerprints

def test_scope_hash_ignores_whitespace_reflow_only():
    assert cr.scope_hash("a  b\nc") == cr.scope_hash("a b c")
    assert cr.scope_hash("a b c") != cr.scope_hash("a b d")
    assert len(cr.scope_hash("anything")) == 12


def test_fingerprint_keeps_display_fields_and_scope_hash():
    fp = cr.fingerprint(org("acme", types=("Open Source", "Vendor"),
                            scope="Acme."))
    assert fp == {"org": "Acme", "country": "USA",
                  "type": "Open Source + Vendor", "scope": cr.scope_hash("Acme.")}


# ------------------------------------------------------------------- diffing

def test_diff_onboarded_departed_scope_changed():
    prev = cr.fingerprint_roster(snap(org("a"), org("b", scope="old"),
                                      org("gone")))
    today = snap(org("a"), org("b", scope="new"), org("c"))
    curr = cr.fingerprint_roster(today)
    events = cr.diff_orgs(prev, today, curr, "2026-07-18")
    assert [(e["short_name"], e["change_type"]) for e in events] == [
        ("c", "onboarded"), ("gone", "departed"), ("b", "scope_changed")]
    # departed row carries the state's profile; onboarded carries today's
    assert events[1]["org"] == "Gone"
    assert events[0]["org"] == "C"


def test_diff_identical_roster_is_empty_and_idempotent():
    s = snap(org("a"), org("b"))
    fp = cr.fingerprint_roster(s)
    assert cr.diff_orgs(fp, s, dict(fp), "2026-07-18") == []


# -------------------------------------------------------------- advance_state

def test_advance_state_appends_and_same_day_replaces():
    state = cr.new_state("2026-07-01")
    cr.advance_state(state, cr.fingerprint_roster(snap(org("a"))), "2026-07-01")
    assert state["size_history"] == [["2026-07-01", 1]]
    # a later date appends
    cr.advance_state(state, cr.fingerprint_roster(snap(org("a"), org("b"))),
                     "2026-07-02")
    assert state["size_history"] == [["2026-07-01", 1], ["2026-07-02", 2]]
    # a same-day re-run replaces, never duplicates
    cr.advance_state(state, cr.fingerprint_roster(snap(org("a"), org("b"),
                                                       org("c"))), "2026-07-02")
    assert state["size_history"] == [["2026-07-01", 1], ["2026-07-02", 3]]


# ------------------------------------------------------------------- event I/O

def test_events_roundtrip_with_comma(tmp_path):
    path = tmp_path / "cna_roster.csv"
    prev = cr.fingerprint_roster(snap(org("keep")))
    today = snap(org("keep"), org("h1", name="HackerOne, Inc."))
    events = cr.diff_orgs(prev, today, cr.fingerprint_roster(today),
                          "2026-07-18")
    cr.write_events(path, events)
    assert cr.read_events(path) == events


def test_read_events_missing_file_is_empty(tmp_path):
    assert cr.read_events(tmp_path / "cna_roster.csv") == []


def test_read_events_fails_loudly_on_bad_change_type(tmp_path):
    path = tmp_path / "cna_roster.csv"
    path.write_text("observed_date,short_name,change_type,org,country,type\n"
                    "2026-07-18,acme,exploded,Acme,USA,Vendor\n",
                    encoding="utf-8")
    with pytest.raises(ValueError):
        cr.read_events(path)


def test_load_state_fails_loudly_on_unrecognized_state(tmp_path):
    cr.state_path(tmp_path).parent.mkdir(parents=True)
    cr.state_path(tmp_path).write_text('{"version": 99}', encoding="utf-8")
    with pytest.raises(ValueError):
        cr.load_state(tmp_path)


# --------------------------------------------------------------------- metrics

def _built(state, events, snapshot, min_n=2):
    obj = cr.build_cna_roster(state, events, snapshot,
                              "2026-07-18T00:00:00Z", min_n=min_n)
    contracts.validate("cna_roster.json", obj)
    return obj


def test_build_roster_mix_breakdowns_and_headline():
    s = snap(org("a", types=("Vendor",), country="USA"),
             org("b", types=("Vendor", "Open Source"), country="USA"),
             org("c", types=("Researcher",), tlr="CISA", root="icscert",
                 country="Germany"))
    state = cr.new_state("2026-07-18")
    cr.advance_state(state, cr.fingerprint_roster(s), "2026-07-18")
    obj = _built(state, [], s)
    mix = obj["roster_mix"]
    assert mix["total"] == 3
    # by_type is flattened (Vendor appears in two orgs) and sorted desc
    assert mix["by_type"][0] == {"label": "Vendor", "n": 2}
    assert {d["label"] for d in mix["by_type"]} == {"Vendor", "Open Source",
                                                    "Researcher"}
    # partitions sum to the total
    assert sum(d["n"] for d in mix["by_tlr"]) == 3
    assert sum(d["n"] for d in mix["by_country"]) == 3
    h = obj["headline"]
    assert h["roster_total"] == 3
    assert h["top_type"] == "Vendor" and h["top_type_n"] == 2
    assert h["country_count"] == 2
    assert h["mitre_n"] == 2 and h["cisa_n"] == 1
    assert h["root_count"] == 1  # only icscert is a non-"n/a" reporting root


def test_build_roster_size_net_change_gated_by_min_n():
    s = snap(org("a"))
    state = cr.new_state("2026-07-18")
    cr.advance_state(state, cr.fingerprint_roster(s), "2026-07-18")
    # one point < min_n -> net_change null (the thin-start honesty rule)
    obj = _built(state, [], s, min_n=2)
    assert obj["roster_size"]["series"] == [{"date": "2026-07-18", "size": 1}]
    assert obj["roster_size"]["net_change"] is None
    assert obj["roster_size"]["current"] == 1

    # a second observation opens the gate
    cr.advance_state(state, cr.fingerprint_roster(snap(org("a"), org("b"))),
                     "2026-07-19")
    obj2 = _built(state, [], snap(org("a"), org("b")), min_n=2)
    assert obj2["roster_size"]["net_change"] == 1


def test_build_roster_flux_months_gap_filled_and_totals():
    events = [
        {"observed_date": "2026-05-10", "short_name": "a",
         "change_type": "onboarded", "org": "A", "country": "USA", "type": "Vendor"},
        {"observed_date": "2026-07-02", "short_name": "b",
         "change_type": "departed", "org": "B", "country": "USA", "type": "Vendor"},
        {"observed_date": "2026-07-02", "short_name": "c",
         "change_type": "scope_changed", "org": "C", "country": "USA", "type": "Vendor"},
    ]
    s = snap(org("x"))
    state = cr.new_state("2026-07-18")
    cr.advance_state(state, cr.fingerprint_roster(s), "2026-07-18")
    obj = _built(state, events, s)
    flux = obj["roster_flux"]
    assert [m["month"] for m in flux["months"]] == ["2026-05", "2026-06",
                                                    "2026-07"]
    assert flux["months"][1] == {"month": "2026-06", "onboarded": 0,
                                 "departed": 0, "scope_changed": 0}
    assert flux["totals"] == {"onboarded": 1, "departed": 1, "scope_changed": 1}
    assert flux["events_total"] == 3
    assert flux["first_observed"] == "2026-05-10"


def test_empty_flux_validates_with_null_first_observed():
    s = snap(org("a"))
    state = cr.new_state("2026-07-18")
    cr.advance_state(state, cr.fingerprint_roster(s), "2026-07-18")
    obj = _built(state, [], s)
    assert obj["roster_flux"]["events_total"] == 0
    assert obj["roster_flux"]["first_observed"] is None
    assert obj["roster_flux"]["months"] == []


def test_contract_rejects_flux_total_drift():
    s = snap(org("a"))
    state = cr.new_state("2026-07-18")
    cr.advance_state(state, cr.fingerprint_roster(s), "2026-07-18")
    obj = cr.build_cna_roster(state, [], s, "2026-07-18T00:00:00Z", min_n=2)
    obj["roster_flux"]["events_total"] += 1
    with pytest.raises(ContractViolation):
        contracts.validate("cna_roster.json", obj)


def test_contract_rejects_partition_sum_mismatch():
    s = snap(org("a", country="USA"), org("b", country="Germany"))
    state = cr.new_state("2026-07-18")
    cr.advance_state(state, cr.fingerprint_roster(s), "2026-07-18")
    obj = cr.build_cna_roster(state, [], s, "2026-07-18T00:00:00Z", min_n=2)
    obj["roster_mix"]["by_country"][0]["n"] += 5  # breaks the partition sum
    with pytest.raises(ContractViolation):
        contracts.validate("cna_roster.json", obj)


# -------------------------------------------------------------------- the stage

def _fixture_snapshot():
    return load_roster_file(FIX / "cna_roster.json")


def test_run_stage_baseline_logs_nothing(tmp_path):
    s = _fixture_snapshot()
    obj, source, pending = cr.run_stage(
        tmp_path, "2026-07-18T00:00:00Z", snapshot=s, offline_fixtures=False)
    contracts.validate("cna_roster.json", obj)
    assert obj["roster_flux"]["events_total"] == 0     # baseline: no prior snap
    assert obj["roster_size"]["series"] == [{"date": "2026-07-18",
                                             "size": 8}]
    assert obj["roster_mix"]["total"] == 8
    assert source == {"fetched_at": "2026-07-18T00:00:00Z",
                      "org_count": 8, "events_total": 0}
    cr.persist(tmp_path, pending, log=lambda *_: None)
    assert cr.read_events(cr.csv_path(tmp_path)) == []


def test_run_stage_live_diff_logs_and_persists(tmp_path):
    s = _fixture_snapshot()
    _o, _s, pending = cr.run_stage(tmp_path, "2026-07-17T00:00:00Z",
                                   snapshot=s, offline_fixtures=False)
    cr.persist(tmp_path, pending, log=lambda *_: None)

    # next night: drop one org, add one, change one scope
    kept = [o for o in s.orgs if o.short_name != "curl"]
    changed = []
    for o in kept:
        if o.short_name == "adobe":
            changed.append(RosterOrg(**{**o.__dict__, "scope": "New scope."}))
        else:
            changed.append(o)
    changed.append(org("newcomer", types=("Researcher",)))
    obj, source, pending = cr.run_stage(
        tmp_path, "2026-07-18T00:00:00Z",
        snapshot=snap(*changed), offline_fixtures=False)
    contracts.validate("cna_roster.json", obj)
    assert obj["roster_flux"]["totals"] == {"onboarded": 1, "departed": 1,
                                            "scope_changed": 1}
    assert obj["roster_size"]["net_change"] == 0  # 8 -> 8 (one in, one out)
    cr.persist(tmp_path, pending, log=lambda *_: None)
    events = cr.read_events(cr.csv_path(tmp_path))
    assert [(e["short_name"], e["change_type"]) for e in events] == [
        ("newcomer", "onboarded"), ("curl", "departed"),
        ("adobe", "scope_changed")]


def test_run_stage_offline_seeds_fixture_state(tmp_path):
    s = _fixture_snapshot()
    obj, source, pending = cr.run_stage(
        tmp_path, "2026-07-18T00:00:00Z", snapshot=s, offline_fixtures=True)
    contracts.validate("cna_roster.json", obj)
    # the fixture prior state produces the full event mix in one run
    assert obj["roster_flux"]["totals"] == {"onboarded": 2, "departed": 1,
                                            "scope_changed": 1}
    assert obj["roster_size"]["series"][0]["date"] == "2026-07-01"
    assert obj["roster_size"]["net_change"] == 1   # 7 -> 8
    cr.persist(tmp_path, pending, log=lambda *_: None)

    # second offline run: committed state wins over the fixture seed
    obj2, _s2, _p2 = cr.run_stage(
        tmp_path, "2026-07-18T00:00:00Z", snapshot=s, offline_fixtures=True)
    assert obj2["roster_flux"]["events_total"] == 4  # nothing new


def test_run_stage_refuses_roster_collapse(tmp_path):
    big = snap(*[org(f"o{i}") for i in range(60)])
    _o, _s, pending = cr.run_stage(tmp_path, "2026-07-17T00:00:00Z",
                                   snapshot=big, offline_fixtures=False)
    cr.persist(tmp_path, pending, log=lambda *_: None)
    with pytest.raises(RuntimeError):
        cr.run_stage(tmp_path, "2026-07-18T00:00:00Z",
                     snapshot=snap(org("o0")), offline_fixtures=False)
