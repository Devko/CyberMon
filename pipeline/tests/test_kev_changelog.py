"""Unit tests for the KEV Changelog diff engine, Wayback backfill logic,
metrics assembly and contracts (pipeline/kev_changelog.py)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import kev_changelog as kc
from pipeline.contracts import ContractViolation
from pipeline.fetch_kev import KevEntry
from pipeline.kev_changelog_contracts import validate


def entry(cve: str, **kw) -> KevEntry:
    defaults = dict(date_added="2023-02-14", due_date="2023-03-07",
                    ransomware_use="Unknown", vendor_project="VendorX",
                    product="Widget", vulnerability_name="Widget RCE",
                    short_description="A fixture description.",
                    required_action="Apply updates.",
                    notes="https://example.com")
    defaults.update(kw)
    return KevEntry(cve_id=cve, **defaults)


def catalog(*entries: KevEntry) -> dict:
    return kc.fingerprint_catalog(entries)


# ---------------------------------------------------------------- fingerprints

def test_fingerprint_normalizes_missing_flag_to_unknown():
    fp = kc.fingerprint(entry("CVE-2023-0001", ransomware_use=None))
    assert fp["ransom"] == "Unknown"
    fp = kc.fingerprint(entry("CVE-2023-0001", ransomware_use=" known "))
    assert fp["ransom"] == "Known"


def test_fingerprint_strips_stray_whitespace():
    a = kc.fingerprint(entry("CVE-2023-0001", vendor_project=" VendorX "))
    b = kc.fingerprint(entry("CVE-2023-0001", vendor_project="VendorX"))
    assert a == b


def test_text_hash_ignores_whitespace_reflow_only():
    assert kc.text_hash("a  b\nc") == kc.text_hash("a b c")
    assert kc.text_hash("a b c") != kc.text_hash("a b d")
    assert len(kc.text_hash("anything")) == 12


# ----------------------------------------------------------------- diff engine

def test_diff_value_field_change_logs_old_and_new():
    prev = catalog(entry("CVE-2023-0001", due_date="2023-02-28"))
    curr = catalog(entry("CVE-2023-0001", due_date="2023-03-07"))
    events = kc.diff_catalogs(prev, curr, "2026-07-11", "daily")
    assert events == [{"observed_date": "2026-07-11",
                       "cve": "CVE-2023-0001",
                       "change_type": "field_changed", "field": "dueDate",
                       "old": "2023-02-28", "new": "2023-03-07",
                       "granularity": "daily"}]


def test_diff_ransomware_flag_flip():
    prev = catalog(entry("CVE-2023-0001", ransomware_use="Unknown"))
    curr = catalog(entry("CVE-2023-0001", ransomware_use="Known"))
    (event,) = kc.diff_catalogs(prev, curr, "2026-07-11", "daily")
    assert event["field"] == "knownRansomwareCampaignUse"
    assert (event["old"], event["new"]) == ("Unknown", "Known")


def test_diff_hash_field_change_never_logs_the_text():
    prev = catalog(entry("CVE-2023-0001", short_description="old text"))
    curr = catalog(entry("CVE-2023-0001", short_description="new text"))
    (event,) = kc.diff_catalogs(prev, curr, "2026-07-11", "daily")
    assert event["change_type"] == "text_changed"
    assert event["field"] == "shortDescription"
    assert event["old"] == "" and event["new"] == ""


def test_diff_added_and_removed():
    prev = catalog(entry("CVE-2023-0001"))
    curr = catalog(entry("CVE-2024-0002"))
    events = kc.diff_catalogs(prev, curr, "2026-07-11", "capture")
    assert [(e["cve"], e["change_type"]) for e in events] == \
        [("CVE-2024-0002", "added"), ("CVE-2023-0001", "removed")]
    assert all(e["granularity"] == "capture" for e in events)


def test_diff_identical_catalogs_is_empty_and_idempotent():
    snap = catalog(entry("CVE-2023-0001"), entry("CVE-2024-0002"))
    assert kc.diff_catalogs(snap, dict(snap), "2026-07-11", "daily") == []


def test_diff_rejects_unknown_granularity():
    with pytest.raises(ValueError):
        kc.diff_catalogs({}, {}, "2026-07-11", "weekly")


def test_apply_snapshot_moves_removals_to_ledger_and_back():
    state = kc.new_state("2026-07-01")
    kc.apply_snapshot(state, catalog(entry("CVE-2023-0001")), "2026-07-01")
    kc.apply_snapshot(state, catalog(entry("CVE-2024-0002")), "2026-07-02")
    assert set(state["entries"]) == {"CVE-2024-0002"}
    assert state["removed"]["CVE-2023-0001"]["removed_on"] == "2026-07-02"
    assert state["removed"]["CVE-2023-0001"]["vendor"] == "VendorX"
    # the removed entry returns: it leaves the ledger again
    kc.apply_snapshot(state, catalog(entry("CVE-2023-0001"),
                                     entry("CVE-2024-0002")), "2026-07-03")
    assert state["removed"] == {}
    assert state["last_observed"] == "2026-07-03"


# ------------------------------------------------------------------- event I/O

def test_events_roundtrip(tmp_path):
    path = tmp_path / "kev_changelog.csv"
    events = kc.diff_catalogs(
        catalog(entry("CVE-2023-0001", vulnerability_name="Name, with comma")),
        catalog(entry("CVE-2023-0001", vulnerability_name="New name")),
        "2026-07-11", "daily")
    kc.write_events(path, events)
    assert kc.read_events(path) == events


def test_read_events_missing_file_is_empty(tmp_path):
    assert kc.read_events(tmp_path / "kev_changelog.csv") == []


def test_read_events_fails_loudly_on_malformed_rows(tmp_path):
    path = tmp_path / "kev_changelog.csv"
    path.write_text("observed_date,cve,change_type,field,old,new,granularity\n"
                    "2026-07-11,CVE-2023-0001,exploded,,,,daily\n",
                    encoding="utf-8")
    with pytest.raises(ValueError):
        kc.read_events(path)


def test_load_state_fails_loudly_on_unrecognized_state(tmp_path):
    kc.state_path(tmp_path).parent.mkdir(parents=True)
    kc.state_path(tmp_path).write_text('{"version": 99}', encoding="utf-8")
    with pytest.raises(ValueError):
        kc.load_state(tmp_path)


# -------------------------------------------------------------------- backfill

def _capture_doc(*entries: KevEntry) -> dict:
    return {"catalogVersion": "x", "count": len(entries),
            "vulnerabilities": [
                {"cveID": e.cve_id, "dateAdded": e.date_added,
                 "dueDate": e.due_date or "",
                 "knownRansomwareCampaignUse": e.ransomware_use or "",
                 "vendorProject": e.vendor_project, "product": e.product,
                 "vulnerabilityName": e.vulnerability_name,
                 "shortDescription": e.short_description,
                 "requiredAction": e.required_action, "notes": e.notes}
                for e in entries]}


def test_backfill_first_capture_is_baseline_then_diffs():
    docs = {
        "20211223000000": _capture_doc(entry("CVE-2021-0001")),
        "20220301000000": _capture_doc(entry("CVE-2021-0001"),
                                       entry("CVE-2022-0002")),
    }
    captures = [(ts, "u") for ts in sorted(docs)]
    events: list[dict] = []
    state, complete = kc.run_backfill(
        None, events, captures=captures,
        fetch=lambda ts, u: docs[ts], batch=10, log=lambda *_: None)
    assert complete
    assert state["baseline_date"] == "2021-12-23"
    assert state["backfill"] == {"captures": 2,
                                 "watermark": "20220301000000",
                                 "complete": True}
    # baseline logs nothing; the second capture logs one addition
    assert [(e["cve"], e["change_type"], e["observed_date"],
             e["granularity"]) for e in events] == \
        [("CVE-2022-0002", "added", "2022-03-01", "capture")]


def test_backfill_batch_cap_and_watermark_resume():
    docs = {f"2022010{i}000000":
            _capture_doc(entry(f"CVE-2022-000{i}")) for i in range(1, 4)}
    captures = [(ts, "u") for ts in sorted(docs)]
    events: list[dict] = []
    state, complete = kc.run_backfill(
        None, events, captures=captures,
        fetch=lambda ts, u: docs[ts], batch=2, log=lambda *_: None)
    assert not complete
    assert state["backfill"]["captures"] == 2
    # resume: only the capture past the watermark is processed
    state, complete = kc.run_backfill(
        state, events, captures=captures,
        fetch=lambda ts, u: docs[ts], batch=10, log=lambda *_: None)
    assert complete
    assert state["backfill"]["captures"] == 3
    assert state["backfill"]["complete"] is True


def test_backfill_skips_failed_and_empty_captures():
    good = _capture_doc(entry("CVE-2021-0001"))
    docs = {"20220101000000": None,               # fetch failed
            "20220201000000": {"vulnerabilities": []},  # parsed empty
            "20220301000000": good}
    captures = [(ts, "u") for ts in sorted(docs)]
    events: list[dict] = []
    state, complete = kc.run_backfill(
        None, events, captures=captures,
        fetch=lambda ts, u: docs[ts], batch=10, log=lambda *_: None)
    assert complete
    assert state["baseline_date"] == "2022-03-01"  # first USABLE capture
    assert events == []


def test_backfill_skips_shrunken_capture():
    big = [entry(f"CVE-2021-{i:04d}") for i in range(1, 61)]
    docs = {"20220101000000": _capture_doc(*big),
            "20220201000000": _capture_doc(*big[:5]),   # broken snapshot
            "20220301000000": _capture_doc(*big[:59])}  # plausible
    captures = [(ts, "u") for ts in sorted(docs)]
    events: list[dict] = []
    state, complete = kc.run_backfill(
        None, events, captures=captures,
        fetch=lambda ts, u: docs[ts], batch=10, log=lambda *_: None)
    assert complete
    # the shrunken capture logged nothing; the third logged one removal
    assert [(e["change_type"], e["observed_date"]) for e in events] == \
        [("removed", "2022-03-01")]


def test_backfill_refuses_live_baselined_state():
    state = kc.new_state("2026-07-01")
    kc.apply_snapshot(state, catalog(entry("CVE-2023-0001")), "2026-07-01")
    events: list[dict] = []
    out, complete = kc.run_backfill(
        state, events, captures=[("20220101000000", "u")],
        fetch=lambda ts, u: pytest.fail("must not fetch"),
        batch=10, log=lambda *_: None)
    assert complete and out is state and events == []


def test_backfill_all_captures_unusable_returns_none():
    events: list[dict] = []
    state, complete = kc.run_backfill(
        None, events, captures=[("20220101000000", "u")],
        fetch=lambda ts, u: None, batch=10, log=lambda *_: None)
    assert complete and state is None and events == []


def test_cdx_captures_merges_and_thins_to_weekly():
    class FakeResp:
        status_code = 200

        def __init__(self, rows):
            self._rows = rows

        def raise_for_status(self):
            pass

        def json(self):
            return self._rows

    calls = []

    class FakeSession:
        def get(self, url, params=None, headers=None, timeout=None):
            calls.append(params["url"])
            if "feeds" in params["url"]:
                return FakeResp([
                    ["urlkey", "timestamp", "original", "mime", "status",
                     "digest", "length"],
                    # two captures in the same ISO week: first one wins
                    ["k", "20220104000000", "https://a", "m", "200", "d", "1"],
                    ["k", "20220106000000", "https://a", "m", "200", "d", "1"],
                    ["k", "20220112000000", "https://a", "m", "200", "d", "1"],
                ])
            return FakeResp([])

    captures = kc.cdx_captures(FakeSession(), log=lambda *_: None)
    assert captures == [("20220104000000", "https://a"),
                        ("20220112000000", "https://a")]
    assert len(calls) == len(kc.KEV_URL_VARIANTS)


def test_fetch_capture_caches_and_never_refetches(tmp_path):
    body = json.dumps(_capture_doc(entry("CVE-2021-0001")))
    fetched = []

    class FakeResp:
        content = body.encode("utf-8")

        def raise_for_status(self):
            pass

    class FakeSession:
        def get(self, url, headers=None, timeout=None):
            fetched.append(url)
            return FakeResp()

    session = FakeSession()
    doc1 = kc.fetch_capture(session, tmp_path, "20220101000000",
                            "https://a", log=lambda *_: None)
    doc2 = kc.fetch_capture(session, tmp_path, "20220101000000",
                            "https://a", log=lambda *_: None)
    assert doc1 == doc2 == json.loads(body)
    assert len(fetched) == 1  # second call served from .cache/kev_wayback
    assert (tmp_path / "kev_wayback" / "20220101000000.json").exists()


# --------------------------------------------------------------------- metrics

def _state_with_events() -> tuple[dict, list[dict]]:
    state = kc.new_state("2026-01-05")
    kc.apply_snapshot(state, catalog(
        entry("CVE-2023-0001", date_added="2023-02-14"),
        entry("CVE-2024-0002", date_added="2024-03-30")), "2026-01-05")
    kc.apply_snapshot(state, catalog(
        entry("CVE-2023-0001", date_added="2023-02-14")), "2026-04-02")
    events = [
        {"observed_date": "2026-01-06", "cve": "CVE-2023-0001",
         "change_type": "field_changed", "field": "dueDate",
         "old": "a", "new": "b", "granularity": "daily"},
        {"observed_date": "2026-01-06", "cve": "CVE-2023-0001",
         "change_type": "text_changed", "field": "notes",
         "old": "", "new": "", "granularity": "daily"},
        {"observed_date": "2026-03-15", "cve": "CVE-2023-0001",
         "change_type": "field_changed",
         "field": "knownRansomwareCampaignUse",
         "old": "Unknown", "new": "Known", "granularity": "daily"},
        {"observed_date": "2026-04-02", "cve": "CVE-2024-0002",
         "change_type": "removed", "field": "", "old": "", "new": "",
         "granularity": "daily"},
        {"observed_date": "2026-04-02", "cve": "CVE-2026-0009",
         "change_type": "added", "field": "", "old": "", "new": "",
         "granularity": "daily"},
    ]
    return state, events


def test_build_kev_changelog_shapes_and_contract():
    state, events = _state_with_events()
    obj = kc.build_kev_changelog(state, events, "2026-07-11T00:00:00Z",
                                 min_n=1)
    validate("kev_changelog.json", obj)

    # months gap-fill contiguously between first and last event month
    assert [m["month"] for m in obj["months"]] == \
        ["2026-01", "2026-02", "2026-03", "2026-04"]
    assert obj["months"][0]["due_date"] == 1
    assert obj["months"][0]["text"] == 1
    assert obj["months"][1]["total"] == 0
    assert obj["months"][2]["ransomware_flag"] == 1
    assert obj["months"][3]["removed"] == 1

    assert obj["catalog"]["events_total"] == 5
    assert obj["catalog"]["edits_total"] == 4
    assert obj["catalog"]["additions_excluded"] == 1
    assert obj["catalog"]["first_observed"] == "2026-01-05"

    # the flip lag: 2026-03-15 minus dateAdded 2023-02-14 = 1125 days
    assert obj["flips"]["total"] == 1
    assert obj["flips"]["lag"] == {"n": 1, "median_days": 1125.0,
                                   "p25_days": 1125.0, "p75_days": 1125.0}
    assert obj["flips"]["by_month"][-1]["cumulative"] == 1

    # board: edits counted per cve (removals separate), removal listed
    assert obj["board"]["most_edited"][0]["cve"] == "CVE-2023-0001"
    assert obj["board"]["most_edited"][0]["edits"] == 3
    assert obj["board"]["removals"] == [{
        "cve": "CVE-2024-0002", "vendor": "VendorX", "product": "Widget",
        "listed": "2024-03-30", "removed": "2026-04-02"}]


def test_build_lag_stats_null_below_min_n():
    state, events = _state_with_events()
    obj = kc.build_kev_changelog(state, events, "2026-07-11T00:00:00Z",
                                 min_n=10)
    validate("kev_changelog.json", obj)
    assert obj["flips"]["lag"] == {"n": 1, "median_days": None,
                                   "p25_days": None, "p75_days": None}


def test_build_empty_record_validates():
    state = kc.new_state("2026-07-11")
    kc.apply_snapshot(state, catalog(entry("CVE-2023-0001")), "2026-07-11")
    obj = kc.build_kev_changelog(state, [], "2026-07-11T00:00:00Z", min_n=1)
    validate("kev_changelog.json", obj)
    assert obj["months"] == [] and obj["headline"] is None


def test_contract_rejects_gap_in_months():
    state, events = _state_with_events()
    obj = kc.build_kev_changelog(state, events, "2026-07-11T00:00:00Z",
                                 min_n=1)
    obj["months"] = [m for m in obj["months"] if m["month"] != "2026-02"]
    with pytest.raises(ContractViolation):
        validate("kev_changelog.json", obj)


def test_contract_rejects_category_sum_mismatch():
    state, events = _state_with_events()
    obj = kc.build_kev_changelog(state, events, "2026-07-11T00:00:00Z",
                                 min_n=1)
    obj["months"][0]["total"] += 1
    with pytest.raises(ContractViolation):
        validate("kev_changelog.json", obj)


def test_contract_rejects_addition_arithmetic_drift():
    state, events = _state_with_events()
    obj = kc.build_kev_changelog(state, events, "2026-07-11T00:00:00Z",
                                 min_n=1)
    obj["catalog"]["additions_excluded"] += 1
    with pytest.raises(ContractViolation):
        validate("kev_changelog.json", obj)


# -------------------------------------------------------------------- the stage

def _fixture_kev_entries() -> list[KevEntry]:
    from pipeline.fetch_kev import load_kev_file

    return load_kev_file(Path(__file__).parent / "fixtures"
                         / "kev.json").entries


def test_run_stage_baseline_then_idempotent(tmp_path):
    entries = _fixture_kev_entries()
    obj, source, pending = kc.run_stage(
        tmp_path, tmp_path / "cache", "2026-07-11T00:00:00Z",
        kev_entries=entries, offline_fixtures=False)
    validate("kev_changelog.json", obj)
    assert obj["catalog"]["events_total"] == 0  # baseline logs nothing
    assert obj["catalog"]["first_observed"] == "2026-07-11"
    assert source == {"fetched_at": "2026-07-11T00:00:00Z",
                      "events_total": 0, "last_observed": "2026-07-11"}
    kc.persist(tmp_path, pending, log=lambda *_: None)

    # same-day re-run against the identical catalog: zero new events
    obj2, _source2, pending2 = kc.run_stage(
        tmp_path, tmp_path / "cache", "2026-07-11T00:00:00Z",
        kev_entries=entries, offline_fixtures=False)
    assert obj2["catalog"]["events_total"] == 0
    kc.persist(tmp_path, pending2, log=lambda *_: None)
    assert kc.read_events(kc.csv_path(tmp_path)) == []


def test_run_stage_live_diff_logs_and_persists(tmp_path):
    entries = _fixture_kev_entries()
    _obj, _source, pending = kc.run_stage(
        tmp_path, tmp_path / "cache", "2026-07-10T00:00:00Z",
        kev_entries=entries, offline_fixtures=False)
    kc.persist(tmp_path, pending, log=lambda *_: None)

    # next night: one entry got a new due date, one vanished
    changed = []
    for e in entries:
        if e.cve_id == "CVE-2023-0001":
            changed.append(KevEntry(**{**e.__dict__, "due_date":
                                       "2023-04-01"}))
        elif e.cve_id == "CVE-2022-9004":
            continue
        else:
            changed.append(e)
    obj, source, pending = kc.run_stage(
        tmp_path, tmp_path / "cache", "2026-07-11T00:00:00Z",
        kev_entries=changed, offline_fixtures=False)
    validate("kev_changelog.json", obj)
    assert obj["catalog"]["events_total"] == 2
    assert obj["catalog"]["edits_total"] == 2
    assert obj["board"]["removals"][0]["cve"] == "CVE-2022-9004"
    kc.persist(tmp_path, pending, log=lambda *_: None)
    events = kc.read_events(kc.csv_path(tmp_path))
    assert [(e["cve"], e["change_type"]) for e in events] == \
        [("CVE-2022-9004", "removed"), ("CVE-2023-0001", "field_changed")]
    assert all(e["granularity"] == "daily" for e in events)


def test_run_stage_refuses_catalog_collapse(tmp_path):
    entries = [entry(f"CVE-2023-{i:04d}") for i in range(1, 101)]
    _obj, _source, pending = kc.run_stage(
        tmp_path, tmp_path / "cache", "2026-07-10T00:00:00Z",
        kev_entries=entries, offline_fixtures=False)
    kc.persist(tmp_path, pending, log=lambda *_: None)
    with pytest.raises(RuntimeError):
        kc.run_stage(tmp_path, tmp_path / "cache", "2026-07-11T00:00:00Z",
                     kev_entries=entries[:10], offline_fixtures=False)


def test_run_stage_offline_seeds_fixture_state(tmp_path):
    entries = _fixture_kev_entries()
    obj, _source, pending = kc.run_stage(
        tmp_path, tmp_path / "cache", "2026-07-11T00:00:00Z",
        kev_entries=entries, offline_fixtures=True)
    validate("kev_changelog.json", obj)
    # the fixture prior state produces the full event mix in one run
    assert obj["catalog"]["events_total"] == 7
    assert obj["catalog"]["edits_total"] == 5
    assert obj["catalog"]["additions_excluded"] == 2
    assert obj["flips"]["total"] == 1
    assert obj["board"]["removals"][0]["cve"] == "CVE-2020-5555"
    kc.persist(tmp_path, pending, log=lambda *_: None)

    # second offline run: committed state wins over the fixture seed
    obj2, _s, _p = kc.run_stage(
        tmp_path, tmp_path / "cache", "2026-07-11T00:00:00Z",
        kev_entries=entries, offline_fixtures=True)
    assert obj2["catalog"]["events_total"] == 7  # nothing new
