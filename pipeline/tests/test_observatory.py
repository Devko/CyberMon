"""Mutation Observatory: builder (pipeline/observatory.py) and contract."""
from __future__ import annotations

import pytest

from pipeline import observatory as ob
from pipeline.contracts import ContractViolation, validate

GEN = "2026-09-22T02:00:00Z"


def _kev(day, cve, ct, fld="", old="", new="", grain="daily"):
    return {"observed_date": day, "cve": cve, "change_type": ct,
            "field": fld, "old": old, "new": new, "granularity": grain}


def _rescore(day, cve, ct, vo=None, so=None, vn="v3.1", sn=7.5, cna="acme"):
    return {"observed_date": day, "cve": cve, "cna": cna, "change_type": ct,
            "version_old": vo, "score_old": so, "version_new": vn,
            "score_new": sn}


def _epss(day, cve, old, new, *, reset=False, moved=10, compared=1000):
    return {"observed_date": day, "model_version": "v1", "n_scored": compared,
            "n_compared": compared, "prob_moved": moved, "pct_moved": moved,
            "crossed_lo": 0, "crossed_mid": 0, "crossed_hi": 0,
            "top_cve": cve, "top_old": old, "top_new": new, "reset": reset}


def _build(**kw):
    args = {
        "kev_rows": [
            _kev("2022-01-18", "CVE-2021-0001", "added", grain="capture"),
            _kev("2024-02-12", "CVE-2021-0001", "field_changed",
                 "knownRansomwareCampaignUse", "Unknown", "Known",
                 grain="capture"),
            _kev("2026-07-11", "CVE-2021-0001", "text_changed", "notes"),
            _kev("2026-07-12", "CVE-2021-0002", "field_changed",
                 "vendorProject", "A|B", "C"),
        ],
        "kev_state": {"baseline_date": "2021-12-23",
                      "backfill": {"watermark": "20260630093818"}},
        "rescore_rows": [
            _rescore("2026-07-15", "CVE-2021-0001", "rescore", "v3.1", 9.8,
                     "v3.1", 7.5),
            _rescore("2026-07-15", "CVE-2026-0003", "first_score"),
        ],
        "epss_rows": [
            _epss("2026-07-18", "CVE-2021-0001", 0.1, 0.4),
            _epss("2026-07-19", "CVE-2026-0003", 0.2, 0.3, reset=True),
            _epss("2026-07-22", "CVE-2026-0004", 0.5, 0.1),     # gap night
        ],
        "generated_at": GEN,
    }
    args.update(kw)
    return ob.build_observatory(**args)


def test_builds_one_dated_stream_and_validates():
    obj = _build()
    validate("observatory.json", obj)
    events = ob.decode(obj)
    assert [e["date"] for e in events] == sorted(e["date"] for e in events)
    assert obj["base_date"] == "2021-12-23"
    assert obj["last_observed"] == "2026-07-22"
    kinds = [e["kind"] for e in events]
    assert kinds.count("kev_flag") == 1 and kinds.count("kev_text") == 1
    trail = [e for e in events if e["cve"] == "CVE-2021-0001"]
    assert [e["kind"] for e in trail] == [
        "kev_added", "kev_flag", "kev_text", "rescore", "epss_move"]
    assert trail[1]["detail"] == "Unknown->Known"
    assert trail[1]["granularity"] == "capture"
    assert trail[3]["detail"] == "v3.1 9.8->v3.1 7.5 (acme)"
    assert trail[4]["detail"] == "0.10000->0.40000"
    # a "|" inside KEV text never breaks the encoding
    vendor = next(e for e in events if e["kind"] == "kev_field")
    assert vendor["detail"] == "vendorProject: A/B->C"


def test_sources_say_when_each_history_begins():
    obj = _build()
    src = obj["sources"]
    assert src["kev"] == {"first_observed": "2021-12-23",
                          "capture_until": "2026-06-30",
                          "nightly_from": "2026-07-11", "events": 4}
    assert src["rescore"]["first_observed"] == "2026-07-15"
    assert src["epss"]["first_observed"] == "2026-07-18"


def test_epss_reset_nights_are_excluded_and_gap_nights_pooled():
    obj = _build()
    epss = [e for e in ob.decode(obj) if e["kind"] == "epss_move"]
    assert [e["cve"] for e in epss] == ["CVE-2021-0001", "CVE-2026-0004"]
    assert epss[1]["granularity"] == "pooled"
    assert obj["sources"]["epss"]["excluded_reset"] == 1
    assert obj["sources"]["epss"]["nights"] == 3


def test_empty_histories_validate():
    obj = _build(kev_rows=[], kev_state=None, rescore_rows=[], epss_rows=[])
    validate("observatory.json", obj)
    assert obj["events"] == [] and obj["last_observed"] is None


def test_contract_rejects_an_event_before_its_history_began():
    obj = _build()
    obj["sources"]["rescore"]["first_observed"] = "2026-08-01"
    with pytest.raises(ContractViolation, match="before its history began"):
        validate("observatory.json", obj)


def test_contract_rejects_count_drift_and_bad_rows():
    obj = _build()
    obj["counts"]["first_score"] += 1
    with pytest.raises(ContractViolation, match="counts"):
        validate("observatory.json", obj)
    obj = _build()
    obj["events"][0] = obj["events"][0] + "|extra"
    with pytest.raises(ContractViolation, match="5"):
        validate("observatory.json", obj)
    obj = _build()
    obj["events"].reverse()
    with pytest.raises(ContractViolation, match="sorted"):
        validate("observatory.json", obj)


def test_contract_rejects_capture_granularity_outside_kev():
    obj = _build()
    i = next(i for i, s in enumerate(obj["events"])
             if s.split("|")[2] == str(ob.KINDS.index("rescore")))
    parts = obj["events"][i].split("|")
    parts[4] = str(ob.GRANULARITIES.index("capture"))
    obj["events"][i] = "|".join(parts)
    with pytest.raises(ContractViolation, match="capture"):
        validate("observatory.json", obj)
