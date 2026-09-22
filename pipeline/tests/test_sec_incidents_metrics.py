"""Incident Clock builder + contract (pipeline/sec_incidents_metrics.py,
pipeline/sec_incidents_contracts.py) and its degrade path in __main__.
Every filing here is synthetic."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from pipeline import contracts
from pipeline import sec_incidents_metrics as m
from pipeline.__main__ import _sec_incidents_outputs
from pipeline.contracts import ContractViolation
from pipeline.fetch_sec_incidents import (Filing, QueryResult,
                                          SecIncidentData,
                                          load_sec_incidents_file)

FIX = Path(__file__).parent / "fixtures" / "sec_incidents.json"
GEN = "2026-09-22T02:50:21Z"


def _f(adsh_n, date, form="8-K", items=("1.05",), cik="9990001",
       primary=True):
    return Filing(adsh=f"0009999999-24-{adsh_n:06d}", cik=cik,
                  company=f"Synthetic {cik}", ticker=None, file_date=date,
                  form=form, items=items, primary=primary)


def _data(f105=(), f801=()):
    return SecIncidentData(results={
        "item_105": QueryResult("item_105", filings=list(f105)),
        "item_801": QueryResult("item_801", filings=list(f801))},
        start="2023-12-18", end=GEN[:10])


def _fixture_obj():
    return m.build_sec_incidents(load_sec_incidents_file(FIX), GEN)


# ------------------------------------------------------------ classification

def test_item_list_decides_not_the_phrase():
    assert m.is_item_105(_f(1, "2024-01-02", items=("8.01",))) == (False,
                                                                   False)
    assert m.is_item_105(_f(1, "2024-01-02", items=("1.05",))) == (True,
                                                                   False)
    # items missing: fall back to the phrase match, and say so
    assert m.is_item_105(_f(1, "2024-01-02", items=None)) == (True, True)


def test_801_needs_the_primary_document_and_no_105():
    assert m.is_item_801(_f(1, "2024-01-02", items=("8.01",)))[0]
    assert not m.is_item_801(_f(1, "2024-01-02", items=("8.01",),
                                primary=False))[0]
    assert not m.is_item_801(_f(1, "2024-01-02", items=("8.01", "1.05")))[0]
    assert not m.is_item_801(_f(1, "2024-01-02", form="8-K/A",
                                items=("8.01",)))[0]


# ------------------------------------------------------------------- builder

def test_fixture_build_counts_and_validates():
    obj = _fixture_obj()
    contracts.validate("sec_incidents.json", obj)
    t = obj["totals"]
    assert (t["originals"], t["amendments"], t["voluntary"]) == (7, 4, 3)
    assert t["companies_105"] == 7 and t["companies_801"] == 3
    d = obj["diagnostics"]
    assert d["dropped_105"] == 1 and d["phrase_fallback_105"] == 1
    assert obj["monthly"][0]["month"] == "2023-12"
    assert obj["monthly"][0]["partial"] and obj["monthly"][-1]["partial"]
    assert obj["monthly"][-1]["month"] == "2026-09"


def test_amendment_lag_matches_nearest_prior_original_same_cik():
    orig1 = _f(1, "2024-01-10")
    orig2 = _f(2, "2024-05-01")
    other = _f(3, "2024-01-01", cik="9990002")
    a1 = _f(4, "2024-02-19", form="8-K/A")      # -> orig1, 40 days
    a2 = _f(5, "2024-03-01", form="8-K/A")      # -> orig1 again (not first)
    a3 = _f(6, "2024-05-01", form="8-K/A")      # same day -> orig2, 0 days
    a4 = _f(7, "2024-02-01", form="8-K/A", cik="9990009")   # no original
    obj = m.build_sec_incidents(_data([orig1, orig2, other, a1, a2, a3, a4]),
                                GEN)
    lag = obj["amendment_lag"]
    assert lag["amended"] == 2
    assert lag["matched_amendments"] == 3 and lag["unmatched_amendments"] == 1
    assert lag["median_days"] == 20.0 and lag["max_days"] == 40
    by_label = {b["label"]: b["n"] for b in lag["buckets"]}
    assert by_label["0–7 days"] == 1 and by_label["31–90 days"] == 1
    receipt = next(r for r in obj["recent"] if r["adsh"] == a2.adsh)
    assert receipt["original_date"] == "2024-01-10"
    assert receipt["lag_days"] == 51     # 2024 is a leap year
    contracts.validate("sec_incidents.json", obj)


def test_no_amendments_means_null_lag_stats():
    obj = m.build_sec_incidents(_data([_f(1, "2024-01-10")]), GEN)
    assert obj["amendment_lag"]["median_days"] is None
    contracts.validate("sec_incidents.json", obj)


def test_filings_outside_the_window_are_ignored():
    obj = m.build_sec_incidents(_data([_f(1, "2023-11-30"),
                                       _f(2, "2026-10-01")]), GEN)
    assert obj["totals"]["originals"] == 0
    contracts.validate("sec_incidents.json", obj)


def test_recent_board_is_capped_and_newest_first():
    fs = [_f(i, f"2024-{1 + i % 12:02d}-{1 + i % 27:02d}", cik=str(9990000 + i))
          for i in range(1, 40)]
    obj = m.build_sec_incidents(_data(fs), GEN)
    assert len(obj["recent"]) == m.RECENT_LIMIT
    dates = [r["date"] for r in obj["recent"]]
    assert dates == sorted(dates, reverse=True)
    contracts.validate("sec_incidents.json", obj)


# ------------------------------------------------------------------ contract

def test_empty_edition_validates_and_claims_no_counts():
    obj = m.build_empty(GEN)
    contracts.validate("sec_incidents.json", obj)
    assert obj["totals"] is None and obj["monthly"] == []


def test_empty_edition_with_zeros_is_rejected():
    obj = m.build_empty(GEN)
    obj["totals"] = {"originals": 0}
    with pytest.raises(ContractViolation):
        contracts.validate("sec_incidents.json", obj)


@pytest.mark.parametrize("mutate", [
    lambda o: o["monthly"].pop(3),                             # gap
    lambda o: o["monthly"][5].__setitem__("originals", 99),    # sums
    lambda o: o["quarterly"][2].__setitem__("partial", True),
    lambda o: o["totals"].__setitem__("companies_801", 99),
    lambda o: o["recent"].reverse(),
    lambda o: o["recent"][0].__setitem__("url", "https://example.com/"),
    lambda o: o["amendment_lag"]["buckets"][0].__setitem__("n", 5),
    lambda o: o["definitions"]["item_801"].__setitem__("q", '"breach"'),
    lambda o: o.__setitem__("status", "partial"),
])
def test_contract_rejects_broken_editions(mutate):
    obj = copy.deepcopy(_fixture_obj())
    mutate(obj)
    with pytest.raises(ContractViolation):
        contracts.validate("sec_incidents.json", obj)


def test_meta_source_blocks():
    base = {"generated_at": GEN, "sources": {}}
    obj = _fixture_obj()
    ok = m.source_block(obj, GEN)
    assert ok == {"fetched_at": GEN, "filings_105": 7, "amendments_105": 4,
                  "filings_801": 3}
    for block in (ok, m.EMPTY_SOURCE, {**ok, "stale": True}):
        meta = copy.deepcopy(base)
        meta["sources"]["sec_incidents"] = block
        _check_sec_meta(meta)
    with pytest.raises(ContractViolation):
        _check_sec_meta({"sources": {"sec_incidents": {
            "status": "empty", "fetched_at": GEN}}})


def _check_sec_meta(meta):
    """Run only the sec_incidents branch of the meta contract: wrap the
    block in the committed meta.json (which carries every other source)."""
    data = Path(__file__).resolve().parents[2] / "site" / "data" / "meta.json"
    full = json.loads(data.read_text(encoding="utf-8"))
    full["sources"]["sec_incidents"] = meta["sources"]["sec_incidents"]
    contracts.validate("meta.json", full)


# ------------------------------------------------------------- degrade path

def test_fresh_fetch_builds_and_stamps_the_source(tmp_path):
    obj, src = _sec_incidents_outputs(tmp_path, load_sec_incidents_file(FIX),
                                      None, GEN)
    assert obj["status"] == "ok" and src["fetched_at"] == GEN


def test_outage_with_a_counted_prior_carries_forward(tmp_path):
    prior = _fixture_obj()
    prior["generated_at"] = "2026-09-21T02:50:00Z"
    (tmp_path / "sec_incidents.json").write_text(json.dumps(prior))
    (tmp_path / "meta.json").write_text(json.dumps({"sources": {
        "sec_incidents": m.source_block(prior, "2026-09-21T02:50:00Z")}}))
    obj, src = _sec_incidents_outputs(tmp_path, None, "SEC down", GEN)
    assert obj["stale"] is True and obj["generated_at"] == GEN
    assert obj["totals"] == prior["totals"]
    assert src["stale"] is True
    assert src["fetched_at"] == "2026-09-21T02:50:00Z"


def test_outage_with_only_the_empty_edition_stays_empty(tmp_path):
    (tmp_path / "sec_incidents.json").write_text(
        json.dumps(m.build_empty("2026-09-21T02:50:00Z")))
    (tmp_path / "meta.json").write_text(json.dumps(
        {"sources": {"sec_incidents": m.EMPTY_SOURCE}}))
    obj, src = _sec_incidents_outputs(tmp_path, None, "SEC down", GEN)
    # nothing counted was ever published: no stale marker on a non-count
    assert obj["status"] == "empty" and "stale" not in obj
    assert obj["generated_at"] == GEN
    assert src == {"status": "empty"}
    contracts.validate("sec_incidents.json", obj)


def test_outage_with_no_prior_emits_the_empty_edition(tmp_path):
    obj, src = _sec_incidents_outputs(tmp_path, None, "SEC down", GEN)
    assert obj["status"] == "empty" and src == {"status": "empty"}
