"""fetch_dnssec parsers: fixture shapes parse; shape drift fails loudly."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.fetch_dnssec import (ECONOMIES, WORLD_CC, load_index_file,
                                   load_series_file, parse_index,
                                   parse_series)

FIXTURES = Path(__file__).parent / "fixtures" / "dnssec"


# ------------------------------------------------------------- parse_series

def test_series_fixture_parses_sorted_30_day_points():
    series = load_series_file(FIXTURES / "XA.json", WORLD_CC)
    assert series.cc == WORLD_CC
    dates = [p.date for p in series.points]
    assert dates == sorted(dates)
    assert dates[0] == "2013-10-07" and dates[-1] == "2026-07-07"
    last = series.points[-1]
    assert last.seen == 493075676
    assert last.validating_pc == pytest.approx(38.452296)
    assert last.partial_pc == pytest.approx(8.835640)


def test_series_skips_malformed_rows_but_keeps_good_ones():
    obj = json.loads((FIXTURES / "XA.json").read_text("utf-8"))
    good = len(obj["data"])
    obj["data"].insert(0, {"date": "2013-01-01"})           # no window
    obj["data"].insert(0, {"30_day": {"seen": 1}})          # no date
    obj["data"].insert(0, "not-a-row")
    obj["data"].insert(0, {"date": "2013-01-02", "cc": "XA",
                           "30_day": {"seen": "many",      # wrong types
                                      "validating_pc": "x",
                                      "partial_validating_pc": None}})
    series = parse_series(obj, WORLD_CC)
    assert len(series.points) == good


def test_series_with_no_data_array_fails_loudly():
    with pytest.raises(ValueError, match="no 'data' array"):
        parse_series({"copyright": "..."}, WORLD_CC)


def test_series_with_zero_parseable_rows_fails_loudly():
    with pytest.raises(ValueError, match="zero parseable rows"):
        parse_series({"data": [{"date": "2020-01-01"}]}, WORLD_CC)


def test_series_for_wrong_code_fails_loudly():
    # x=<code> answering with another code's rows = endpoint drift.
    with pytest.raises(ValueError, match="endpoint drift"):
        load_series_file(FIXTURES / "US.json", "DE")


# -------------------------------------------------------------- parse_index

def test_index_fixture_parses_economy_rows_only():
    rows = load_index_file(FIXTURES / "index.html", min_rows=5)
    ccs = {r.cc for r in rows}
    # Region pseudo-codes are excluded ...
    assert ccs.isdisjoint({"XA", "XE", "QR"})
    # ... but QA is Qatar, a real economy, despite the leading Q.
    assert "QA" in ccs
    de = next(r for r in rows if r.cc == "DE")
    assert de.validating_pc == pytest.approx(80.96)
    assert de.partial_pc == pytest.approx(3.18)
    assert de.seen == 5788219
    assert de.weighted == 8147757


def test_index_sanity_floor_fails_loudly_on_shape_drift():
    html = (FIXTURES / "index.html").read_text("utf-8")
    with pytest.raises(ValueError, match="shape drift"):
        parse_index(html, min_rows=100)  # fixture has ~11 economies
    with pytest.raises(ValueError, match="shape drift"):
        parse_index("<html>redesigned page, no table</html>", min_rows=5)


def test_index_default_floor_is_production_strength():
    # ~240 economies live; anything under 100 must break the run.
    with pytest.raises(ValueError, match="only 0 economy rows"):
        parse_index("")


# ---------------------------------------------------------------- constants

def test_fixed_economy_set_is_ten_unique_codes():
    ccs = [cc for cc, _ in ECONOMIES]
    assert len(ccs) == 10
    assert len(set(ccs)) == 10
    assert all(len(cc) == 2 and cc.isupper() for cc in ccs)
