"""Contract tests for support_windows.json (pipeline/eol_contracts.py) and
meta.sources.eol."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from pipeline import contracts, eol_metrics
from pipeline.contracts import ContractViolation
from pipeline.fetch_eol import load_full_file

FIX = Path(__file__).parent / "fixtures" / "eol_products_full.json"
GEN = "2026-11-05T06:00:00Z"


@pytest.fixture()
def obj() -> dict:
    return eol_metrics.build_support_windows(
        load_full_file(FIX), GEN, min_products=1, min_category_products=1)


def test_fixture_output_validates(obj):
    contracts.validate("support_windows.json", obj)


def test_real_floor_output_validates():
    contracts.validate("support_windows.json",
                       eol_metrics.build_support_windows(load_full_file(FIX),
                                                         GEN))


def test_carried_forward_edition_validates(obj):
    carried = {**copy.deepcopy(obj), "generated_at": "2027-01-02T06:00:00Z",
               "stale": True}
    contracts.validate("support_windows.json", carried)


def _broken(obj, mutate):
    bad = copy.deepcopy(obj)
    mutate(bad)
    with pytest.raises(ContractViolation):
        contracts.validate("support_windows.json", bad)


def test_states_must_sum_to_lines(obj):
    _broken(obj, lambda o: o["catalog"].__setitem__("open", 99))


def test_median_and_lower_bound_are_exclusive(obj):
    def mutate(o):
        o["periods"]["all"]["early"]["median_at_least"] = 5
    _broken(obj, mutate)


def test_only_the_as_of_year_is_partial(obj):
    _broken(obj, lambda o: o["years"][0].__setitem__("partial", True))


def test_high_open_share_must_be_provisional(obj):
    def mutate(o):
        row = next(r for r in o["years"] if r["open_pct"] > 20)
        row["provisional"] = False
    _broken(obj, mutate)


def test_thin_year_publishes_no_median(obj):
    def mutate(o):
        o["min_products"] = 50
    _broken(obj, mutate)


def test_categories_must_stay_sorted(obj):
    _broken(obj, lambda o: o["categories"].reverse())


def test_category_counts_must_add_up(obj):
    _broken(obj, lambda o: o["categories"][0].__setitem__(
        "no_supported_line", o["categories"][0]["no_supported_line"] + 1))


def test_panel_cells_cover_every_panel_product(obj):
    _broken(obj, lambda o: o["panel"].__setitem__("products", 3))


def test_years_must_reach_the_as_of_year(obj):
    _broken(obj, lambda o: o["years"].pop())


def test_gap_lines_partition_the_phase_lines(obj):
    _broken(obj, lambda o: o["phases"].__setitem__("gap_unknown_lines", 5))


def _meta(eol_block):
    return {
        "generated_at": GEN, "sample": False,
        "sources": {
            "cvelist": {"release": "r", "cve_count": 1},
            "epss": {"model_version": "v", "score_date": "2026-11-05",
                     "row_count": 1},
            "kev": {"catalog_version": "v", "count": 1},
            "eol": eol_block,
        },
    }


def test_meta_source_block():
    good = {"fetched_at": GEN, "products": 489, "lines": 9367,
            "not_modified": True}
    contracts.validate("meta.json", _meta(good))
    contracts.validate("meta.json", _meta({**good, "stale": True}))
    with pytest.raises(ContractViolation):
        contracts.validate("meta.json", _meta({**good, "not_modified": 1}))
    with pytest.raises(ContractViolation):
        contracts.validate("meta.json", _meta({**good, "products": 0}))
