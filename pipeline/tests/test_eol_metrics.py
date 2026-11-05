"""Unit tests for the Support Windows stage (pipeline/eol_metrics.py)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import eol_metrics as em
from pipeline.fetch_eol import EolSnapshot, Product, ReleaseLine, load_full_file

FIX = Path(__file__).parent / "fixtures" / "eol_products_full.json"
GEN = "2026-11-05T06:00:00Z"


def _line(release, eol=None, is_eol=False, **kw):
    return ReleaseLine(name="x", release=release, eol=eol, is_eol=is_eol,
                       has_eoas=kw.pop("has_eoas", False), **kw)


def _build(snap=None, **floors):
    snap = snap or load_full_file(FIX)
    return em.build_support_windows(
        snap, GEN, **({"min_products": 1, "min_category_products": 1}
                      | floors))


# ------------------------------------------------------------ Kaplan-Meier

def test_km_median_without_censoring_is_the_lower_median():
    items = [(10, True, 1), (20, True, 1), (30, True, 1), (40, True, 1)]
    assert em.km_median(items) == (20, None)


def test_km_median_keeps_censored_lines_at_risk():
    # A line open at 20 days is neither dropped (median of 10/30/40 = 30
    # by accident here, but for the wrong reason) nor counted as ended at
    # 20 (which would give 20): it leaves the risk set at 20.
    items = [(10, True, 1), (20, False, 1), (30, True, 1), (40, True, 1)]
    assert em.km_median(items) == (30, None)
    as_ended = [(10, True, 1), (20, True, 1), (30, True, 1), (40, True, 1)]
    assert em.km_median(as_ended) == (20, None)


def test_km_median_not_reached_gives_a_lower_bound():
    items = [(10, True, 1), (100, False, 1), (120, False, 1)]
    assert em.km_median(items) == (None, 120)


def test_km_median_empty():
    assert em.km_median([]) == (None, None)


def test_km_median_weights_products_equally():
    # Product A ships three 10-day lines, B and C one long line each. With
    # one vote per product the median is B's window; one vote per line
    # would give 10.
    items = [(10, True, 1 / 3)] * 3 + [(1000, True, 1), (2000, True, 1)]
    assert em.km_median(items) == (1000, None)
    assert em.km_median([(t, e, 1) for t, e, _ in items]) == (10, None)


def test_weighted_median():
    assert em.weighted_median([(1, 1), (5, 1), (9, 1)]) == 5
    assert em.weighted_median([(1, 3), (5, 1)]) == 1
    assert em.weighted_median([]) is None


# ------------------------------------------------------------ line states

@pytest.mark.parametrize("line,state,item", [
    (_line("2020-01-01", "2022-01-01", True), "ended", (731, True)),
    (_line("2020-01-01", "2030-01-01", False), "scheduled", (3653, True)),
    (_line("2020-01-01", None, False), "open", (2500, False)),
    (_line("2020-01-01", None, True), "ended_undated", None),
    # the date wins over a stale upstream flag
    (_line("2020-01-01", "2022-01-01", False), "ended", (731, True)),
])
def test_line_state_and_window(line, state, item):
    as_of = "2026-11-05"
    assert em.line_state(line, as_of) == state
    assert em.window_item(line, as_of) == item


def test_active_item_only_for_phased_lines():
    as_of = "2026-11-05"
    assert em.active_item(_line("2020-01-01", "2024-01-01"), as_of) is None
    phased = _line("2020-01-01", "2024-01-01", has_eoas=True,
                   eoas="2021-01-01", is_eoas=True)
    assert em.active_item(phased, as_of) == (366, True)
    undated = _line("2020-01-01", None, has_eoas=True, is_eoas=True)
    assert em.active_item(undated, as_of) is None
    still = _line("2020-01-01", None, has_eoas=True, is_eoas=False)
    assert em.active_item(still, as_of) == (2500, False)


# ------------------------------------------------------------ the build

def test_fixture_catalogue_counts():
    obj = _build()
    c = obj["catalog"]
    assert c["products"] == 8
    assert c["lines"] == 23 and c["unreleased"] == 1
    assert (c["ended"], c["scheduled"], c["open"], c["ended_undated"]) == \
        (16, 4, 2, 1)
    assert c["no_supported_line"] == 2      # demo-framework, demo-legacy
    assert c["newest_line_ended"] == 3      # ... and demo-app
    assert c["first_year"] == 2010 and c["last_year"] == 2025


def test_panel_needs_a_usable_line_in_both_windows():
    obj = _build()
    # demo-phone's only 2014-2016 line ended without a date; demo-server
    # has no early line.
    assert obj["panel"]["products"] == 4
    pan = obj["periods"]["panel"]
    assert pan["early"]["products"] == pan["late"]["products"] == 4
    assert obj["periods"]["all"]["late"]["products"] == 6


def test_years_are_contiguous_to_the_as_of_year():
    obj = _build()
    ys = [r["year"] for r in obj["years"]]
    assert ys == list(range(2010, 2027))
    assert [r["year"] for r in obj["years"] if r["partial"]] == [2026]
    empty = next(r for r in obj["years"] if r["year"] == 2011)
    assert empty["products"] == 0 and empty["median_days"] is None
    assert empty["provisional"] is True


def test_open_share_marks_a_year_provisional():
    obj = _build()
    y2024 = next(r for r in obj["years"] if r["year"] == 2024)
    # demo-lang 4 and demo-server 3.1 are open: half of 2024's product
    # weight has no announced end.
    assert y2024["open_pct"] > em.PROVISIONAL_OPEN_PCT
    assert y2024["provisional"] is True
    y2014 = next(r for r in obj["years"] if r["year"] == 2014)
    assert y2014["open_pct"] == 0.0 and y2014["provisional"] is False


def test_real_floors_withhold_thin_medians():
    obj = em.build_support_windows(load_full_file(FIX), GEN)
    assert obj["min_products"] == em.MIN_PRODUCTS
    assert all(r["median_days"] is None for r in obj["years"])
    assert all(r["median_days"] is None for r in obj["categories"])


def test_phases_cover_products_with_active_support():
    ph = _build()["phases"]
    assert ph["products"] == 2 and ph["lines"] == 8
    assert ph["gap_lines"] == 7 and ph["gap_unknown_lines"] == 1
    assert ph["active_median_days"] < ph["security_median_days"]


def test_categories_sorted_by_median_and_sum_to_the_catalogue():
    obj = _build()
    rows = obj["categories"]
    meds = [r["median_days"] for r in rows]
    assert meds == sorted(meds, reverse=True)
    assert sum(r["products"] for r in rows) == obj["catalog"]["products"]
    assert sum(r["lines"] for r in rows) == obj["catalog"]["lines"]


def test_prior_product_count(tmp_path):
    assert em.prior_product_count(None) is None
    assert em.prior_product_count(tmp_path) is None
    (tmp_path / em.OUTPUT_NAME).write_text(json.dumps(
        {"catalog": {"products": 489}}), "utf-8")
    assert em.prior_product_count(tmp_path) == 489


def test_run_stage_offline_uses_the_fixture():
    obj, source = em.run_stage(Path("/nonexistent"), GEN,
                               offline_fixtures=True, log=lambda m: None)
    assert source == {"fetched_at": GEN, "products": 8, "lines": 23,
                      "not_modified": False}
    assert obj["min_products"] == 1


def test_unreleased_line_is_counted_not_charted():
    p = Product("p", "P", "app", [_line("2099-01-01"),
                                  _line("2020-01-01", "2021-01-01", True)])
    obj = _build(EolSnapshot(products=[p]))
    assert obj["catalog"]["unreleased"] == 1
    assert obj["catalog"]["lines"] == 1
