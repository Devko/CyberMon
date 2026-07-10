"""hygiene_metrics: sampling rules, spread buckets, baseline, run_stage."""
from __future__ import annotations

import pytest

from pipeline import contracts, hygiene_metrics
from pipeline.fetch_dnssec import DnssecData, DnssecPoint, DnssecSeries, EconomySnapshot
from pipeline.hygiene_metrics import (SPREAD_BUCKETS, build_dnssec_adoption,
                                      build_spread, monthly_series,
                                      quarterly_series, run_stage,
                                      spread_bucket)

GENERATED_AT = "2026-07-09T00:00:00Z"


def pt(date: str, pc: float, seen: int = 100_000,
       partial: float = 5.0) -> DnssecPoint:
    return DnssecPoint(date=date, seen=seen, validating_pc=pc,
                       partial_pc=partial)


def snap(cc: str, pc: float, seen: int = 100_000) -> EconomySnapshot:
    return EconomySnapshot(cc=cc, validating_pc=pc, partial_pc=1.0,
                           seen=seen, weighted=seen)


# ----------------------------------------------------------------- sampling

def test_monthly_series_keeps_last_point_per_month_rounded():
    rows = monthly_series([pt("2020-01-05", 10.04), pt("2020-01-25", 11.16),
                           pt("2020-02-10", 12.99)])
    assert rows == [{"month": "2020-01", "validating_pc": 11.2},
                    {"month": "2020-02", "validating_pc": 13.0}]


def test_quarterly_series_takes_quarter_ends_plus_newest():
    rows = quarterly_series([
        pt("2020-01-31", 1.0),   # not a quarter-end month: dropped
        pt("2020-03-15", 2.0), pt("2020-03-30", 3.0),  # last of March wins
        pt("2020-06-30", 4.0),
        pt("2021-02-14", 5.0),   # newest month always joins
    ])
    assert rows == [{"month": "2020-03", "validating_pc": 3.0},
                    {"month": "2020-06", "validating_pc": 4.0},
                    {"month": "2021-02", "validating_pc": 5.0}]


def test_quarterly_series_newest_month_never_duplicated():
    rows = quarterly_series([pt("2020-03-15", 2.0), pt("2020-06-30", 4.0)])
    assert [r["month"] for r in rows] == ["2020-03", "2020-06"]


# ----------------------------------------------------------------- baseline

def _world(dates_pcs) -> DnssecSeries:
    return DnssecSeries(cc="XA", points=[pt(d, p) for d, p in dates_pcs])


def test_decade_baseline_prefers_exactly_120_months_back():
    data = DnssecData(world=_world([("2013-10-07", 8.6), ("2016-07-15", 14.6),
                                    ("2026-07-07", 38.5)]), snapshot=[snap("DE", 80.0)])
    obj = build_dnssec_adoption(data, GENERATED_AT)
    assert obj["world"]["baseline"] == {"month": "2016-07",
                                        "validating_pc": 14.6}


def test_decade_baseline_falls_back_to_first_month():
    data = DnssecData(world=_world([("2020-05-01", 20.0),
                                    ("2026-07-07", 38.5)]),
                      snapshot=[snap("DE", 80.0)])
    obj = build_dnssec_adoption(data, GENERATED_AT)
    assert obj["world"]["baseline"] == {"month": "2020-05",
                                        "validating_pc": 20.0}


# ------------------------------------------------------------------- spread

def test_spread_bucket_edges_are_lower_inclusive():
    assert spread_bucket(0.0) == "<10%"
    assert spread_bucket(9.9) == "<10%"
    assert spread_bucket(10.0) == "10-25%"
    assert spread_bucket(25.0) == "25-50%"
    assert spread_bucket(49.9) == "25-50%"
    assert spread_bucket(50.0) == "50-75%"
    assert spread_bucket(75.0) == "75%+"
    assert spread_bucket(100.0) == "75%+"


def test_spread_filters_thin_samples_and_counts_all_buckets():
    rows = [snap("AA", 5.0), snap("BB", 55.0), snap("CC", 80.0),
            snap("DD", 99.0, seen=999)]  # under the floor: dropped
    spread = build_spread(rows, min_seen=1000)
    assert spread["min_seen"] == 1000
    assert spread["n_economies"] == 3
    assert spread["buckets"] == [
        {"bucket": "<10%", "n": 1}, {"bucket": "10-25%", "n": 0},
        {"bucket": "25-50%", "n": 0}, {"bucket": "50-75%", "n": 1},
        {"bucket": "75%+", "n": 1}]
    assert [b["bucket"] for b in spread["buckets"]] == SPREAD_BUCKETS


# ------------------------------------------------------------------ economies

def test_economies_ranked_by_current_rate_fixed_set_only():
    world = _world([("2026-07-07", 38.5)])
    economies = {
        "US": DnssecSeries(cc="US", points=[pt("2026-07-07", 44.5)]),
        "CN": DnssecSeries(cc="CN", points=[pt("2026-07-07", 0.1)]),
        "PH": DnssecSeries(cc="PH", points=[pt("2026-07-07", 93.5)]),
        "ZZ": DnssecSeries(cc="ZZ", points=[pt("2026-07-07", 99.0)]),  # not in set
    }
    obj = build_dnssec_adoption(DnssecData(world=world, economies=economies,
                                           snapshot=[snap("DE", 80.0)]),
                                GENERATED_AT)
    assert [e["cc"] for e in obj["economies"]] == ["PH", "US", "CN"]
    assert obj["economies"][0]["name"] == "Philippines"
    assert obj["economies"][-1]["latest_pc"] == 0.1


# ------------------------------------------------------------------ run_stage

def test_offline_stage_builds_valid_output_and_source():
    obj, source = run_stage(GENERATED_AT, offline_fixtures=True)
    contracts.validate("dnssec_adoption.json", obj)
    assert obj["generated_at"] == GENERATED_AT
    # Fixture set: XA + the US/CN series files.
    assert [e["cc"] for e in obj["economies"]] == ["US", "CN"]
    assert source == {"fetched_at": GENERATED_AT, "economy_count": 2,
                      "spread_economy_count": obj["spread"]["n_economies"]}
    # The TT fixture row (512 samples) fell under the min_seen floor.
    assert obj["spread"]["n_economies"] == 9


def test_offline_stage_world_matches_fixture_numbers():
    obj, _ = run_stage(GENERATED_AT, offline_fixtures=True)
    world = obj["world"]
    assert world["series"][0] == {"month": "2013-10", "validating_pc": 8.6}
    assert world["latest"] == {"date": "2026-07-07", "validating_pc": 38.5,
                               "partial_pc": 8.8, "seen": 493075676}
    assert world["baseline"] == {"month": "2016-07", "validating_pc": 14.6}
