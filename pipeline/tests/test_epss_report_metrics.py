"""epss_report_metrics: grading, classification, partial-backfill honesty."""
from __future__ import annotations

import json

import pytest

from pipeline import epss_report_metrics as erm
from pipeline.epss_report_contracts import validate
from pipeline.fetch_epss_history import reconstruct_state
from pipeline.fetch_kev import KevEntry

GENERATED_AT = "2026-07-09T00:00:00Z"


def _kev(cve, added):
    return KevEntry(cve_id=cve, date_added=added, due_date=None)


def _scored(score_date, epss, percentile, model):
    return {"score_date": score_date, "epss": epss,
            "percentile": percentile, "model": model, "reason": None}


def _null(score_date, reason="no_score_for_date"):
    return {"score_date": score_date, "epss": None, "percentile": None,
            "model": None, "reason": reason}


def _state(entries):
    return {"version": 1, "last_sync": GENERATED_AT, "entries": entries}


@pytest.fixture()
def rich_state():
    """Four graded entries across two eras + one null + one pending (the
    pending pair simply has no state entry)."""
    return _state({
        "CVE-2021-1111|2021-11-03": _scored("2021-11-02", 0.35064,
                                            0.98923, "v1"),
        "CVE-2021-2222|2021-11-03": _scored("2021-11-02", 0.0005,
                                            0.2, "v1"),
        "CVE-2023-3333|2023-06-02": _scored("2023-06-01", 0.05,
                                            0.6, "v3"),
        "CVE-2023-4444|2023-06-02": _scored("2023-06-01", 0.002,
                                            0.45, "v3"),
        "CVE-2024-5555|2024-03-30": _null("2024-03-29"),
    })


@pytest.fixture()
def rich_kev():
    return [_kev("CVE-2021-1111", "2021-11-03"),
            _kev("CVE-2021-2222", "2021-11-03"),
            _kev("CVE-2023-3333", "2023-06-02"),
            _kev("CVE-2023-4444", "2023-06-02"),
            _kev("CVE-2024-5555", "2024-03-30"),
            _kev("CVE-2025-6666", "2025-01-15")]  # pending: not in state


def test_build_grades_bands_and_pending(rich_state, rich_kev):
    obj = erm.build_epss_report(rich_state, rich_kev,
                                {"CVE-2024-5555": "2024-04-01"},
                                GENERATED_AT, min_n=1)
    validate("epss_report.json", obj)

    by_year = {row["year"]: row for row in obj["grade_by_year"]}
    assert by_year[2021]["n_above_10pct"] == 1     # 0.35064
    assert by_year[2021]["n_below_1pct"] == 1      # 0.0005
    assert by_year[2023] == {
        "year": 2023, "graded": 2,
        "n_below_1pct": 1, "n_1_to_10pct": 1, "n_above_10pct": 0,
        "pct_below_1pct": 50.0, "pct_1_to_10pct": 50.0,
        "pct_above_10pct": 0.0, "ungradeable": 0, "pending": 0}
    assert 2024 not in by_year  # graded 0 < min_n, even with min_n=1

    assert obj["catalog"] == {
        "total": 6, "graded": 4,
        "ungradeable": {"pre_epss": 0, "listed_before_publication": 1,
                        "no_prior_score": 0},
        "pending_backfill": 1}

    # Eras in release order, only eras with graded entries present.
    assert [row["model"] for row in obj["distribution"]["by_model"]] == \
        ["v1", "v3"]
    dist = {row["model"]: row for row in obj["distribution"]["by_model"]}
    assert dist["v1"]["counts"] == {"<0.1%": 1,   # 0.0005 = 0.05%
                                    "0.1-1%": 0, "1-10%": 0,
                                    ">10%": 1}    # 0.35064
    assert dist["v3"]["counts"] == {"<0.1%": 0,
                                    "0.1-1%": 1,  # 0.002 = 0.2%
                                    "1-10%": 1,   # 0.05 = 5%
                                    ">10%": 0}


def test_bucket_arithmetic_matches_score_vs_reality():
    assert erm.dist_bucket(0.0009) == "<0.1%"
    assert erm.dist_bucket(0.001) == "0.1-1%"
    assert erm.dist_bucket(0.0099) == "0.1-1%"
    assert erm.dist_bucket(0.01) == "1-10%"
    assert erm.dist_bucket(0.0999) == "1-10%"
    assert erm.dist_bucket(0.1) == ">10%"


def test_percentile_buckets_lower_edge_inclusive():
    assert erm.percentile_bucket(0.0) == "0-25"
    assert erm.percentile_bucket(0.2499) == "0-25"
    assert erm.percentile_bucket(0.25) == "25-50"
    assert erm.percentile_bucket(0.4999) == "25-50"
    assert erm.percentile_bucket(0.5) == "50-75"
    assert erm.percentile_bucket(0.75) == "75-90"
    assert erm.percentile_bucket(0.90) == "90-99"
    assert erm.percentile_bucket(0.99) == "99-100"
    assert erm.percentile_bucket(1.0) == "99-100"


def test_percentile_section_counts_bottom_half(rich_state, rich_kev):
    obj = erm.build_epss_report(rich_state, rich_kev, {},
                                GENERATED_AT, min_n=1)
    pct = obj["percentiles"]
    assert pct["n"] == 4
    assert pct["bottom_half"] == {"n": 2, "pct": 50.0}  # 0.2 and 0.45
    counts = {row["bucket"]: row["n"] for row in pct["buckets"]}
    assert counts == {"0-25": 1, "25-50": 1, "50-75": 1, "75-90": 0,
                      "90-99": 1, "99-100": 0}
    assert pct["median_percentile"] == 52.5  # median of .2 .45 .6 .98923


def test_entries_missing_percentile_stay_graded_but_not_ranked():
    state = _state({"CVE-2021-1111|2021-11-03":
                    _scored("2021-11-02", 0.35064, None, "v1")})
    obj = erm.build_epss_report(state, [_kev("CVE-2021-1111",
                                             "2021-11-03")],
                                {}, GENERATED_AT, min_n=1)
    validate("epss_report.json", obj)
    assert obj["catalog"]["graded"] == 1
    assert obj["percentiles"]["n"] == 0
    assert obj["percentiles"]["median_percentile"] is None


def test_ungradeable_classification_uses_publication_dates():
    state = _state({
        "CVE-2024-0001|2024-03-30": _null("2024-03-29"),  # published later
        "CVE-2024-0002|2024-03-30": _null("2024-03-29"),  # same-day publish
        "CVE-2024-0003|2024-03-30": _null("2024-03-29"),  # published before
        "CVE-2024-0004|2024-03-30": _null("2024-03-29"),  # unmatched CVE
        "CVE-2020-0005|2021-04-10": _null("2021-04-09", "pre_epss"),
    })
    kev = [_kev("CVE-2024-0001", "2024-03-30"),
           _kev("CVE-2024-0002", "2024-03-30"),
           _kev("CVE-2024-0003", "2024-03-30"),
           _kev("CVE-2024-0004", "2024-03-30"),
           _kev("CVE-2020-0005", "2021-04-10")]
    published = {"CVE-2024-0001": "2024-04-15",
                 "CVE-2024-0002": "2024-03-30",
                 "CVE-2024-0003": "2024-03-01"}
    obj = erm.build_epss_report(state, kev, published, GENERATED_AT,
                                min_n=1)
    assert obj["catalog"]["ungradeable"] == {
        "pre_epss": 1,
        "listed_before_publication": 2,  # later + same-day
        "no_prior_score": 2}             # published before + unmatched


def test_headline_prefers_last_complete_year(rich_state, rich_kev):
    obj = erm.build_epss_report(rich_state, rich_kev, {},
                                GENERATED_AT, min_n=1)
    assert obj["headline"] == {
        "graded": 4, "pct_below_1pct": 50.0,   # 0.0005 and 0.002 of 4
        "latest_year": 2023, "graded_latest": 2,
        "pct_below_1pct_latest": 50.0}


def test_headline_null_when_nothing_graded():
    obj = erm.build_epss_report(_state({}), [_kev("CVE-2025-1", "2025-01-01")],
                                {}, GENERATED_AT, min_n=10)
    validate("epss_report.json", obj)
    assert obj["headline"] is None
    assert obj["catalog"]["pending_backfill"] == 1


def test_min_n_filters_years_but_not_catalog(rich_state, rich_kev):
    obj = erm.build_epss_report(rich_state, rich_kev, {},
                                GENERATED_AT, min_n=2)
    assert [row["year"] for row in obj["grade_by_year"]] == [2021, 2023]
    obj = erm.build_epss_report(rich_state, rich_kev, {},
                                GENERATED_AT, min_n=3)
    assert obj["grade_by_year"] == []
    assert obj["catalog"]["graded"] == 4  # catalog never filtered


def test_output_round_trips_into_state(rich_state, rich_kev, tmp_path):
    obj = erm.build_epss_report(rich_state, rich_kev, {},
                                GENERATED_AT, min_n=1)
    (tmp_path / "epss_report.json").write_text(json.dumps(obj),
                                               encoding="utf-8")
    rebuilt = reconstruct_state(tmp_path, log=lambda _msg: None)
    assert rebuilt["entries"] == rich_state["entries"]
    assert rebuilt["last_sync"] == GENERATED_AT


# --------------------------------------------------------------------- stage

def test_run_stage_skip_carries_forward(tmp_path):
    prior = {"generated_at": "2026-07-01T00:00:00Z",
             "catalog": {"graded": 5, "pending_backfill": 2}}
    (tmp_path / "epss_report.json").write_text(json.dumps(prior),
                                               encoding="utf-8")
    obj, source = erm.run_stage(
        tmp_path, tmp_path, GENERATED_AT, kev_entries=[],
        published_dates={}, current_model_version="v2026.06.15",
        skip=True, offline_fixtures=False, log=lambda _msg: None)
    assert obj["stale"] is True
    assert obj["generated_at"] == GENERATED_AT
    assert source == {"fetched_at": "2026-07-01T00:00:00Z", "graded": 5,
                      "pending_backfill": 2, "stale": True}


def test_run_stage_skip_without_prior_omits(tmp_path):
    obj, source = erm.run_stage(
        tmp_path, tmp_path, GENERATED_AT, kev_entries=[],
        published_dates={}, current_model_version="v2026.06.15",
        skip=True, offline_fixtures=False, log=lambda _msg: None)
    assert obj is None and source is None


def test_run_stage_offline_fixtures(tmp_path):
    kev = [_kev("CVE-2023-0001", "2023-02-14"),
           _kev("CVE-2023-0003", "2021-12-01"),
           _kev("CVE-2024-0002", "2024-03-30")]
    obj, source = erm.run_stage(
        tmp_path, tmp_path, GENERATED_AT, kev_entries=kev,
        published_dates={"CVE-2024-0002": "2024-04-01"},
        current_model_version="v2026.06.15",
        skip=False, offline_fixtures=True, log=lambda _msg: None)
    validate("epss_report.json", obj)
    assert obj["catalog"] == {
        "total": 3, "graded": 2,
        "ungradeable": {"pre_epss": 0, "listed_before_publication": 1,
                        "no_prior_score": 0},
        "pending_backfill": 0}
    assert source == {"fetched_at": GENERATED_AT, "graded": 2,
                      "pending_backfill": 0}
    # offline mode never writes disk state
    assert not (tmp_path / "epss_report_state.json").exists()


def test_run_stage_warns_on_unknown_model_version(tmp_path):
    logs = []
    erm.run_stage(tmp_path, tmp_path, GENERATED_AT,
                  kev_entries=[], published_dates={},
                  current_model_version="v2027.09.09",
                  skip=False, offline_fixtures=False,
                  backfill_batch=0, session=object(), log=logs.append)
    assert any("model_version" in line and "WARNING" in line
               for line in logs)
