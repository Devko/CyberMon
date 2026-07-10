"""Shared fixtures: an Aggregator fed from the hand-written CVE records,
and a full set of built outputs (all offline, no network anywhere)."""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline import (breach_metrics, concentration_metrics,
                      extortion_metrics, guards_metrics, kev_metrics,
                      epss_report_metrics, extortion_metrics, kev_metrics,
from pipeline import (breach_metrics, calendar_metrics,
                      concentration_metrics, extortion_metrics, kev_metrics,
                      metrics, quality_metrics)
from pipeline.fetch_cvelist import iter_cve_records_from_dir
from pipeline.fetch_epss import load_epss_file
from pipeline.fetch_hibp import load_hibp_file
from pipeline.fetch_kev import load_kev_file
from pipeline.fetch_ransomwhere import load_ransomwhere_file

FIXTURES = Path(__file__).parent / "fixtures"
GENERATED_AT = "2026-07-09T00:00:00Z"


@pytest.fixture()
def agg(kev) -> metrics.Aggregator:
    aggregator = metrics.Aggregator(kev_ids=kev.cve_ids)
    aggregator.consume(iter_cve_records_from_dir(FIXTURES / "cvelist"))
    return aggregator


@pytest.fixture()
def epss():
    return load_epss_file(FIXTURES / "epss_scores.csv")


@pytest.fixture()
def kev():
    return load_kev_file(FIXTURES / "kev.json")


@pytest.fixture()
def hibp():
    return load_hibp_file(FIXTURES / "hibp_breaches.json")


@pytest.fixture()
def ransomwhere():
    return load_ransomwhere_file(FIXTURES / "ransomwhere.json")


@pytest.fixture()
def outputs(agg, epss, kev, hibp, ransomwhere) -> dict[str, dict]:
    """Every contracted output file, built from fixtures (min_cves=1)."""
    import json

    statuses = json.loads((FIXTURES / "nvd_statuses.json").read_text("utf-8"))
    history_rows = [metrics.backlog_row(statuses, "2026-07-09")]
    out = {
        "severity_inflation.json":
            metrics.build_severity_inflation(agg, GENERATED_AT,
                                             min_n=1, min_share=0.0),
        "nine_eight_flood.json":
            metrics.build_nine_eight_flood(agg, GENERATED_AT),
        "score_vs_reality.json":
            metrics.build_score_vs_reality(agg, epss.scores, kev.cve_ids,
                                           GENERATED_AT),
        "nvd_decay.json":
            metrics.build_nvd_decay(statuses, history_rows, GENERATED_AT),
        "cna_leaderboard.json":
            metrics.build_cna_leaderboard(agg, GENERATED_AT, min_cves=1),
        "volume_curve.json": metrics.build_volume_curve(agg, GENERATED_AT),
        "kev_latency.json":
            kev_metrics.build_kev_latency(agg, kev.entries, GENERATED_AT,
                                          min_n=1),
        "cna_concentration.json":
            concentration_metrics.build_cna_concentration(agg, GENERATED_AT,
                                                          min_total=1),
        "advisory_quality.json":
            quality_metrics.build_advisory_quality(agg, GENERATED_AT,
                                                   min_n=1),
        "cwe_distribution.json":
            quality_metrics.build_cwe_distribution(agg, GENERATED_AT,
                                                   min_n=1),
        "kev_ransomware.json":
            kev_metrics.build_kev_ransomware(kev.entries, GENERATED_AT,
                                             min_n=1),
        "kev_guards.json":
            guards_metrics.build_kev_guards(kev.entries, GENERATED_AT,
                                            min_n=1, min_vendor_entries=1),
        "breach_ledger.json":
            breach_metrics.build_breach_ledger(hibp.breaches, GENERATED_AT,
                                               min_n=1),
        "extortion_ledger.json":
            extortion_metrics.build_extortion_ledger(ransomwhere,
                                                     GENERATED_AT, min_n=1),
        "cve_calendar.json":
            calendar_metrics.build_cve_calendar(agg, GENERATED_AT, min_n=1),
        "meta.json": metrics.build_meta(
            GENERATED_AT, cvelist_release="fixtures", cve_count=agg.cve_count,
            epss_model_version=epss.model_version,
            epss_score_date=epss.score_date, epss_row_count=epss.row_count,
            kev_catalog_version=kev.catalog_version, kev_count=kev.count,
            nvd_source={"fetched_at": GENERATED_AT}),
    }
    out["meta.json"]["sources"]["hibp"] = {
        "fetched_at": GENERATED_AT, "breach_count": hibp.breach_count}
    epss_report, epss_history_source = epss_report_metrics.run_stage(
        Path("."), Path("."), GENERATED_AT, kev_entries=kev.entries,
        published_dates=agg.kev_published_dates,
        current_model_version=epss.model_version,
        skip=False, offline_fixtures=True, min_n=1,
        log=lambda _msg: None)
    out["epss_report.json"] = epss_report
    out["meta.json"]["sources"]["epss_history"] = epss_history_source
    return out
