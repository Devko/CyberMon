"""The additive ``without_linux`` variants (volume curve, 9.8 flood, CNA
concentration): exact subtraction of the Linux kernel CNA's records, their
own pace projections, and the contract guards."""
from __future__ import annotations

import copy

import pytest

from pipeline import concentration_metrics, contracts, metrics

GEN = "2026-07-01T00:00:00Z"  # far enough into the year to pace


def _f(cve_id, year, cna, score=None, state="PUBLISHED"):
    return metrics.CveFacts(cve_id, state, year, cna,
                            cna_scores={"v3": score} if score else {},
                            date_published=f"{year}-03-01")


def _agg():
    agg = metrics.Aggregator()
    facts = [
        _f("CVE-2023-0001", 2023, "a", 9.8),
        _f("CVE-2024-0001", 2024, "a", 5.0),
        _f("CVE-2024-0002", 2024, "b", 7.5),
        _f("CVE-2024-0003", 2024, "Linux"),
        _f("CVE-2024-0004", 2024, "Linux"),
        _f("CVE-2024-0005", 2024, "Linux", 5.5),
        _f("CVE-2024-0006", 2024, "Linux", state="REJECTED"),
        _f("CVE-2026-0001", 2026, "Linux"),
        _f("CVE-2026-0002", 2026, "b", 9.1),
    ]
    for f in facts:
        agg.add(f)
    return agg


def test_volume_without_linux_subtracts_published_and_rejected():
    out = metrics.build_volume_curve(_agg(), GEN)
    wl = out["without_linux"]
    assert wl["cna"] == "Linux"
    assert [r["year"] for r in wl["years"]] == \
        [r["year"] for r in out["years"]]
    by = {r["year"]: r for r in wl["years"]}
    assert by[2024] == {"year": 2024, "published": 2, "rejected": 0}
    assert by[2023] == {"year": 2023, "published": 1, "rejected": 0}
    # its own projection, paced from the reduced count (1 record so far)
    assert wl["projection"]["published"] == \
        metrics.pace_projection(1, GEN)
    assert out["projection"]["published"] == metrics.pace_projection(2, GEN)
    contracts.validate("volume_curve.json", out)


def test_flood_without_linux_subtracts_bucket_by_bucket():
    out = metrics.build_nine_eight_flood(_agg(), GEN)
    by = {r["year"]: r for r in out["without_linux"]["years"]}
    full = {r["year"]: r for r in out["years"]}
    assert full[2024]["unscored"] == 2 and full[2024]["medium"] == 2
    assert by[2024] == {"year": 2024, "critical": 0, "high": 1, "medium": 1,
                        "low": 0, "unscored": 0}
    assert out["without_linux"]["projection"]["total"] == \
        metrics.pace_projection(1, GEN)
    contracts.validate("nine_eight_flood.json", out)


def test_projection_absent_when_nothing_left_to_pace():
    agg = metrics.Aggregator()
    agg.add(_f("CVE-2025-0001", 2025, "a", 5.0))
    agg.add(_f("CVE-2026-0001", 2026, "Linux"))
    vol = metrics.build_volume_curve(agg, GEN)
    assert "projection" in vol and "projection" not in vol["without_linux"]
    flood = metrics.build_nine_eight_flood(agg, GEN)
    assert "projection" not in flood["without_linux"]


def test_concentration_without_linux_recomputes_shares():
    out = concentration_metrics.build_cna_concentration(_agg(), GEN,
                                                        min_total=1)
    by = {r["year"]: r for r in out["without_linux"]["years"]}
    # 2024 without Linux: a 1, b 1 -> HHI 5000; Linux (published and
    # rejected) leaves the active roster too
    assert by[2024] == {"year": 2024, "cna_count": 2, "top5_share": 100.0,
                        "top10_share": 100.0, "hhi": 5000.0}
    full = {r["year"]: r for r in out["years"]}
    assert full[2024]["hhi"] == 4400.0  # 3/5 Linux, 1/5, 1/5 -> 0.44
    contracts.validate("cna_concentration.json", out)


def test_no_linux_records_leaves_series_unchanged():
    agg = metrics.Aggregator()
    agg.add(_f("CVE-2025-0001", 2025, "a", 5.0))
    vol = metrics.build_volume_curve(agg, GEN)
    assert vol["without_linux"]["years"] == vol["years"]


def test_contracts_reject_a_subtraction_that_adds_records():
    out = metrics.build_volume_curve(_agg(), GEN)
    bad = copy.deepcopy(out)
    bad["without_linux"]["years"][1]["published"] += 99
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("volume_curve.json", bad)
    bad = copy.deepcopy(out)
    bad["without_linux"]["years"].pop()
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("volume_curve.json", bad)

    flood = metrics.build_nine_eight_flood(_agg(), GEN)
    bad = copy.deepcopy(flood)
    bad["without_linux"]["projection"]["year"] = 2025
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("nine_eight_flood.json", bad)

    conc = concentration_metrics.build_cna_concentration(_agg(), GEN,
                                                         min_total=1)
    bad = copy.deepcopy(conc)
    bad["without_linux"]["years"][0]["cna_count"] += 5
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("cna_concentration.json", bad)
