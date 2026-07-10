"""Offline end-to-end: the full pipeline from fixtures into a temp dir,
every emitted file validated against the contracts. No network."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import contracts
from pipeline.__main__ import main

ALL_FILES = ["meta.json", "severity_inflation.json", "nine_eight_flood.json",
             "score_vs_reality.json", "nvd_decay.json", "cna_leaderboard.json",
             "volume_curve.json", "kev_latency.json", "cna_concentration.json",
             "advisory_quality.json", "cwe_distribution.json",
             "kev_ransomware.json", "dnssec_adoption.json"]


def _load(out: Path, name: str) -> dict:
    return json.loads((out / name).read_text(encoding="utf-8"))


def test_offline_fixtures_run_emits_all_valid_outputs(tmp_path, capsys):
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0

    for name in ALL_FILES:
        assert (tmp_path / name).exists(), f"{name} missing"
        contracts.validate(name, _load(tmp_path, name))

    meta = _load(tmp_path, "meta.json")
    assert meta["sample"] is False  # fixture runs are real pipeline runs
    assert meta["sources"]["cvelist"] == {"release": "fixtures", "cve_count": 11}
    assert meta["sources"]["epss"]["row_count"] == 7
    assert meta["sources"]["kev"]["count"] == 3

    decay = _load(tmp_path, "nvd_decay.json")
    assert decay["current"]["backlog_total"] == 31102  # 290 + 30412 + 400
    assert len(decay["history"]) == 1
    assert (tmp_path / "history" / "nvd_backlog.csv").exists()

    # KEV latency: all 3 fixture entries join; the 2021-12-01 entry lands
    # in the launch-backfill cohort, the other two in the trend stats.
    latency = _load(tmp_path, "kev_latency.json")
    assert latency["matched"] == {"total_kev": 3, "matched_cve": 3,
                                  "unmatched_cve": 0}
    assert latency["launch_backfill"]["n"] == 1
    assert latency["launch_backfill"]["median_days"] == -612.0
    assert [(y["year"], y["n"], y["median_days"])
            for y in latency["latency_by_year"]] == [(2023, 1, 30.0),
                                                     (2024, 1, -2.0)]
    buckets = {b["bucket"]: b["n"] for b in latency["latency_buckets"]}
    assert buckets["before_publish"] == 1 and buckets["8-30d"] == 1
    assert latency["headline"]["latest_year"] == 2024

    # CNA concentration: gap-filled 2014-2025 span, exact fixture counts.
    conc = _load(tmp_path, "cna_concentration.json")
    assert [y["year"] for y in conc["years"]] == list(range(2014, 2026))
    by_year = {y["year"]: y for y in conc["years"]}
    assert by_year[2014]["hhi"] == 10000.0
    assert by_year[2020]["hhi"] == 0.0  # gap year
    assert by_year[2024] == {"year": 2024, "cna_count": 3,
                             "newcomer_count": 0, "top5_share": 100.0,
                             "top10_share": 100.0, "hhi": 3333.3}
    board = conc["rejection_leaderboard"]
    assert board["min_total"] == 1  # offline default, mirrors --min-cves
    assert board["cnas"][0] == {"cna": "mitre", "total": 2, "rejected": 1,
                                "rejected_rate_pct": 50.0}

    # The fixture corpus carries no current-year records, so none of the
    # three flow charts may emit a pace projection (contracts allow absence).
    for name in ("volume_curve.json", "nine_eight_flood.json",
                 "cna_concentration.json"):
        assert "projection" not in _load(tmp_path, name), name

    # Advisory quality: fixture-mode min_n=1, so every publication year
    # charts; 2024's REJECTED record is excluded from the denominator.
    quality = _load(tmp_path, "advisory_quality.json")
    assert quality["min_n"] == 1
    by_year = {y["year"]: y for y in quality["years"]}
    assert sorted(by_year) == [2014, 2023, 2024, 2025]
    assert by_year[2014]["pct_missing_cwe"] == 100.0
    assert by_year[2024] == {"year": 2024, "n": 3,
                             "missing_cwe": 2, "pct_missing_cwe": 66.7,
                             "missing_cvss": 1, "pct_missing_cvss": 33.3,
                             "missing_affected": 2,
                             "pct_missing_affected": 66.7}

    # CWE distribution: window = last 10 complete years; CWE-79 leads by
    # volume, ties break by CWE number; unmapped CWE-1321 keeps its bare id.
    cwe = _load(tmp_path, "cwe_distribution.json")
    assert cwe["window"] == {"start_year": 2016, "end_year": 2025}
    assert [t["id"] for t in cwe["top_cwes"]] == \
        ["CWE-79", "CWE-416", "CWE-787", "CWE-1321"]
    assert cwe["top_cwes"][-1]["name"] == "CWE-1321"
    shares_2023 = next(y for y in cwe["years"] if y["year"] == 2023)["shares"]
    assert shares_2023["CWE-79"] == 66.7 and shares_2023["other"] == 0.0

    # DNSSEC adoption: fixture set = XA world + US/CN economy series;
    # the TT snapshot row (512 samples) falls under the min_seen floor.
    dnssec = _load(tmp_path, "dnssec_adoption.json")
    assert dnssec["world"]["latest"]["validating_pc"] == 38.5
    assert [e["cc"] for e in dnssec["economies"]] == ["US", "CN"]
    assert dnssec["spread"]["n_economies"] == 9
    assert meta["sources"]["apnic"]["economy_count"] == 2

    # KEV ransomware: all three entries dated; only the 2023 one is Known
    # (the 2024 entry has no knownRansomwareCampaignUse field at all).
    ransomware = _load(tmp_path, "kev_ransomware.json")
    assert [(y["year"], y["total"], y["known"])
            for y in ransomware["years"]] == [(2021, 1, 0), (2023, 1, 1),
                                              (2024, 1, 0)]
    assert ransomware["catalog"] == {"total": 3, "known": 1,
                                     "pct_known": 33.3}


def test_offline_rerun_replaces_todays_history_row(tmp_path, capsys):
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    decay = _load(tmp_path, "nvd_decay.json")
    assert len(decay["history"]) == 1  # same date -> replaced, not duplicated


def test_skip_nvd_carries_previous_run_forward(tmp_path, capsys):
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    first = _load(tmp_path, "nvd_decay.json")

    assert main(["--offline-fixtures", "--skip-nvd", "--out",
                 str(tmp_path)]) == 0
    carried = _load(tmp_path, "nvd_decay.json")
    contracts.validate("nvd_decay.json", carried)
    assert carried["stale"] is True
    assert carried["current"] == first["current"]
    assert carried["history"] == first["history"]  # no fake extra snapshot

    meta = _load(tmp_path, "meta.json")
    assert meta["sources"]["nvd"]["stale"] is True
    assert meta["sources"]["nvd"]["fetched_at"] == first["generated_at"]


def test_validation_failure_writes_nothing(tmp_path, capsys, monkeypatch):
    """The append-only history CSV must not be touched by a run that fails
    contract validation — the write happens only after every output passes."""
    def _always_fail(name, obj):
        raise contracts.ContractViolation(f"forced failure for {name}")

    monkeypatch.setattr(contracts, "validate", _always_fail)
    with pytest.raises(contracts.ContractViolation):
        main(["--offline-fixtures", "--out", str(tmp_path)])
    assert not (tmp_path / "history" / "nvd_backlog.csv").exists()
    for name in ALL_FILES:
        assert not (tmp_path / name).exists()


def test_skip_nvd_without_prior_data_omits_nvd_outputs(tmp_path, capsys):
    assert main(["--offline-fixtures", "--skip-nvd", "--out",
                 str(tmp_path)]) == 0
    assert not (tmp_path / "nvd_decay.json").exists()
    meta = _load(tmp_path, "meta.json")
    contracts.validate("meta.json", meta)
    assert "nvd" not in meta["sources"]
    # the other six files are all present and valid
    for name in ALL_FILES:
        if name != "nvd_decay.json":
            contracts.validate(name, _load(tmp_path, name))
