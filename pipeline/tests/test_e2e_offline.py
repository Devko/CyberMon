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
             "kev_ransomware.json", "kev_guards.json", "breach_ledger.json",
             "extortion_ledger.json", "dnssec_adoption.json",
             "epss_report.json", "cve_calendar.json"]


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
    assert meta["sources"]["kev"]["count"] == 7
    assert meta["sources"]["hibp"]["breach_count"] == 9
    assert meta["sources"]["ransomwhere"]["address_count"] == 6
    assert meta["sources"]["ransomwhere"]["tx_count"] == 8

    decay = _load(tmp_path, "nvd_decay.json")
    assert decay["current"]["backlog_total"] == 31102  # 290 + 30412 + 400
    assert len(decay["history"]) == 1
    assert (tmp_path / "history" / "nvd_backlog.csv").exists()

    # KEV latency: the 3 original fixture entries join the corpus; the 4
    # guards-module entries (Fortinet/Cisco) deliberately have no fixture
    # CVE records, so they count as unmatched and stay out of every
    # latency stat. The 2021-12-01 entry lands in the launch-backfill
    # cohort, the other two matched ones in the trend stats.
    latency = _load(tmp_path, "kev_latency.json")
    assert latency["matched"] == {"total_kev": 7, "matched_cve": 3,
                                  "unmatched_cve": 4}
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

    # The fixtures carry no current-year records, so none of the four flow
    # charts may emit a pace projection (contracts allow absence).
    for name in ("volume_curve.json", "nine_eight_flood.json",
                 "cna_concentration.json", "breach_ledger.json"):
        assert "projection" not in _load(tmp_path, name), name

    # Breach ledger: 4 of the 9 fixture entries are excluded (one per
    # reason; SpamHaul carries both spam and malware flags and counts once,
    # under spam_list); the 2013 launch import stays out of the lag trend.
    ledger = _load(tmp_path, "breach_ledger.json")
    assert ledger["catalog"] == {
        "total": 9, "cohort": 5,
        "excluded": {"fabricated": 1, "spam_list": 1, "malware": 1,
                     "stealer_log": 1}}
    assert ledger["import_era"] == {"added_before": "2014-01-01", "n": 1,
                                    "median_days": 522.0}
    assert [(y["year"], y["n"], y["median_days"])
            for y in ledger["lag_by_year"]] == [(2024, 2, 213.0),
                                                (2025, 2, -8.0)]
    assert [y["year"] for y in ledger["volume_by_year"]] == [2013, 2024, 2025]
    assert ledger["class_shares"]["classes"][0] == "Email addresses"

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

    # KEV ransomware: all seven entries dated; the VendorX and FortiOS
    # entries are Known (the 2024-03-30 entry has no
    # knownRansomwareCampaignUse field at all — never counted as Known).
    ransomware = _load(tmp_path, "kev_ransomware.json")
    assert [(y["year"], y["total"], y["known"])
            for y in ransomware["years"]] == [(2021, 1, 0), (2022, 1, 0),
                                              (2023, 3, 2), (2024, 2, 0)]
    assert ransomware["catalog"] == {"total": 7, "known": 2,
                                     "pct_known": 28.6}

    # KEV guards: FortiOS/FortiProxy classify via the wholesale vendor
    # list, Cisco ASA via a product keyword, Cisco IOS XE misses on
    # purpose; the seeding-era 2022 entry charts like any other year.
    guards = _load(tmp_path, "kev_guards.json")
    assert [(y["year"], y["total"], y["security"], y["pct_security"])
            for y in guards["years"]] == [(2021, 1, 0, 0.0),
                                          (2022, 1, 0, 0.0),
                                          (2023, 3, 2, 66.7),
                                          (2024, 2, 1, 50.0)]
    by_vendor = {v["vendor"]: v for v in guards["vendors"]}
    # ties on entries break by casefolded vendor name
    assert [v["vendor"] for v in guards["vendors"]] == \
        ["Cisco", "Fortinet", "GitHub_M", "mitre", "VendorX"]
    assert by_vendor["Fortinet"] == {
        "vendor": "Fortinet", "entries": 2, "security_entries": 2,
        "pct_security": 100.0, "first_added": "2023-06-14",
        "last_added": "2024-05-15", "median_gap_days": 336.0}
    assert by_vendor["Cisco"]["security_entries"] == 1  # ASA yes, IOS XE no
    assert by_vendor["Cisco"]["median_gap_days"] == 549.0
    assert by_vendor["VendorX"]["median_gap_days"] is None  # single entry
    assert guards["ransomware"] == {
        "security": {"total": 3, "known": 1, "pct_known": 33.3},
        "other": {"total": 4, "known": 1, "pct_known": 25.0}}
    assert guards["catalog"]["total"] == 7
    assert guards["catalog"]["security"] == 3
    assert guards["catalog"]["classifier_version"] >= 1

    # EPSS Report Card: the two dated-and-published fixture entries grade
    # (v1-era above 10%, v2-era below 1%); the negative-latency 2024 entry
    # (listed two days before its CVE published) is ungradeable, never a
    # miss; nothing is pending because the fixture envelopes cover every
    # KEV date.
    epss_report = _load(tmp_path, "epss_report.json")
    # 7 KEV fixture entries (the guards module added four): six grade with
    # a day-before score, the 2021-12-01 entry is listed before its CVE
    # published and can have no prior score.
    assert epss_report["catalog"] == {
        "total": 7, "graded": 6,
        "ungradeable": {"pre_epss": 0, "listed_before_publication": 1,
                        "no_prior_score": 0},
        "pending_backfill": 0}
    assert [(y["year"], y["graded"], y["pct_below_1pct"])
            for y in epss_report["grade_by_year"]] == [(2021, 1, 0.0),
                                                       (2023, 1, 100.0)]
    assert [(m["model"], m["n"])
            for m in epss_report["distribution"]["by_model"]] == \
        [("v1", 1), ("v2", 1)]
    assert epss_report["percentiles"]["bottom_half"] == {"n": 1,
                                                         "pct": 50.0}
    assert [e["cve"] for e in epss_report["entries"]] == \
        ["CVE-2023-0003", "CVE-2023-0001", "CVE-2024-0002"]
    assert meta["sources"]["epss_history"] == {
        "fetched_at": epss_report["generated_at"], "graded": 2,
        "pending_backfill": 0}

    # CVE Calendar: the two old-ID fixture records land in the age buckets;
    # CVE-2024-0001 (2024-02-13) is the corpus's one patch-Tuesday hit; the
    # datePublished-less CVE-2025-0001 joins id_age but not the day tally.
    cal = _load(tmp_path, "cve_calendar.json")
    ages = {y["year"]: y for y in cal["id_age"]["years"]}
    assert ages[2014]["two_plus"] == 1   # CVE-2012-0002, published 2014
    assert ages[2025]["one_year"] == 1   # CVE-2024-0005, published 2025
    assert ages[2025]["n"] == 2 and ages[2025]["pct_prior_year"] == 50.0
    assert cal["id_age"]["clamped_negative"] == 0
    wk = {y["year"]: y for y in cal["weekday"]["years"]}
    assert wk[2025]["n"] == 1                       # undated record excluded
    assert wk[2024]["counts"] == [1, 1, 0, 1, 0, 0, 0]  # Mon/Tue/Thu
    pt = {y["year"]: y for y in cal["patch_tuesday"]["years"]}
    assert pt[2024]["on_pt"] == 1 and pt[2023]["on_pt"] == 0
    assert cal["patch_tuesday"]["calendar_pct"] == 3.3

    # Extortion ledger: 8 fixture ledger entries collapse to 7 payments (one
    # transaction pays two DemoLocker addresses); the Unlabeled address is
    # never ranked as a family; quarters are contiguous 2022Q1..2026Q1.
    ledger = _load(tmp_path, "extortion_ledger.json")
    assert ledger["catalog"] == {"addresses": 6, "families": 2,
                                 "transactions": 8, "payments": 7,
                                 "total_usd": 121000}
    assert len(ledger["revenue_by_quarter"]) == 17  # gap-filled quarters
    assert [f["family"] for f in ledger["families"]["top"]] == \
        ["DemoLocker", "PetitEncrypt"]
    assert ledger["families"]["unattributed"] == {"usd": 50000, "payments": 1}
    assert ledger["headline"]["peak_quarter"] == {"year": 2022, "quarter": 3,
                                                  "usd": 50000}


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


def test_skip_epss_report_carries_previous_run_forward(tmp_path, capsys):
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    first = _load(tmp_path, "epss_report.json")

    assert main(["--offline-fixtures", "--skip-epss-report", "--out",
                 str(tmp_path)]) == 0
    carried = _load(tmp_path, "epss_report.json")
    contracts.validate("epss_report.json", carried)
    assert carried["stale"] is True
    assert carried["entries"] == first["entries"]
    assert carried["catalog"] == first["catalog"]

    meta = _load(tmp_path, "meta.json")
    assert meta["sources"]["epss_history"]["stale"] is True
    assert meta["sources"]["epss_history"]["fetched_at"] == \
        first["generated_at"]


def test_skip_epss_report_without_prior_data_omits_outputs(tmp_path, capsys):
    assert main(["--offline-fixtures", "--skip-epss-report", "--out",
                 str(tmp_path)]) == 0
    assert not (tmp_path / "epss_report.json").exists()
    meta = _load(tmp_path, "meta.json")
    contracts.validate("meta.json", meta)
    assert "epss_history" not in meta["sources"]


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
