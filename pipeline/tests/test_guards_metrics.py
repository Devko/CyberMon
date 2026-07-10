"""guards_metrics.build_kev_guards: year shares, the recidivism board,
the ransomware split, and the audit block."""
from __future__ import annotations

from pipeline.fetch_kev import KevEntry
from pipeline.guards_metrics import build_kev_guards
from pipeline.security_products import CLASSIFIER_VERSION, rule_count

GENERATED_AT = "2026-07-09T00:00:00Z"


def entry(cve="CVE-2024-0001", added="2024-01-10", vendor="Fortinet",
          product="FortiOS", ransomware=None):
    return KevEntry(cve_id=cve, date_added=added, due_date=None,
                    ransomware_use=ransomware, vendor_project=vendor,
                    product=product)


def test_year_shares_and_min_n():
    entries = [
        entry(added="2023-01-01"),                              # security
        entry(added="2023-02-01", vendor="Microsoft",
              product="Exchange Server"),                       # not
        entry(added="2023-03-01", vendor="Cisco",
              product="Adaptive Security Appliance (ASA)"),     # security
        entry(added="2024-06-01", vendor="Microsoft",
              product="Windows"),                               # thin year
    ]
    out = build_kev_guards(entries, GENERATED_AT, min_n=3,
                           min_vendor_entries=1)
    # 2024 has 1 < min_n entries and never plots; the catalog still counts it
    assert [(y["year"], y["total"], y["security"], y["pct_security"])
            for y in out["years"]] == [(2023, 3, 2, 66.7)]
    assert out["catalog"]["total"] == 4
    assert out["catalog"]["security"] == 2


def test_seeding_era_years_belong():
    # the guard share reads the catalog as a snapshot — 2021-22 imports
    # answer "what kind of product?" as well as fresh listings do
    entries = [entry(added="2021-11-03"), entry(added="2021-11-04",
                                                vendor="Adobe",
                                                product="Acrobat")]
    out = build_kev_guards(entries, GENERATED_AT, min_n=1,
                           min_vendor_entries=1)
    assert out["years"][0] == {"year": 2021, "total": 2, "security": 1,
                               "pct_security": 50.0}


def test_recidivism_board_threshold_dates_and_median_gap():
    entries = [
        entry(cve="A", added="2024-01-01"),
        entry(cve="B", added="2024-01-11"),   # gap 10
        entry(cve="C", added="2024-02-10"),   # gap 30
        entry(cve="D", added="2024-04-10"),   # gap 60 -> median 30
        entry(cve="E", added="2023-05-05", vendor="Adobe", product="Acrobat"),
    ]
    out = build_kev_guards(entries, GENERATED_AT, min_n=1,
                           min_vendor_entries=2)
    assert [v["vendor"] for v in out["vendors"]] == ["Fortinet"]  # Adobe < 2
    row = out["vendors"][0]
    assert row["entries"] == 4 and row["security_entries"] == 4
    assert row["first_added"] == "2024-01-01"
    assert row["last_added"] == "2024-04-10"
    assert row["median_gap_days"] == 30.0


def test_board_sorts_by_entries_then_name_and_null_gap():
    entries = [
        entry(cve="A", added="2024-01-01", vendor="zebra", product="Z"),
        entry(cve="B", added="2024-01-02", vendor="Alpha", product="A"),
        entry(cve="C", added="2024-01-03", vendor="Alpha", product="A"),
    ]
    out = build_kev_guards(entries, GENERATED_AT, min_n=1,
                           min_vendor_entries=1)
    assert [v["vendor"] for v in out["vendors"]] == ["Alpha", "zebra"]
    assert out["vendors"][1]["median_gap_days"] is None  # single entry


def test_vendor_labels_normalized_but_never_merged():
    # "SimpleHelp " (feed whitespace) groups with "SimpleHelp"; Pulse
    # Secure is NOT folded into Ivanti — the catalog's attribution stands
    entries = [
        entry(cve="A", vendor="SimpleHelp ", product="SimpleHelp"),
        entry(cve="B", vendor="SimpleHelp", product="SimpleHelp"),
        entry(cve="C", vendor="Pulse Secure", product="Pulse Connect Secure"),
        entry(cve="D", vendor="Ivanti", product="Pulse Connect Secure"),
    ]
    out = build_kev_guards(entries, GENERATED_AT, min_n=1,
                           min_vendor_entries=1)
    assert [v["vendor"] for v in out["vendors"]] == \
        ["SimpleHelp", "Ivanti", "Pulse Secure"]


def test_ransomware_split_covers_catalog_and_missing_flag_is_not_known():
    entries = [
        entry(cve="A", ransomware="Known"),                       # security
        entry(cve="B", ransomware="Unknown"),                     # security
        entry(cve="C", vendor="Adobe", product="Acrobat",
              ransomware="Known"),                                # other
        entry(cve="D", vendor="Adobe", product="Reader"),         # no flag
    ]
    out = build_kev_guards(entries, GENERATED_AT, min_n=1,
                           min_vendor_entries=1)
    assert out["ransomware"]["security"] == {"total": 2, "known": 1,
                                             "pct_known": 50.0}
    assert out["ransomware"]["other"] == {"total": 2, "known": 1,
                                          "pct_known": 50.0}
    total = (out["ransomware"]["security"]["total"]
             + out["ransomware"]["other"]["total"])
    assert total == out["catalog"]["total"]


def test_undated_entries_count_in_catalog_but_join_no_year():
    entries = [entry(added="not-a-date"), entry(added="2024-01-01")]
    out = build_kev_guards(entries, GENERATED_AT, min_n=1,
                           min_vendor_entries=1)
    assert out["catalog"]["total"] == 2
    assert [(y["year"], y["total"]) for y in out["years"]] == [(2024, 1)]
    # the undated entry still counts on the board, dates from the dated one
    assert out["vendors"][0]["entries"] == 2
    assert out["vendors"][0]["median_gap_days"] is None


def test_catalog_block_carries_classifier_revision():
    out = build_kev_guards([entry()], GENERATED_AT, min_n=1,
                           min_vendor_entries=1)
    assert out["catalog"]["classifier_version"] == CLASSIFIER_VERSION
    assert out["catalog"]["classifier_rules"] == rule_count()
