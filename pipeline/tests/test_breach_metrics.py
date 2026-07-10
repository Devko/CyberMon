"""Breach ledger math: cohort rule, import era, negative lag, volume,
class shares, headline, pace projection."""
from __future__ import annotations

from pipeline.breach_metrics import (EXCLUSION_REASONS, IMPORT_CUTOFF,
                                     build_breach_ledger, split_cohort)
from pipeline.fetch_hibp import HibpBreach

from .conftest import GENERATED_AT


def _breach(name: str, breach_date: str = "2024-01-01",
            added_date: str = "2024-02-01T00:00:00Z", pwn_count: int = 100,
            data_classes: list[str] | None = None, **flags) -> HibpBreach:
    return HibpBreach(name=name, breach_date=breach_date,
                      added_date=added_date, pwn_count=pwn_count,
                      data_classes=data_classes or ["Email addresses"],
                      **flags)


# ------------------------------------------------------------- cohort rule

def test_exclusion_reasons_and_precedence():
    breaches = [
        _breach("keep"),
        _breach("fab", is_fabricated=True),
        _breach("spam", is_spam_list=True),
        _breach("mal", is_malware=True),
        _breach("steal", is_stealer_log=True),
        # Both flags set: counted once, under the higher-precedence reason.
        _breach("spam+mal", is_spam_list=True, is_malware=True),
        _breach("fab+steal", is_fabricated=True, is_stealer_log=True),
    ]
    cohort, excluded = split_cohort(breaches)
    assert [b.name for b in cohort] == ["keep"]
    assert excluded == {"fabricated": 2, "spam_list": 2, "malware": 1,
                        "stealer_log": 1}
    assert list(excluded) == EXCLUSION_REASONS


def test_catalog_block_always_sums_to_total():
    breaches = [_breach("a"), _breach("b", is_spam_list=True),
                _breach("c", is_malware=True, is_stealer_log=True)]
    obj = build_breach_ledger(breaches, GENERATED_AT, min_n=1)
    cat = obj["catalog"]
    assert cat["total"] == 3
    assert cat["cohort"] + sum(cat["excluded"].values()) == cat["total"]
    assert cat["excluded"]["malware"] == 1  # precedence over stealer_log


def test_excluded_entries_join_no_chart():
    breaches = [_breach("keep", pwn_count=10),
                _breach("spam", pwn_count=999999, is_spam_list=True,
                        data_classes=["Email addresses", "Phone numbers"])]
    obj = build_breach_ledger(breaches, GENERATED_AT, min_n=1)
    assert obj["volume_by_year"] == [{"year": 2024, "breaches": 1,
                                      "records": 10}]
    assert obj["class_shares"]["classes"] == ["Email addresses"]


# ------------------------------------------------------------- import era

def test_import_cutoff_boundary_day_is_trend_not_import():
    breaches = [_breach("import", "2012-07-01", "2013-12-31T00:00:00Z"),
                _breach("trend", "2013-06-01", "2014-01-01T00:00:00Z")]
    obj = build_breach_ledger(breaches, GENERATED_AT, min_n=1)
    assert obj["import_era"]["n"] == 1
    assert obj["import_era"]["added_before"] == IMPORT_CUTOFF
    assert [r["year"] for r in obj["lag_by_year"]] == [2014]
    # ... but the import year still charts in volume and class shares.
    assert [r["year"] for r in obj["volume_by_year"]] == [2013, 2014]


def test_empty_import_era_median_is_null_never_zero():
    obj = build_breach_ledger([_breach("only")], GENERATED_AT, min_n=1)
    assert obj["import_era"] == {"added_before": IMPORT_CUTOFF, "n": 0,
                                 "median_days": None}


# ------------------------------------------------------- lag stats & dates

def test_negative_lag_kept_not_floored():
    breaches = [_breach("timetravel", "2025-03-01", "2025-02-01T00:00:00Z")]
    obj = build_breach_ledger(breaches, GENERATED_AT, min_n=1)
    row = obj["lag_by_year"][0]
    assert row["median_days"] == -28.0  # never floored to 0
    assert row["pct_negative"] == 100.0


def test_lag_quartiles_and_over_a_year_share():
    breaches = [_breach(f"b{i}", "2024-01-01",
                        added_date=f"2024-01-{1 + d:02d}T00:00:00Z")
                for i, d in enumerate((10, 20, 30))]
    breaches.append(_breach("late", "2023-01-01", "2024-01-11T00:00:00Z"))
    obj = build_breach_ledger(breaches, GENERATED_AT, min_n=1)
    row = obj["lag_by_year"][0]
    assert row["n"] == 4
    # lags 10, 20, 30, 375: inclusive quartiles (p75 = 116.25 -> 116.2)
    assert (row["p25_days"], row["median_days"], row["p75_days"]) == \
        (17.5, 25.0, 116.2)
    assert row["pct_over_365d"] == 25.0


def test_undated_entries_count_in_catalog_only():
    breaches = [_breach("dated"),
                _breach("no-added", added_date=""),
                _breach("no-breach-date", breach_date="")]
    obj = build_breach_ledger(breaches, GENERATED_AT, min_n=1)
    assert obj["catalog"]["cohort"] == 3
    # no AddedDate: joins no chart at all
    assert obj["volume_by_year"][0]["breaches"] == 2
    # no BreachDate: charts in volume/classes, but has no lag
    assert obj["lag_by_year"][0]["n"] == 1


def test_min_n_drops_thin_years_from_lag_and_classes_not_volume():
    breaches = [_breach(f"b{i}", added_date="2024-02-01T00:00:00Z")
                for i in range(3)]
    breaches.append(_breach("lone", added_date="2025-02-01T00:00:00Z"))
    obj = build_breach_ledger(breaches, GENERATED_AT, min_n=3)
    assert [r["year"] for r in obj["lag_by_year"]] == [2024]
    assert [r["year"] for r in obj["class_shares"]["years"]] == [2024]
    assert [r["year"] for r in obj["volume_by_year"]] == [2024, 2025]


# ------------------------------------------------------------ volume chart

def test_volume_sums_records_per_catalog_year():
    breaches = [_breach("a", pwn_count=1000),
                _breach("b", pwn_count=234,
                        added_date="2024-11-01T00:00:00Z"),
                _breach("c", pwn_count=5, added_date="2025-01-01T00:00:00Z")]
    obj = build_breach_ledger(breaches, GENERATED_AT, min_n=1)
    assert obj["volume_by_year"] == [
        {"year": 2024, "breaches": 2, "records": 1234},
        {"year": 2025, "breaches": 1, "records": 5}]


# ------------------------------------------------------------ class shares

def test_top_classes_ranked_by_frequency_ties_alphabetical():
    breaches = [
        _breach("a", data_classes=["Email addresses", "Passwords"]),
        _breach("b", data_classes=["Email addresses", "Zeta", "Alpha"]),
        _breach("c", data_classes=["Email addresses", "Passwords", "Alpha",
                                   "Beta", "Gamma", "Delta", "Epsilon"]),
    ]
    obj = build_breach_ledger(breaches, GENERATED_AT, min_n=1)
    # Email 3, Passwords 2, Alpha 2, then alphabetical among count-1 —
    # capped at six classes even though eight appear.
    assert obj["class_shares"]["classes"] == \
        ["Email addresses", "Alpha", "Passwords", "Beta", "Delta", "Epsilon"]


def test_class_counted_once_per_breach_and_share_is_of_year_cohort():
    breaches = [
        _breach("dup", data_classes=["Email addresses", "Email addresses"]),
        _breach("other", data_classes=["Passwords"]),
    ]
    obj = build_breach_ledger(breaches, GENERATED_AT, min_n=1)
    year = obj["class_shares"]["years"][0]
    assert year["n"] == 2
    assert year["shares"]["Email addresses"] == 50.0
    assert year["shares"]["Passwords"] == 50.0


# ---------------------------------------------------------------- headline

def test_headline_pools_trend_and_prefers_last_complete_year(hibp):
    obj = build_breach_ledger(hibp.breaches, GENERATED_AT, min_n=1)
    # fixture trend lags: 60, 366 (2024), -28, 12 (2025) -> median 36.0
    assert obj["headline"] == {"trend_n": 4, "median_days": 36.0,
                               "pct_over_365d": 25.0,
                               "latest_year": 2025,
                               "median_days_latest": -8.0}


def test_headline_falls_back_to_partial_current_year():
    breaches = [_breach("now", "2026-05-01", "2026-06-01T00:00:00Z")]
    obj = build_breach_ledger(breaches, GENERATED_AT, min_n=1)
    assert obj["headline"]["latest_year"] == 2026
    assert obj["headline"]["median_days_latest"] == 31.0


def test_headline_empty_catalog():
    obj = build_breach_ledger([], GENERATED_AT)
    assert obj["headline"] == {"trend_n": 0, "median_days": 0.0,
                               "pct_over_365d": 0.0, "latest_year": 0,
                               "median_days_latest": 0.0}
    assert obj["catalog"] == {"total": 0, "cohort": 0,
                              "excluded": {r: 0 for r in EXCLUSION_REASONS}}


# ---------------------------------------------------------- pace projection

def test_projection_paces_current_year_breach_flow():
    breaches = [_breach(f"b{i}", "2026-01-01", "2026-03-01T00:00:00Z")
                for i in range(3)]
    obj = build_breach_ledger(breaches, "2026-07-02T00:00:00Z", min_n=1)
    # day 183 of 365 -> elapsed 0.501...; 3 / 0.5014 -> 6
    assert obj["projection"] == {"year": 2026, "breaches": 6,
                                 "elapsed": 0.501}


def test_projection_absent_early_in_year_and_without_current_entries():
    breaches = [_breach("early", "2026-01-01", "2026-01-05T00:00:00Z")]
    obj = build_breach_ledger(breaches, "2026-01-15T00:00:00Z", min_n=1)
    assert "projection" not in obj  # elapsed < 0.125
    obj = build_breach_ledger([_breach("old")], "2026-07-02T00:00:00Z",
                              min_n=1)
    assert "projection" not in obj  # no current-year additions


# ------------------------------------------------------- fixture-based build

def test_fixture_build_full_shape(hibp):
    obj = build_breach_ledger(hibp.breaches, GENERATED_AT, min_n=1)
    assert obj["catalog"] == {
        "total": 9, "cohort": 5,
        "excluded": {"fabricated": 1, "spam_list": 1, "malware": 1,
                     "stealer_log": 1}}
    assert obj["import_era"] == {"added_before": IMPORT_CUTOFF, "n": 1,
                                 "median_days": 522.0}
    assert [(r["year"], r["n"], r["median_days"], r["pct_over_365d"],
             r["pct_negative"]) for r in obj["lag_by_year"]] == \
        [(2024, 2, 213.0, 50.0, 0.0), (2025, 2, -8.0, 0.0, 50.0)]
    assert obj["volume_by_year"] == [
        {"year": 2013, "breaches": 1, "records": 1000000},
        {"year": 2024, "breaches": 2, "records": 5250000},
        {"year": 2025, "breaches": 2, "records": 942000}]
    assert obj["class_shares"]["classes"] == \
        ["Email addresses", "Passwords", "IP addresses", "Names",
         "Phone numbers", "Usernames"]
    shares_2025 = next(y for y in obj["class_shares"]["years"]
                       if y["year"] == 2025)["shares"]
    assert shares_2025 == {"Email addresses": 100.0, "Passwords": 50.0,
                           "IP addresses": 50.0, "Names": 0.0,
                           "Phone numbers": 50.0, "Usernames": 0.0}
    assert "projection" not in obj  # fixtures carry no current-year entries
