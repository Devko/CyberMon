"""Unit tests for the Time-to-PoC metrics (pipeline/poc_metrics.py)."""
from __future__ import annotations

import pytest

from pipeline import poc_metrics
from pipeline.fetch_kev import KevEntry
from pipeline.fetch_poc import PocData
from pipeline.metrics import Aggregator, CveFacts

GENERATED_AT = "2026-07-09T00:00:00Z"


def _facts(cve_id: str, date_published: str | None, year: int,
           score: float | None = None, state: str = "PUBLISHED") -> CveFacts:
    return CveFacts(cve_id=cve_id, state=state, year=year, cna="fixture",
                    cna_scores={} if score is None else {"v3": score},
                    date_published=date_published)


def _poc(edb_dates=None, msf_dates=None, nuclei=(), **counts) -> PocData:
    edb_dates = edb_dates or {}
    msf_dates = msf_dates or {}
    defaults = dict(edb_entries=len(edb_dates),
                    edb_entries_with_cve=len(edb_dates),
                    msf_modules=len(msf_dates),
                    msf_modules_with_cve=len(msf_dates),
                    nuclei_templates=len(nuclei))
    defaults.update(counts)
    return PocData(edb_dates=edb_dates, msf_dates=msf_dates,
                   edb_ids=frozenset(edb_dates),
                   msf_ids=frozenset(msf_dates),
                   nuclei_ids=frozenset(nuclei), **defaults)


def _build(facts_list, poc, kev_entries=(), min_n=1, arming_min_n=None,
           generated_at=GENERATED_AT):
    agg = Aggregator(kev_ids=[e.cve_id for e in kev_entries],
                     poc_ids=poc.all_ids)
    for facts in facts_list:
        agg.add(facts)
    return poc_metrics.build_time_to_poc(agg, poc, kev_entries,
                                         generated_at, min_n=min_n,
                                         arming_min_n=arming_min_n)


def test_negative_gaps_are_kept_never_floored():
    # PoC published 40 days BEFORE the CVE record: the gap must stay -40.
    poc = _poc(edb_dates={"CVE-2020-0001": "2020-01-01"})
    out = _build([_facts("CVE-2020-0001", "2020-02-10", 2020)], poc)
    row = out["hero"]["years"][0]
    assert row["median_days"] == -40.0
    assert row["pct_negative"] == 100.0
    assert row["pct_within_week"] == 100.0  # negative is trivially within


def test_first_poc_is_min_over_dated_sources():
    poc = _poc(edb_dates={"CVE-2020-0001": "2020-03-01"},
               msf_dates={"CVE-2020-0001": "2020-02-01"})
    out = _build([_facts("CVE-2020-0001", "2020-01-01", 2020)], poc)
    assert out["hero"]["years"][0]["median_days"] == 31.0  # vs MSF date


def test_min_n_gates_hero_years():
    poc = _poc(edb_dates={"CVE-2020-0001": "2020-01-05",
                          "CVE-2021-0001": "2021-01-05",
                          "CVE-2021-0002": "2021-01-06"})
    facts = [_facts("CVE-2020-0001", "2020-01-01", 2020),
             _facts("CVE-2021-0001", "2021-01-01", 2021),
             _facts("CVE-2021-0002", "2021-01-01", 2021)]
    out = _build(facts, poc, min_n=2)
    assert [r["year"] for r in out["hero"]["years"]] == [2021]


def test_undated_and_uncorpused_cves_count_as_unmatched():
    poc = _poc(edb_dates={"CVE-2020-0001": "2020-01-05",
                          "CVE-2099-0001": "2099-01-01"})
    out = _build([_facts("CVE-2020-0001", "2020-01-01", 2020)], poc)
    assert out["hero"]["matched"] == {"dated_cves": 2, "matched_cves": 1,
                                     "unmatched_cves": 1}


def test_rejected_record_still_joins_like_the_kev_precedent():
    # A PoC against a later-REJECTED record is real; the join keeps it.
    poc = _poc(edb_dates={"CVE-2020-0001": "2020-01-11"})
    out = _build([_facts("CVE-2020-0001", "2020-01-01", 2020,
                         state="REJECTED")], poc)
    assert out["hero"]["matched"]["matched_cves"] == 1
    assert out["hero"]["years"][0]["median_days"] == 10.0


def test_headline_skips_partial_current_year():
    poc = _poc(edb_dates={"CVE-2025-0001": "2025-01-11",
                          "CVE-2026-0001": "2026-01-02"})
    facts = [_facts("CVE-2025-0001", "2025-01-01", 2025),
             _facts("CVE-2026-0001", "2026-01-01", 2026)]
    out = _build(facts, poc)
    assert [r["year"] for r in out["hero"]["years"]] == [2025, 2026]
    assert out["hero"]["headline"]["latest_year"] == 2025


def test_kev_preempt_splits_seeding_from_trend():
    poc = _poc(edb_dates={"CVE-2019-0001": "2020-01-01",   # old, preempted
                          "CVE-2023-0001": "2023-06-01",   # after listing
                          "CVE-2023-0002": "2023-01-01"})  # before listing
    entries = [
        KevEntry("CVE-2019-0001", "2021-11-03", None),  # seeding era
        KevEntry("CVE-2023-0001", "2023-05-01", None),  # trend, not preempted
        KevEntry("CVE-2023-0002", "2023-02-01", None),  # trend, preempted
        KevEntry("CVE-2023-0003", "2023-03-01", None),  # no PoC at all
        KevEntry("CVE-2023-0004", "", None),            # unparseable date
    ]
    out = _build([], _poc(edb_dates=dict(poc.edb_dates)), entries)
    kp = out["kev_preempt"]
    assert kp["total_kev"] == 5
    assert kp["seeding"] == {"with_poc_date": 1, "preempted": 1,
                             "pct_preempted": 100.0}
    assert kp["trend"] == {"with_poc_date": 2, "preempted": 1,
                           "pct_preempted": 50.0}
    years = {r["year"]: r for r in kp["years"]}
    assert years[2023]["total_added"] == 3
    assert years[2023]["with_poc_date"] == 2
    # 2023-03-01 entry has no PoC date: counted in total, not in the share
    assert years[2023]["preempted"] == 1


def test_kev_preempt_same_day_listing_is_not_preempted():
    # "predates" is strict: a PoC dated the listing day did not beat it.
    poc = _poc(edb_dates={"CVE-2023-0001": "2023-05-01"})
    entries = [KevEntry("CVE-2023-0001", "2023-05-01", None)]
    out = _build([], poc, entries)
    assert out["kev_preempt"]["trend"]["preempted"] == 0


def test_coverage_uses_latest_complete_year_and_flood_buckets():
    poc = _poc(edb_dates={"CVE-2025-0001": "2025-02-01"},
               nuclei={"CVE-2025-0002"})
    facts = [
        _facts("CVE-2025-0001", "2025-01-01", 2025, score=9.8),
        _facts("CVE-2025-0002", "2025-01-01", 2025, score=9.1),
        _facts("CVE-2025-0003", "2025-01-01", 2025, score=9.0),  # uncovered
        _facts("CVE-2025-0004", "2025-01-01", 2025, score=5.0),  # uncovered
        _facts("CVE-2025-0005", "2025-01-01", 2025),             # unscored
        _facts("CVE-2026-0001", "2026-01-01", 2026, score=9.9),  # partial yr
    ]
    out = _build(facts, poc)
    cov = out["coverage"]
    assert cov["window_year"] == 2025
    rows = {r["bucket"]: r for r in cov["buckets"]}
    assert rows["9.0-10.0"] == {"bucket": "9.0-10.0", "total": 3,
                                "with_poc": 2, "pct": 66.7}
    assert rows["4.0-6.9"]["with_poc"] == 0
    assert cov["unscored"] == {"total": 1, "with_poc": 0, "pct": 0.0}


def test_coverage_min_n_drops_thin_buckets():
    poc = _poc(edb_dates={"CVE-2025-0001": "2025-02-01"})
    facts = [_facts("CVE-2025-0001", "2025-01-01", 2025, score=9.8),
             _facts("CVE-2025-0004", "2025-01-01", 2025, score=5.0)]
    out = _build(facts, poc, min_n=2)
    assert out["coverage"]["buckets"] == []  # both buckets under min_n


def test_catalog_carries_the_join_audit():
    poc = _poc(edb_dates={"CVE-2020-0001": "2020-01-05"},
               msf_dates={"CVE-2020-0002": "2020-01-06"},
               nuclei={"CVE-2020-0003"})
    out = _build([_facts("CVE-2020-0001", "2020-01-01", 2020)], poc)
    cat = out["catalog"]
    assert cat["union_cves"] == 3
    assert cat["dated_cves"] == 2
    assert cat["matched_in_corpus"] == 1
    assert cat["dated_cves"] == out["hero"]["matched"]["dated_cves"]


def test_output_validates_against_contract(agg, poc, kev):
    from pipeline import contracts

    obj = poc_metrics.build_time_to_poc(agg, poc, kev.entries,
                                        GENERATED_AT, min_n=1)
    contracts.validate("time_to_poc.json", obj)  # must not raise


@pytest.mark.parametrize("mutate,fragment", [
    (lambda o: o["hero"]["matched"].update(matched_cves=999),
     "must equal"),
    (lambda o: o["kev_preempt"]["trend"].update(preempted=10 ** 6),
     "exceeds with_poc_date"),
    (lambda o: o["coverage"]["buckets"].__setitem__(
        0, {"bucket": "bogus", "total": 1, "with_poc": 0, "pct": 0.0}),
     "unknown bucket"),
    (lambda o: o["coverage"]["unscored"].update(with_poc=10 ** 6),
     "exceeds total"),
    (lambda o: o["catalog"].update(dated_cves=10 ** 6),
     "cannot exceed union_cves"),
])
def test_contract_rejects_broken_arithmetic(agg, poc, kev, mutate, fragment):
    from pipeline import contracts

    obj = poc_metrics.build_time_to_poc(agg, poc, kev.entries,
                                        GENERATED_AT, min_n=1)
    mutate(obj)
    with pytest.raises(contracts.ContractViolation, match=fragment):
        contracts.validate("time_to_poc.json", obj)


# ---- arming: the like-for-like clock (the AI Alibi's primary metric) ----

def _arming_case(*pairs, generated_at=GENERATED_AT, **kw):
    """(published, poc_date) pairs -> the built arming section."""
    facts, dates = [], {}
    for i, (published, poc_date) in enumerate(pairs):
        cve = f"CVE-{published[:4]}-{1000 + i}"
        facts.append(_facts(cve, published, int(published[:4])))
        dates[cve] = poc_date
    return _build(facts, _poc(edb_dates=dates), generated_at=generated_at,
                  **kw)["arming"]


def test_arming_threshold_is_explicit_named_and_emitted():
    poc = _poc(edb_dates={"CVE-2020-0001": "2020-01-05"})
    facts = [_facts("CVE-2020-0001", "2020-01-01", 2020)]
    # A production floor never leaks into the arming threshold: 15 is
    # neither 15 nor "silently 30 because it is >= 10" -- it is the
    # named constant unless the caller says otherwise.
    assert _build(facts, poc, min_n=15)["arming"]["min_n"] == \
        poc_metrics.ARMING_MIN_N == 30
    assert _build(facts, poc, min_n=10)["arming"]["min_n"] == 30
    # The fixture floor is inherited so the offline corpus still charts.
    assert _build(facts, poc, min_n=1)["arming"]["min_n"] == 1
    # Explicit always wins, and gates the rows.
    out = _build(facts, poc, min_n=1, arming_min_n=2)
    assert out["arming"]["min_n"] == 2
    assert out["arming"]["years"] == []
    with pytest.raises(ValueError):
        _build(facts, poc, arming_min_n=0)


def test_arming_window_is_symmetric_and_bounded():
    # Cohort 2020, observed long ago. Gaps: -4452 (an old exploit finally
    # getting an id), +91 (one day past the horizon), -90, +90, +5.
    arming = _arming_case(("2020-01-01", "2007-10-24"),   # -4452: out
                          ("2020-01-01", "2020-04-01"),   # +91: out
                          ("2020-01-01", "2019-10-03"),   # -90: in
                          ("2020-01-01", "2020-03-31"),   # +90: in
                          ("2020-01-01", "2020-01-06"))   # +5: in
    assert arming["horizon_days"] == 90
    assert arming["years"] == [{
        "year": 2020, "n": 3, "median_days": 5.0,
        "pct_within_week": 66.7,   # -90 and +5
        "pct_negative": 33.3,      # -90
        "provisional": False}]


def test_arming_observed_through_cuts_cohorts_without_a_full_window():
    # generated_at 2026-07-09 minus 90 days = 2026-04-10: a record
    # published that day has had the whole window; one published the day
    # after has not, however fast its PoC was.
    arming = _arming_case(("2026-04-10", "2026-04-11"),
                          ("2026-04-11", "2026-04-12"))
    assert arming["observed_through"] == "2026-04-10"
    assert [(r["year"], r["n"]) for r in arming["years"]] == [(2026, 1)]


def test_arming_settled_on_date_math_drives_provisional():
    # Cohort 2024 settles on 2024-12-31 + 90 + 365 days = 2026-03-31.
    settled = ("2024-06-01", "2024-06-02")
    assert _arming_case(settled, generated_at="2026-03-30T23:59:59Z"
                        )["years"][0]["provisional"] is True
    assert _arming_case(settled, generated_at="2026-03-31T00:00:00Z"
                        )["years"][0]["provisional"] is False
    # And at the test clock: 2024 settled, 2025 not (settles 2027-03-31).
    arming = _arming_case(("2024-06-01", "2024-06-02"),
                          ("2025-06-01", "2025-06-02"))
    assert [(r["year"], r["provisional"]) for r in arming["years"]] == \
        [(2024, False), (2025, True)]


def _two_cohorts():
    return _build([_facts("CVE-2024-0001", "2024-06-01", 2024),
                   _facts("CVE-2025-0001", "2025-06-01", 2025)],
                  _poc(edb_dates={"CVE-2024-0001": "2024-06-02",
                                  "CVE-2025-0001": "2025-06-02"}))


def test_built_arming_validates():
    from pipeline import contracts

    contracts.validate("time_to_poc.json", _two_cohorts())


@pytest.mark.parametrize("mutate,fragment", [
    (lambda a: a["years"][0].update(provisional=True), "disagrees"),
    (lambda a: a["years"][1].update(provisional=False), "disagrees"),
    (lambda a: a.update(observed_through="2026/04/10"), "required format"),
    (lambda a: a.update(ingestion_allowance_days=-1), "below minimum"),
    (lambda a: a.update(ingestion_allowance_days=1.5), "expected integer"),
    (lambda a: a.update(min_n=0), "below minimum"),
    (lambda a: a.update(min_n=2), "below arming.min_n"),
])
def test_contract_rederives_and_bounds_the_arming_section(mutate, fragment):
    from pipeline import contracts

    obj = _two_cohorts()
    mutate(obj["arming"])
    with pytest.raises(contracts.ContractViolation, match=fragment):
        contracts.validate("time_to_poc.json", obj)


def test_contract_tolerates_editions_without_arming_min_n():
    from pipeline import contracts

    obj = _two_cohorts()
    del obj["arming"]["min_n"]  # an edition published before the field
    contracts.validate("time_to_poc.json", obj)
