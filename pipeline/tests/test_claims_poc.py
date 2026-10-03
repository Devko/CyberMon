"""Claims audit for the Time-to-PoC copy (test_claims_breach.py pattern).

Each entry quotes site/js/editorial.js VERBATIM (test_claims_anchors.py
enforces the anchor) and asserts the committed number still sits in a range
where the sentence stays true. Ranges are calibrated from the live fetch of
2026-07-21 (median gap 2025: -12 days; KEV trend preempted 80.7% of 228;
coverage 2025: critical 8.3% vs medium 1.0%; union 29,360 CVEs of 367,886
records) and deliberately tolerant — nightly drift must not trip them, only
a claim becoming untrue should. When one fails, fix the copy AND this test
together, or fix the pipeline; never silence the test.

Skips itself when site/data holds sample data or the file is missing (the
file first appears after the module's first nightly run).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from . import claims_support

DATA_DIR = claims_support.DATA_DIR

_meta_path = DATA_DIR / "meta.json"
if not _meta_path.exists():
    pytest.skip(
        "site/data/meta.json missing — no committed data to audit",
        allow_module_level=True,
    )
_META = json.loads(_meta_path.read_text("utf-8"))
if _META.get("sample") is True:
    pytest.skip(
        "site/data holds sample data — claims audit only judges real data",
        allow_module_level=True,
    )

GENERATION_YEAR = claims_support.GENERATION_YEAR


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return claims_support.read_json(path)


# --------------------------------------------------------------------------
# Claim checks (verbatim copy in the comments — grep it in editorial.js).
# --------------------------------------------------------------------------


def _require_exploit_dated_clock(d: dict) -> None:
    # Editions before 2026-09-21 dated the clock with Metasploit disclosure
    # dates as well; the claims below describe the Exploit-DB-dated clock
    # and have nothing to judge on the older mixed one.
    if "exploit_cves" not in d.get("catalog", {}):
        pytest.skip("edition predates the Exploit-DB-only clock")


def check_median_within_a_month_of_zero_2005_2020(d: dict) -> None:
    _require_exploit_dated_clock(d)
    # editorial.js (exploits.html hero): "From the mid-2000s through 2020
    # the median sat within a month of zero, and in most of those years it
    # was negative". (Exploit-DB-dated clock, 2026-09-21: 2005-2020 medians
    # run -28 to +1 days, 13 of 16 negative or zero.)
    span = [r for r in d["hero"]["years"] if 2005 <= r["year"] <= 2020]
    assert len(span) >= 12, "the 2005-2020 span is not charted"
    worst = max(abs(r["median_days"]) for r in span)
    assert worst <= 31, (
        f"'within a month of zero' needs every 2005-2020 median inside "
        f"+/-31 days; the worst year is {worst} days out"
    )
    negative = sum(1 for r in span if r["median_days"] < 0)
    assert negative > len(span) / 2, (
        f"'in most of those years it was negative' vs {negative} of "
        f"{len(span)} years negative"
    )


# A current-year cohort starts January with a handful of CVEs and is
# right-censored all year (a CVE published in March has had months, not
# years, to attract code), so its median is held to the copy only once the
# cohort is as large as the smallest one the copy describes ("one to three
# hundred CVEs each"). 2026 passed 100 dated CVEs in the autumn (119 on
# 2026-10-03).
CURRENT_COHORT_MIN_N = 100


def _judged_medians(d: dict) -> dict[int, float]:
    return {r["year"]: r["median_days"] for r in d["hero"]["years"]
            if claims_support.judged(r["year"], r["n"],
                                     min_n=CURRENT_COHORT_MIN_N)}


def check_two_weeks_or_more_since_2022(d: dict) -> None:
    _require_exploit_dated_clock(d)
    # editorial.js (exploits.html hero): headline "Since 2022, the median
    # first public exploit has come two weeks or more after the CVE record."
    # and caption "Since 2021 the median has been positive, and since 2022
    # it has been two weeks or more". (2026-10-03: 2021-2026 medians 8, 20,
    # 15.5, 166.5, 38, 41 days; the thin margin is 2023's 15.5 against 14.
    # A late Exploit-DB entry for an old CVE adds a long gap, so a complete
    # year's median mostly moves up.)
    medians = _judged_medians(d)
    recent = {y: m for y, m in medians.items() if y >= 2021}
    assert len([y for y in recent if y < GENERATION_YEAR]) >= 4, (
        f"too few complete years since 2021 to judge: {sorted(recent)}")
    assert all(m > 0 for m in recent.values()), (
        f"'Since 2021 the median has been positive' vs "
        f"{sorted(recent.items())}")
    since_2022 = {y: m for y, m in recent.items() if y >= 2022}
    assert all(m >= 14 for m in since_2022.values()), (
        f"'since 2022 it has been two weeks or more' needs every judged "
        f"median since 2022 at 14 days or more; data says "
        f"{sorted(since_2022.items())}")


def check_only_2024_above_three_months(d: dict) -> None:
    _require_exploit_dated_clock(d)
    # editorial.js (exploits.html hero): "Only the 2024 cohort has a median
    # above three months." (2026-10-03: 2024 at 166.5 days; every other
    # charted year at 41 days or less, the pre-2003 years deeply negative.)
    above = sorted(y for y, m in _judged_medians(d).items() if m > 90)
    assert above == [2024], (
        f"'Only the 2024 cohort has a median above three months' vs the "
        f"years above 90 days: {above}")


def check_early_records_catalogued_an_arsenal(d: dict) -> None:
    # editorial.js (exploits.html hero): "early CVE records were
    # cataloguing an arsenal that already existed". (Live fetch 2026-07:
    # 1999-2002 medians run -800 to -88 days, 96-98% negative.)
    early = [r for r in d["hero"]["years"] if r["year"] <= 2002]
    if not early:
        pytest.skip("no pre-2003 years survive the min-n gate")
    assert all(r["median_days"] < 0 for r in early), (
        f"'cataloguing an arsenal that already existed' needs every "
        f"charted pre-2003 median negative; data says "
        f"{[(r['year'], r['median_days']) for r in early]}"
    )


def check_about_half_kev_preempted(d: dict) -> None:
    _require_exploit_dated_clock(d)
    # editorial.js (exploits.html #2): headline "public code preceded about
    # half of KEV listings with a dated exploit" and caption "about half of
    # the listings with a dated PoC had the code published before the
    # listing day". (2026-09-29: 55.4% of 121; 2026-10-03: 54.5% of 123. The
    # share drifts down as late Exploit-DB entries for listed CVEs count as
    # code after the listing.)
    pct = d["kev_preempt"]["trend"]["pct_preempted"]
    n = d["kev_preempt"]["trend"]["with_poc_date"]
    assert 40 <= pct <= 60, (
        f"'about half of the listings with a dated PoC' claims 40-60%; "
        f"data says {pct}% (over {n} entries)"
    )


def check_quarter_of_catalog_matched(d: dict) -> None:
    # editorial.js (exploits.html #2 methodology): "entries with a dated
    # PoC, roughly a quarter of the catalog". (Live 2026-09-22: 26.2% on the
    # Exploit-DB-only clock; the old mixed clock read 38.8%.)
    kp = d["kev_preempt"]
    with_poc = kp["trend"]["with_poc_date"] + kp["seeding"]["with_poc_date"]
    share = 100.0 * with_poc / kp["total_kev"]
    assert 20 <= share <= 32, (
        f"'roughly a quarter of the catalog' claims ~25%; data says "
        f"{share:.1f}% ({with_poc} of {kp['total_kev']})"
    )


def check_overwhelming_majority_uncovered(d: dict) -> None:
    # editorial.js (exploits.html #3): "the overwhelming majority of
    # records never attract tracked public exploit code at all".
    # (Live 2026-07: 1.9% of the 2025 window covered.)
    cov = d["coverage"]
    rows = cov["buckets"] + [cov["unscored"]]
    total = sum(r["total"] for r in rows)
    covered = sum(r["with_poc"] for r in rows)
    assert total > 0
    share = 100.0 * covered / total
    assert share <= 15, (
        f"'the overwhelming majority of records never attract tracked "
        f"public exploit code' needs window coverage well under half; "
        f"data says {share:.1f}%"
    )


def check_criticals_several_times_middle(d: dict) -> None:
    # editorial.js (exploits.html #3): "criticals draw public exploit
    # attention at more than ten times the rate of the middle of the
    # scale". (Live 2026-07: 8.3% vs 1.0%; 2026-09-23: 5.0% vs 0.3%.)
    rows = {r["bucket"]: r for r in d["coverage"]["buckets"]}
    critical = rows.get("9.0-10.0")
    medium = rows.get("4.0-6.9")
    assert critical and medium, "both buckets must survive the min-n gate"
    assert medium["pct"] > 0, "middle-bucket coverage vanished entirely"
    ratio = critical["pct"] / medium["pct"]
    assert ratio > 10, (
        f"'more than ten times the rate of the middle of the scale' needs "
        f"the critical/medium coverage ratio above 10; data says "
        f"{critical['pct']}% vs {medium['pct']}% (x{ratio:.1f})"
    )


def _coverage_pct(row: dict) -> float:
    # The published pct is rounded to 0.1; the counts are exact.
    return 100.0 * row["with_poc"] / row["total"]


def check_highest_for_critical(d: dict) -> None:
    # editorial.js (exploits.html #3): headline "Public exploit code is most
    # common on CVEs rated critical." and caption "It is highest for
    # critical-rated records". (2026-10-03, 2025 window: critical 5.01%,
    # high 1.15%, medium 0.30%, low 0.25%, unscored 0.03%. The 2026
    # records in the local corpus give 1.22% / 0.25% / 0.07% / 0.12%, so
    # the order holds when the window moves in January.)
    cov = d["coverage"]
    rows = {r["bucket"]: r for r in cov["buckets"]}
    critical = rows.get("9.0-10.0")
    assert critical, "the critical bucket must survive the min-n gate"
    others = {b: _coverage_pct(r) for b, r in rows.items() if b != "9.0-10.0"}
    if cov["unscored"]["total"]:
        others["unscored"] = _coverage_pct(cov["unscored"])
    assert _coverage_pct(critical) > max(others.values()), (
        f"'highest for critical-rated records' vs critical "
        f"{_coverage_pct(critical):.2f}% and {others}")


def check_low_and_medium_below_half_a_percent(d: dict) -> None:
    # editorial.js (exploits.html #3): "below half a percent for low- and
    # medium-rated ones". (2026-10-03, 2025 window: low 4 of 1,603 = 0.25%,
    # medium 72 of 23,720 = 0.30%; the 2026 records in the local corpus
    # give 0.12% and 0.07%.)
    rows = {r["bucket"]: r for r in d["coverage"]["buckets"]}
    for bucket in ("0.0-3.9", "4.0-6.9"):
        assert bucket in rows, f"{bucket} must survive the min-n gate"
        pct = _coverage_pct(rows[bucket])
        assert pct < 0.5, (
            f"'below half a percent for low- and medium-rated ones' vs "
            f"{bucket} at {pct:.2f}%")


def check_few_percent_ever_get_a_poc(d: dict) -> None:
    # editorial.js (exploits.html hero methodology): "only a few percent of
    # records ever get a tracked public exploit". Exploit code only — the
    # union adds Nuclei detection checks, which the page says are not
    # exploits. (2026-09-23: 25,978 of 396,407 = 6.6%.)
    cve_count = _META["sources"]["cvelist"]["cve_count"]
    share = 100.0 * d["catalog"]["exploit_cves"] / cve_count
    assert 0.5 <= share <= 12, (
        f"'only a few percent of records ever get a tracked public "
        f"exploit' claims single digits; data says {share:.1f}% "
        f"({d['catalog']['exploit_cves']} of {cve_count})"
    )


def check_newest_cohorts_are_a_few_hundred(d: dict) -> None:
    _require_exploit_dated_clock(d)
    # editorial.js (exploits.html hero): "Read those newest years with
    # care: one to three hundred CVEs each". (2026-09-21: 2021-2025
    # cohorts run 154-270 CVEs against 2,000+ in the late 2000s.)
    recent = [r for r in d["hero"]["years"]
              if 2021 <= r["year"] < GENERATION_YEAR]
    assert recent, "no complete years since 2021"
    assert all(100 <= r["n"] < 350 for r in recent), (
        f"'one to three hundred CVEs each' vs "
        f"{[(r['year'], r['n']) for r in recent]}"
    )


def check_channel_thinned(d: dict) -> None:
    # editorial.js (exploits.html methodology and ai.html banked
    # methodology): "the dated cohort per year is now well under a fifth of
    # its late-2000s size" — 2,640 (2009) vs 262 (2024).
    by_year = {r["year"]: r["n"] for r in d["hero"]["years"]}
    peak = max(n for y, n in by_year.items() if 2005 <= y <= 2012)
    latest = max(y for y in by_year if y < GENERATION_YEAR)
    assert by_year[latest] <= 0.2 * peak, (
        f"'well under a fifth of its late-2000s size' vs {by_year[latest]} "
        f"in {latest} against a 2005-12 peak of {peak}"
    )


CLAIMS = [
    (
        "one to three hundred CVEs each",
        "time_to_poc.json",
        check_newest_cohorts_are_a_few_hundred,
    ),
    (
        "Since 2022, the median first public exploit has come two weeks or "
        "more after the CVE record.",
        "time_to_poc.json",
        check_two_weeks_or_more_since_2022,
    ),
    (
        "Since 2021 the median has been positive, and since 2022 it has been "
        "two weeks or more",
        "time_to_poc.json",
        check_two_weeks_or_more_since_2022,
    ),
    (
        "Only the 2024 cohort has a median above three months.",
        "time_to_poc.json",
        check_only_2024_above_three_months,
    ),
    (
        "the dated cohort per year is now well under a fifth of its late-2000s size",
        "time_to_poc.json",
        check_channel_thinned,
    ),
    (
        "From the mid-2000s through 2020 the median sat within a month of zero",
        "time_to_poc.json",
        check_median_within_a_month_of_zero_2005_2020,
    ),
    (
        "early CVE records catalogued exploits that already existed",
        "time_to_poc.json",
        check_early_records_catalogued_an_arsenal,
    ),
    (
        "Since 2023, public code preceded about half of KEV listings with a "
        "dated exploit.",
        "time_to_poc.json",
        check_about_half_kev_preempted,
    ),
    (
        "about half of the listings with a dated PoC had the code published before the listing day",
        "time_to_poc.json",
        check_about_half_kev_preempted,
    ),
    (
        "roughly a quarter of the catalog",
        "time_to_poc.json",
        check_quarter_of_catalog_matched,
    ),
    (
        "the overwhelming majority of records have no tracked public exploit code",
        "time_to_poc.json",
        check_overwhelming_majority_uncovered,
    ),
    (
        "at more than ten times the rate of medium-rated records",
        "time_to_poc.json",
        check_criticals_several_times_middle,
    ),
    (
        "Public exploit code is most common on CVEs rated critical.",
        "time_to_poc.json",
        check_highest_for_critical,
    ),
    (
        "It is highest for critical-rated records",
        "time_to_poc.json",
        check_highest_for_critical,
    ),
    (
        "below half a percent for low- and medium-rated ones",
        "time_to_poc.json",
        check_low_and_medium_below_half_a_percent,
    ),
    (
        "only a few percent of records ever get a tracked public exploit",
        "time_to_poc.json",
        check_few_percent_ever_get_a_poc,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
