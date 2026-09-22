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
import os
from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parents[2] / "site" / "data"

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

GENERATION_YEAR = int(os.environ.get("CYBERMON_REHEARSE_YEAR")
                      or _META["generated_at"][:4])  # see test_claims_audit


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return json.loads(path.read_text("utf-8"))


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


def check_median_moved_to_weeks_after_since_2021(d: dict) -> None:
    _require_exploit_dated_clock(d)
    # editorial.js (exploits.html hero): "Since 2021 the median has moved
    # the other way, to weeks after publication" and "the 2024 cohort, at
    # months rather than weeks, is the outlier". (2026-09-21: 2021-2025
    # medians 8, 20, 15.5, 166.5, 38 days.)
    recent = {r["year"]: r for r in d["hero"]["years"]
              if 2021 <= r["year"] < GENERATION_YEAR}
    assert len(recent) >= 3, "too few complete years since 2021 to judge"
    assert all(r["median_days"] >= 7 for r in recent.values()), (
        f"'to weeks after publication' needs every complete-year median "
        f"since 2021 at a week or more; data says "
        f"{[(y, r['median_days']) for y, r in sorted(recent.items())]}"
    )
    assert 2024 in recent and recent[2024]["median_days"] >= 60, (
        f"'the 2024 cohort, at months rather than weeks' vs "
        f"{recent.get(2024, {}).get('median_days')} days"
    )
    others = [r["median_days"] for y, r in recent.items() if y != 2024]
    assert max(others) < 90, (
        f"'is the outlier' needs every other recent median under three "
        f"months; data says {others}"
    )


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


def check_just_over_half_kev_preempted(d: dict) -> None:
    _require_exploit_dated_clock(d)
    # editorial.js (exploits.html #2): "just over half of the listings with
    # a dated PoC were beaten to the announcement". (Exploit-DB-dated clock,
    # 2026-09-21: 55.4% over 121 entries; the old mixed clock read 80.7%.)
    pct = d["kev_preempt"]["trend"]["pct_preempted"]
    n = d["kev_preempt"]["trend"]["with_poc_date"]
    assert 50 <= pct <= 66, (
        f"'just over half of the listings with a dated PoC were beaten to "
        f"the announcement' claims 50-65%; data says {pct}% (over {n} entries)"
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
    # attention at several times the rate of the middle of the scale".
    # (Live 2026-07: 8.3% vs 1.0%.)
    rows = {r["bucket"]: r for r in d["coverage"]["buckets"]}
    critical = rows.get("9.0-10.0")
    medium = rows.get("4.0-6.9")
    assert critical and medium, "both buckets must survive the min-n gate"
    assert medium["pct"] > 0, "middle-bucket coverage vanished entirely"
    ratio = critical["pct"] / medium["pct"]
    assert ratio >= 2.5, (
        f"'several times the rate of the middle of the scale' needs the "
        f"critical/medium coverage ratio comfortably above 2; data says "
        f"{critical['pct']}% vs {medium['pct']}% (x{ratio:.1f})"
    )


def check_few_percent_ever_get_a_poc(d: dict) -> None:
    # editorial.js (exploits.html hero methodology): "only a few percent of
    # records ever get a tracked public exploit". (Live 2026-07: 29,360
    # union CVEs against 367,886 corpus records = 8.0%.)
    cve_count = _META["sources"]["cvelist"]["cve_count"]
    share = 100.0 * d["catalog"]["union_cves"] / cve_count
    assert 0.5 <= share <= 12, (
        f"'only a few percent of records ever get a tracked public "
        f"exploit' claims single digits; data says {share:.1f}% "
        f"({d['catalog']['union_cves']} of {cve_count})"
    )


def check_newest_cohorts_are_a_few_hundred(d: dict) -> None:
    _require_exploit_dated_clock(d)
    # editorial.js (exploits.html hero): "Read those newest years with
    # care: a few hundred CVEs each". (2026-09-21: 2021-2025 cohorts run
    # 154-270 CVEs against 2,000+ in the late 2000s.)
    recent = [r for r in d["hero"]["years"]
              if 2021 <= r["year"] < GENERATION_YEAR]
    assert recent, "no complete years since 2021"
    assert all(50 <= r["n"] < 1000 for r in recent), (
        f"'a few hundred CVEs each' vs "
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
        "Read those newest years with care: a few hundred CVEs each",
        "time_to_poc.json",
        check_newest_cohorts_are_a_few_hundred,
    ),
    (
        "Since 2021 the median has moved the other way, to weeks after publication",
        "time_to_poc.json",
        check_median_moved_to_weeks_after_since_2021,
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
        "early CVE records were cataloguing an arsenal that already existed",
        "time_to_poc.json",
        check_early_records_catalogued_an_arsenal,
    ),
    (
        "just over half of the listings with a dated PoC were beaten to the announcement",
        "time_to_poc.json",
        check_just_over_half_kev_preempted,
    ),
    (
        "roughly a quarter of the catalog",
        "time_to_poc.json",
        check_quarter_of_catalog_matched,
    ),
    (
        "the overwhelming majority of records never attract tracked public exploit code at all",
        "time_to_poc.json",
        check_overwhelming_majority_uncovered,
    ),
    (
        "criticals draw public exploit attention at several times the rate of the middle of the scale",
        "time_to_poc.json",
        check_criticals_several_times_middle,
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
