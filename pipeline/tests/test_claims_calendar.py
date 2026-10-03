"""Claims audit for the CVE Calendar copy (test_claims_audit.py pattern).

Each entry quotes site/js/editorial.js verbatim and asserts the number in
site/data/cve_calendar.json still sits in a range where the sentence stays
true. Ranges are deliberately tolerant — nightly drift must not trip them;
only a claim becoming untrue should. Never silence a failure here: fix the
copy (and this test's quoted claim + range, in the same commit) or fix the
pipeline. Reference values from the real corpus, 2026-07-10 (release
cve_2026-07-10_0700Z, 364,398 records): 2025 prior-year-ID share 20.4%
(11.4% one-year + 9.0% two-plus); 2025 Tuesday share 24.5% (the week's
top day; weekend 7.5% combined); 2025 patch-Tuesday share 9.8% of volume
on 3.3% of the calendar (~3.0x), 8.1-9.8% across 2022-2025.

Re-guarded 2026-10-03 (release cve_2026-10-03_0900Z) so that no copy names
a year the chart stops showing in January: the weekday and Patch Tuesday
headlines follow "the latest complete year", the ID-age headline names
2021-2025, and every read of the partial current year goes through
claims_support.judged with a size bar.
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
if json.loads(_meta_path.read_text("utf-8")).get("sample") is True:
    pytest.skip(
        "site/data holds sample data — claims audit only judges real data",
        allow_module_level=True,
    )


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return claims_support.read_json(path)


GENERATION_YEAR = claims_support.GENERATION_YEAR

# Size bars for the current (partial) year, in dated records. 1 Jan 2027 is
# a Friday, so the first ~500 records of a year can arrive before its first
# Tuesday; these bars hold the year out until it has several weeks behind
# it (2026 runs at ~270 records a day, 2025 ran at ~130).
WEEKDAY_MIN_N = 8_000
PATCH_TUESDAY_MIN_N = 10_000   # two or three Patch Tuesdays at least
ID_AGE_MIN_N = 20_000          # prior-year IDs cluster early in the year


def latest_complete_years(named: int) -> list[int]:
    """The latest complete year as the chart names it (the pipeline's
    choice) and as the calendar does; the two differ only in a rehearsal,
    where the payload still carries the pipeline's pre-rollover choice."""
    return sorted({named, GENERATION_YEAR - 1})


def check_one_in_five_2021_to_2025(d: dict) -> None:
    # editorial.js (calendar.html hero headline): "From 2021 to 2025, about
    # one in five CVEs published each year carried an earlier year's ID."
    # Named years, so the January rollover cannot move it. 2026-10-03:
    # 19.5 / 20.8 / 19.0 / 18.2 / 20.4%. It said "One in five CVEs
    # published in 2025 ..." until 2026-10-03, which the stat would have
    # contradicted once it moved to 2026 in January.
    by_year = {y["year"]: y["pct_prior_year"] for y in d["id_age"]["years"]}
    off = {y: by_year.get(y) for y in range(2021, 2026)
           if by_year.get(y) is None or not 17 <= by_year[y] <= 23}
    assert not off, (
        f"'From 2021 to 2025, about one in five' needs each year in "
        f"17-23%; off: {off}"
    )


def check_2026_lowest_since_2008(d: dict) -> None:
    # editorial.js (calendar.html hero caption): "The 2026 share is the
    # lowest since 2008." Holds on both sides of the rollover: 2026 below
    # every year from 2009 to 2025 (lowest 13.6%, 2013) and not below
    # 2008's 4.9%. 2026-10-03: 10.1% (n=73,605), falling about 0.6 points
    # a fortnight; a year-end of 7-8% keeps it. Replaced "2026 is running
    # lower" on 2026-10-03.
    by_year = {y["year"]: y for y in d["id_age"]["years"]}
    row = by_year.get(2026)
    if row is None or not claims_support.judged(2026, row["n"],
                                                min_n=ID_AGE_MIN_N):
        pytest.skip("2026 is too young to judge")
    share = row["pct_prior_year"]
    lower = {y: by_year[y]["pct_prior_year"] for y in range(2009, 2026)
             if by_year[y]["pct_prior_year"] <= share}
    assert not lower, (
        f"'the lowest since 2008' — 2026 at {share}% is not below {lower}"
    )
    assert by_year[2008]["pct_prior_year"] <= share, (
        f"'the lowest since 2008' — 2026 at {share}% is below 2008's "
        f"{by_year[2008]['pct_prior_year']}% too; name an earlier year"
    )


def check_tuesday_peak(d: dict) -> None:
    # editorial.js (calendar.html weekly beat headline + caption): "In the
    # latest complete year, Tuesday carried about a quarter of all CVE
    # publications" and "Saturday and Sunday carry few records". The
    # headline named 2025 until 2026-10-03; the chart moves to 2026 in
    # January. "About a quarter" is 22-28%; "few" is at most 12% for the
    # two days together. 2026-10-03: 2025 Tuesday 24.5%, weekend 7.5%;
    # 2026 so far 25.5% and 9.2%.
    comp = d["weekday"]["comparison"]
    assert comp is not None, "no charted years — nothing carries the claim"
    rows = {y["year"]: y for y in d["weekday"]["years"]}
    for year in latest_complete_years(comp["latest_year"]):
        row = rows[year]
        tue = row["pct"][1]
        assert tue == max(row["pct"]), (
            f"'Tuesday carried about a quarter' — {year}'s top weekday share "
            f"is {max(row['pct'])}%, Tuesday only {tue}%"
        )
        assert 22 <= tue <= 28, (
            f"'about a quarter' claims ~25% for {year}; data says {tue}%"
        )
        weekend = row["pct"][5] + row["pct"][6]
        assert weekend <= 12, (
            f"'Saturday and Sunday carry few records' — {year}'s weekend "
            f"holds {weekend:.1f}% combined"
        )


def check_tuesday_busiest_since_2022(d: dict) -> None:
    # editorial.js (home card): "Since 2022, more CVEs have been published
    # on Tuesday than on any other day." Every complete year from 2022, and
    # the current year once it has WEEKDAY_MIN_N dated records. 2026-10-03:
    # Tuesday leads 2022-2026 with 22.3-25.5% (runner-up 21.1%, Friday
    # 2022). Moved from test_claims_copy.py on 2026-10-03; it used to judge
    # the current year from 500 records, which fails on 1 Jan 2027 (a
    # Friday).
    years = [y for y in d["weekday"]["years"] if y["year"] >= 2022
             and claims_support.judged(y["year"], y["n"],
                                       min_n=WEEKDAY_MIN_N)]
    assert any(y["year"] < GENERATION_YEAR for y in years), years
    off = [(y["year"], y["pct"]) for y in years
           if y["pct"].index(max(y["pct"])) != 1]
    assert not off, (
        f"'Since 2022, more CVEs have been published on Tuesday than on any "
        f"other day' — Tuesday does not lead in {off}"
    )


def check_wednesday_baseline_and_clamps(d: dict) -> None:
    # editorial.js (calendar.html weekly beat caption): "a decade earlier
    # the peak sat later in the week" — the baseline rolls forward each
    # January (2015 peaks Wednesday, 2016 Thursday), so the copy names no
    # day; the guard only needs the baseline's peak to fall after Tuesday.
    comp = d["weekday"]["comparison"]
    assert comp is not None, "no charted years — nothing carries the claim"
    row = next(y for y in d["weekday"]["years"]
               if y["year"] == comp["baseline_year"])
    peak = row["pct"].index(max(row["pct"]))  # 0 = Monday
    assert peak > 1, (
        f"'a decade earlier the peak sat later in the week' — "
        f"{comp['baseline_year']}'s peak weekday index is {peak} "
        f"(0 = Monday); it is not later than Tuesday; update the caption"
    )
    # reservation methodology: "the real corpus currently contains none"
    # (clamped negative ID ages)
    assert d["id_age"]["clamped_negative"] == 0, (
        f"'the real corpus currently contains none' — clamped_negative is "
        f"{d['id_age']['clamped_negative']}; update the methodology"
    )


def check_patch_tuesday_multiple(d: dict) -> None:
    # editorial.js (calendar.html patch tuesday headline): "In the latest
    # complete year, Patch Tuesdays carried two to three times their
    # calendar share of CVEs." The ratio is the chart's own: the year's bar
    # over the dashed 3.3% line, read at one decimal as the copy reads it.
    # 2026-10-03: 2025 at 9.8% = 2.97x (2.99x on the raw counts), 2026 so
    # far 8.5% = 2.58x. The headline said "In 2025 ... nearly three times"
    # until 2026-10-03, unguarded, and the guard allowed 1.8-3.8x.
    pt = d["patch_tuesday"]
    h = pt["headline"]
    assert h is not None, "no charted years — nothing carries the claim"
    calendar_pct = pt["calendar_pct"]
    rows = {r["year"]: r for r in pt["years"]}
    for year in latest_complete_years(h["latest_year"]):
        ratio = rows[year]["pct"] / calendar_pct
        assert 2.0 <= round(ratio, 1) <= 3.0, (
            f"'two to three times their calendar share' — {year}: "
            f"{rows[year]['pct']}% against {calendar_pct}% = {ratio:.2f}x"
        )


def check_patch_tuesday_clears_calendar_line(d: dict) -> None:
    # editorial.js (calendar.html patch tuesday caption): "The bar has
    # cleared that line in every complete year since 2014" (2013 sat below
    # it, 2.8%, which is why the sentence starts at 2014). 2026-10-03: the
    # closest complete year is 2018 at 3.5% against 3.3%.
    pt = d["patch_tuesday"]
    calendar_pct = pt["calendar_pct"]
    below = [r["year"] for r in claims_support.complete_years(pt["years"])
             if r["year"] >= 2014 and r["pct"] <= calendar_pct]
    assert not below, (
        f"'cleared that line in every complete year since 2014' — these "
        f"complete years sit at or under {calendar_pct}%: {below}"
    )


def check_patch_tuesday_clears_an_ordinary_tuesday(d: dict) -> None:
    # editorial.js (calendar.html patch tuesday): "every year since 2019 the
    # bar has cleared what its own ordinary Tuesdays would carry". The chart
    # draws the per-year baseline, so every charted year from 2019 on is
    # judged against its own (2018 is the last year below: 3.5 vs 4.4); the
    # current year once it holds PATCH_TUESDAY_MIN_N dated records.
    # 2026-10-03: the closest is 2019, 5.1% against 4.1%; 2026 so far 8.5%
    # against 5.1%. The ordinary-Tuesday baseline landed 2026-09-20; an
    # edition without it has nothing to judge.
    rows = [r for r in d["patch_tuesday"]["years"] if r["year"] >= 2019
            and claims_support.judged(r["year"], r["n"],
                                      min_n=PATCH_TUESDAY_MIN_N)]
    if not any(r.get("tuesday_baseline_pct") is not None for r in rows):
        pytest.skip("edition predates tuesday_baseline_pct")
    below = [(r["year"], r["pct"], r["tuesday_baseline_pct"]) for r in rows
             if r.get("tuesday_baseline_pct") is not None
             and r["pct"] <= r["tuesday_baseline_pct"]]
    assert not below, (
        f"'every year since 2019 the bar has cleared what its own ordinary "
        f"Tuesdays would carry' vs years at or below their baseline: {below}"
    )


CLAIMS = [
    (
        "a decade earlier the peak sat later in the week",
        "cve_calendar.json",
        check_wednesday_baseline_and_clamps,
    ),
    (
        "From 2021 to 2025, about one in five CVEs published each year "
        "carried an earlier year's ID.",
        "cve_calendar.json",
        check_one_in_five_2021_to_2025,
    ),
    (
        "The 2026 share is the lowest since 2008.",
        "cve_calendar.json",
        check_2026_lowest_since_2008,
    ),
    (
        "In the latest complete year, Tuesday carried about a quarter of all "
        "CVE publications.",
        "cve_calendar.json",
        check_tuesday_peak,
    ),
    (
        "In the latest complete year Saturday and Sunday carry few records",
        "cve_calendar.json",
        check_tuesday_peak,
    ),
    (
        "Since 2022, more CVEs have been published on Tuesday than on any "
        "other day.",
        "cve_calendar.json",
        check_tuesday_busiest_since_2022,
    ),
    (
        "every year since 2019 the bar has cleared what its own ordinary Tuesdays would carry",
        "cve_calendar.json",
        check_patch_tuesday_clears_an_ordinary_tuesday,
    ),
    (
        "In the latest complete year, Patch Tuesdays carried two to three "
        "times their calendar share of CVEs.",
        "cve_calendar.json",
        check_patch_tuesday_multiple,
    ),
    (
        "The bar has cleared that line in every complete year since 2014.",
        "cve_calendar.json",
        check_patch_tuesday_clears_calendar_line,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
