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
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parents[2] / "site" / "data"

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
    return json.loads(path.read_text("utf-8"))


def check_old_id_share(d: dict) -> None:
    # editorial.js (calendar.html hero): headline "One in five new CVEs
    # arrives on an old ID" + caption "one in five of the latest complete
    # year's records carried an ID minted in an earlier year"
    h = d["id_age"]["headline"]
    assert h is not None, "no charted years — nothing carries the claim"
    assert 15 <= h["pct_prior_year_latest"] <= 27, (
        f"'one in five' claims ~20%; data says "
        f"{h['pct_prior_year_latest']}% for {h['latest_year']}"
    )


def check_tuesday_peak(d: dict) -> None:
    # editorial.js (calendar.html weekly beat): "Tuesday is the busiest
    # day of the CVE week — roughly a quarter of the latest complete
    # year's records — while the weekend is close to silent"
    comp = d["weekday"]["comparison"]
    assert comp is not None, "no charted years — nothing carries the claim"
    row = next(y for y in d["weekday"]["years"]
               if y["year"] == comp["latest_year"])
    tue = row["pct"][1]
    assert tue == max(row["pct"]), (
        f"'Tuesday is the busiest day' — {comp['latest_year']}'s top "
        f"weekday share is {max(row['pct'])}%, Tuesday only {tue}%"
    )
    assert 19 <= tue <= 31, (
        f"'roughly a quarter' claims ~25%; data says {tue}%"
    )
    weekend = row["pct"][5] + row["pct"][6]
    assert weekend <= 12, (
        f"'the weekend is close to silent' needs a near-empty weekend; "
        f"data says {weekend:.1f}% combined"
    )


def check_wednesday_baseline_and_clamps(d: dict) -> None:
    # editorial.js (calendar.html weekly beat caption): "ten years ago the
    # peak sat a day later, on Wednesday" — true for the 2015 baseline,
    # but the baseline rolls forward each year (2016's peak is Thursday),
    # so the sentence needs a guard, not faith.
    comp = d["weekday"]["comparison"]
    assert comp is not None, "no charted years — nothing carries the claim"
    row = next(y for y in d["weekday"]["years"]
               if y["year"] == comp["baseline_year"])
    wed = row["pct"][2]
    assert wed == max(row["pct"]), (
        f"'ten years ago the peak sat … on Wednesday' — "
        f"{comp['baseline_year']}'s top weekday share is "
        f"{max(row['pct'])}%, Wednesday only {wed}%; update the caption"
    )
    # reservation methodology: "the real corpus currently contains none"
    # (clamped negative ID ages)
    assert d["id_age"]["clamped_negative"] == 0, (
        f"'the real corpus currently contains none' — clamped_negative is "
        f"{d['id_age']['clamped_negative']}; update the methodology"
    )


def check_patch_tuesday_multiple(d: dict) -> None:
    # editorial.js (calendar.html patch tuesday): "twelve days carrying
    # roughly triple their calendar share of the year's records"
    h = d["patch_tuesday"]["headline"]
    assert h is not None, "no charted years — nothing carries the claim"
    calendar_pct = d["patch_tuesday"]["calendar_pct"]
    ratio = h["pct_latest"] / calendar_pct
    assert 2.2 <= ratio <= 3.8, (
        f"'roughly triple' claims ~3x the {calendar_pct}% calendar share; "
        f"data says {h['pct_latest']}% = {ratio:.1f}x for {h['latest_year']}"
    )
    # caption: "the bar has cleared the line in every complete year since
    # 2014" (2013 sat below it — 2.8% — which is why the sentence starts
    # at 2014)
    below = [y["year"] for y in d["patch_tuesday"]["years"]
             if 2014 <= y["year"] <= h["latest_year"]
             and y["pct"] <= calendar_pct]
    assert not below, (
        f"'cleared the line in every complete year since 2014' — these "
        f"complete years sit at or under {calendar_pct}%: {below}"
    )


CLAIMS = [
    (
        "ten years ago the peak sat a day later, on Wednesday",
        "cve_calendar.json",
        check_wednesday_baseline_and_clamps,
    ),
    (
        "In the latest complete year, one in five records shipped on an "
        "earlier-year ID",
        "cve_calendar.json",
        check_old_id_share,
    ),
    (
        "In the latest complete year, Tuesday leads with roughly a quarter "
        "of all records",
        "cve_calendar.json",
        check_tuesday_peak,
    ),
    (
        "The latest complete year put roughly triple that share on them",
        "cve_calendar.json",
        check_patch_tuesday_multiple,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
