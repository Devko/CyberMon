"""Claims audit for the KEV vintage section (kev.html, section key
``kev_vintage``): how old a CVE is when CISA adds it to KEV.

Every quantitative claim in the section's headline, caption, table title
and context line is checked here against kev_latency.json. The headline
names complete years only (2023-2025), so the January rollover and a
thin new year cannot move it; the per-year bars and the 12-month table
are filled from the data by kev_vintage.js, and their guards check that
the inputs the sentences name exist and agree.
"""
from __future__ import annotations

import json
from datetime import date, timedelta

import pytest

from . import claims_support

DATA_DIR = claims_support.DATA_DIR

_meta_path = DATA_DIR / "meta.json"
if not _meta_path.exists():
    pytest.skip("site/data/meta.json missing — no committed data to audit",
                allow_module_level=True)
if json.loads(_meta_path.read_text("utf-8")).get("sample") is True:
    pytest.skip("site/data holds sample data — claims audit only judges "
                "real data", allow_module_level=True)

OLD_BUCKETS = ["1-3y", "3-5y", "5-10y", "10y+"]


def _load() -> dict:
    return claims_support.read_json(DATA_DIR / "kev_latency.json")


def check_quarter_over_a_year(d: dict) -> None:
    # headline: "In each year from 2023 to 2025, about a quarter of the CVEs
    # CISA added to KEV had been published more than a year earlier." "About
    # a quarter" is 20-30%, for each of the three named years. (2026-11-05:
    # 24.6% of 187, 24.2% of 186, 22.9% of 245; 2026 so far 18.0%, which
    # the headline does not name.) Complete years: their listings are fixed.
    by_year = {r["year"]: r for r in d["vintage_by_year"]}
    for year in (2023, 2024, 2025):
        assert year in by_year, f"the headline names {year}; no bar for it"
        pct = by_year[year]["pct_over_1y"]
        assert 20 <= pct <= 30, (
            f"'about a quarter' in {year} vs {pct}% added more than a year "
            f"after publication")


def check_bars_start_2023(d: dict) -> None:
    # caption: "Each bar is one year of KEV additions since 2023." The bars
    # are the latency trend's years, which start after the seeding era.
    years = [r["year"] for r in d["vintage_by_year"]]
    assert years and years[0] == 2023, f"bars start in {years[:1]}"
    assert years == [r["year"] for r in d["latency_by_year"]]


def _judged_rows(d: dict) -> list[dict]:
    # Complete years always; the current year once it has the 10 entries
    # a bar needs (a few January days are not held to the copy).
    return [r for r in d["vintage_by_year"]
            if claims_support.judged(r["year"], r["n"], min_n=10)]


def check_split_edges(d: dict) -> None:
    # caption: "split by how long before: 1–3, 3–5, 5–10 or more than 10
    # years"; the four parts add up to the bar.
    rows = _judged_rows(d)
    assert rows, "no judged vintage year"
    for r in rows:
        assert [b["bucket"] for b in r["buckets"]] == OLD_BUCKETS
        assert sum(b["n"] for b in r["buckets"]) == r["over_1y"]


def check_min_ten_per_year(d: dict) -> None:
    # methodology: "a year plots only with at least 10 of them". The
    # pipeline drops thinner years; complete years are checked here.
    small = [(r["year"], r["n"])
             for r in claims_support.complete_years(d["vintage_by_year"])
             if r["n"] < 10]
    assert not small, f"years plotted with fewer than 10 entries: {small}"


def check_oldest_window(d: dict) -> None:
    # table title: "The {shown} oldest CVEs added to KEV in the last 12
    # months": a 365-day window ending on the edition date, oldest first,
    # at most ten names.
    recent = d["oldest_recent"]
    until = date.fromisoformat(recent["until"])
    assert recent["until"] == d["generated_at"][:10]
    assert recent["window_days"] == 365
    assert date.fromisoformat(recent["since"]) == until - timedelta(days=364)
    ages = [e["age_days"] for e in recent["entries"]]
    assert ages == sorted(ages, reverse=True)
    assert 0 < len(ages) <= 10, f"{len(ages)} entries named"


def check_oldest_context(d: dict) -> None:
    # context line: "{n_over_10y} of the {n_listed} CVEs added from {since}
    # to {until} had been published more than ten years earlier." Filled
    # from the data; the count must cover every named entry past ten years,
    # and the window held listings at all. (2026-11-05: 15 of 313; oldest
    # CVE-2008-4128, published 2008, added 2026-07-13.)
    recent = d["oldest_recent"]
    assert recent["n_listed"] >= len(recent["entries"]) > 0
    named_old = sum(1 for e in recent["entries"] if e["age_days"] > 3650)
    assert named_old <= recent["n_over_10y"] <= recent["n_listed"]
    if recent["n_over_10y"] >= len(recent["entries"]):
        assert named_old == len(recent["entries"])


CLAIMS = [
    (
        "In each year from 2023 to 2025, about a quarter of the CVEs CISA added "
        "to KEV had been published more than a year earlier.",
        "kev_latency.json",
        check_quarter_over_a_year,
    ),
    (
        "Each bar is one year of KEV additions since 2023.",
        "kev_latency.json",
        check_bars_start_2023,
    ),
    (
        "split by how long before: 1–3, 3–5, 5–10 or more than 10 years",
        "kev_latency.json",
        check_split_edges,
    ),
    (
        "a year plots only with at least 10 of them",
        "kev_latency.json",
        check_min_ten_per_year,
    ),
    (
        "The {shown} oldest CVEs added to KEV in the last 12 months",
        "kev_latency.json",
        check_oldest_window,
    ),
    (
        "{n_over_10y} of the {n_listed} CVEs added from {since} to {until} had "
        "been published more than ten years earlier.",
        "kev_latency.json",
        check_oldest_context,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(_load())
