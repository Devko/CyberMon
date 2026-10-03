"""Claims audit for the Breach Ledger copy (site/js/editorial.js).

Same standing guard as test_claims_audit.py, same rules: each entry quotes
the copy verbatim and asserts the committed number still sits in a range
where the sentence stays true. Ranges are deliberately tolerant — normal
nightly drift must not trip them; only a claim becoming untrue should.
When one fails, fix the copy AND this test together, or fix the pipeline;
never silence the test.

Skips itself when site/data holds sample data or the files are missing —
this audit only ever judges the committed real data.
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


def check_typical_gap_in_months(d: dict) -> None:
    # editorial.js (breaches.html hero): headline "Since 2014, the median
    # breach has reached HIBP's catalog months after it happened" and
    # caption "the typical gap is measured in months" — the pooled
    # live-era median, the hero stat's accent figure, must sit in month
    # territory, not days and not years. (Live fetch 2026-07: 144 days;
    # 137.5 on 09-23, 137.0 on 2026-10-03.) The stat's second figure, the
    # latest complete year, is not held to "months": single years range
    # from days to more than a year (check_single_years_vary), and 2026,
    # which takes that slot in January, is at 23 days so far.
    median = d["headline"]["median_days"]
    assert 60 <= median <= 365, (
        f"'the typical gap is measured in months' needs the pooled trend "
        f"median between ~2 and ~12 months; data says {median} days "
        f"(over {d['headline']['trend_n']} breaches)"
    )


def check_import_era_callout(d: dict) -> None:
    # editorial.js (breach lag methodology): "six of its seven
    # opening-import entries predate the service itself, and the seven
    # carry a median nominal lag of well over a year" — import_era is a
    # fixed historical set (n=7, 511 d; PixelFederation is dated launch
    # day, the other six before it).
    era = d["import_era"]
    assert era["n"] == 7, f"'its seven opening-import entries' vs n={era['n']}"
    assert 365 <= era["median_days"] <= 1000, (
        f"'a median nominal lag of well over a year' vs {era['median_days']} d"
    )


def check_single_years_vary(d: dict) -> None:
    # editorial.js (breaches.html hero caption): "The median for a single
    # year has ranged from under a week, in 2014, to more than a year, in
    # 2017 and 2023." Named, complete years. (2026-10-03, unchanged since
    # 09-23: 5 days in 2014, 452 in 2017, 439 in 2023.)
    by = {r["year"]: r["median_days"] for r in d["lag_by_year"]}
    assert by[2014] < 7, f"'under a week, in 2014' vs {by[2014]} days"
    for y in (2017, 2023):
        assert by[y] > 365, f"'more than a year, in {y}' vs {by[y]} days"


# A partial year's class shares are held to the copy only from this many
# cataloged breaches; three breaches in January can put a share anywhere.
CLASS_SHARE_MIN_BREACHES = 50


def _email_rows(d: dict) -> list[dict]:
    return [y for y in d["class_shares"]["years"]
            if claims_support.judged(y["year"], y.get("n"),
                                     min_n=CLASS_SHARE_MIN_BREACHES)]


def check_email_every_year_since_2015(d: dict) -> None:
    # editorial.js (breaches.html leaks caption): "Email addresses appear in
    # at least 95% of each year's breaches since 2015." (2026-10-03,
    # unchanged since 09-23: lowest 97.0% in 2015 and 98.6% in 2021,
    # 98.8% in 2025, 100% in 2026 so far over 102 breaches; 2014 was 88.9%.)
    rows = [(y["year"], y["shares"].get("Email addresses", 0.0))
            for y in _email_rows(d) if y["year"] >= 2015]
    assert rows and rows[0][0] == 2015, rows[:1]
    low = [(y, s) for y, s in rows if s < 95]
    assert not low, f"'at least 95% of each year's breaches since 2015' vs {low}"


def check_email_nearly_every_breach(d: dict) -> None:
    # editorial.js (breaches.html leaks headline): "Nearly every cataloged
    # breach includes email addresses" — pooled over the charted years.
    # (2026-10-03: 99.3% of 999 breaches, 2014 through 2026; 99.3% of 998
    # on 09-23.)
    rows = _email_rows(d)
    n = sum(y["n"] for y in rows)
    with_email = sum(y["n"] * y["shares"].get("Email addresses", 0.0) / 100
                     for y in rows)
    assert n and with_email / n >= 0.95, (
        f"'Nearly every cataloged breach includes email addresses' vs "
        f"{100 * with_email / n:.1f}% of {n}")


def check_third_take_over_a_year(d: dict) -> None:
    # editorial.js (breaches.html hero): "roughly a third of entries take
    # more than a year to reach the catalog". (Live fetch 2026-07: 35.5%.)
    pct = d["headline"]["pct_over_365d"]
    assert 25 <= pct <= 45, (
        f"'roughly a third of entries take more than a year to reach the catalog' "
        f"claims ~33%; data says {pct}%"
    )


def check_passwords_trend(d: dict) -> None:
    # editorial.js (breaches.html leaks caption): "Passwords are the trend:
    # in nine of ten breaches cataloged in 2014, about four in ten by 2025,
    # and lower every year since 2019." Named years: 2014-2025 are settled.
    by = {y["year"]: y["shares"].get("Passwords") for y in d["class_shares"]["years"]}
    assert by[2014] is not None and 85 <= by[2014] <= 95, by.get(2014)
    assert by[2025] is not None and 35 <= by[2025] <= 45, by.get(2025)
    run = [by[y] for y in range(2019, 2026)]
    assert all(a > b for a, b in zip(run, run[1:])), (
        f"'lower every year since 2019' vs {list(zip(range(2019, 2026), run))}")


CLAIMS = [
    (
        "Since 2014, the median breach has reached HIBP's catalog months after it happened.",
        "breach_ledger.json",
        check_typical_gap_in_months,
    ),
    (
        "the typical gap is measured in months",
        "breach_ledger.json",
        check_typical_gap_in_months,
    ),
    (
        # home card; cards are text only, so "typically" is the pooled median
        "Breaches typically reach Have I Been Pwned months after their "
        "recorded breach date.",
        "breach_ledger.json",
        check_typical_gap_in_months,
    ),
    (
        "The median for a single year has ranged from under a week, in 2014, to more than a year, in 2017 and 2023.",
        "breach_ledger.json",
        check_single_years_vary,
    ),
    (
        "Email addresses appear in at least 95% of each year's breaches since 2015.",
        "breach_ledger.json",
        check_email_every_year_since_2015,
    ),
    (
        "Nearly every cataloged breach includes email addresses; a falling share includes passwords.",
        "breach_ledger.json",
        check_email_nearly_every_breach,
    ),
    (
        "Nearly every cataloged breach includes email addresses; a falling share includes passwords.",
        "breach_ledger.json",
        check_passwords_trend,
    ),
    (
        "six of its seven opening-import entries predate the service itself, and the seven carry a median nominal lag of well over a year",
        "breach_ledger.json",
        check_import_era_callout,
    ),
    (
        "roughly a third of entries take more than a year to reach the catalog",
        "breach_ledger.json",
        check_third_take_over_a_year,
    ),
    (
        "Passwords appeared in nine of ten breaches cataloged in 2014, about four in ten by 2025, and a lower share every year since 2019",
        "breach_ledger.json",
        check_passwords_trend,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
