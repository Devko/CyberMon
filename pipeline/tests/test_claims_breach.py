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


def check_typical_gap_in_months(d: dict) -> None:
    # editorial.js (breaches.html hero): "the typical gap is measured in
    # months" — the pooled live-era median must sit in month territory,
    # not days and not years. (Live fetch 2026-07: 144 days.)
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
        "the typical gap is measured in months",
        "breach_ledger.json",
        check_typical_gap_in_months,
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
