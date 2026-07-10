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

GENERATION_YEAR = int(_META["generated_at"][:4])


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


def check_third_take_over_a_year(d: dict) -> None:
    # editorial.js (breaches.html hero): "roughly a third of entries take
    # more than a year to surface". (Live fetch 2026-07: 35.5%.)
    pct = d["headline"]["pct_over_365d"]
    assert 25 <= pct <= 45, (
        f"'roughly a third of entries take more than a year to surface' "
        f"claims ~33%; data says {pct}%"
    )


CLAIMS = [
    (
        "the typical gap is measured in months",
        "breach_ledger.json",
        check_typical_gap_in_months,
    ),
    (
        "roughly a third of entries take more than a year to surface",
        "breach_ledger.json",
        check_third_take_over_a_year,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
