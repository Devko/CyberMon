"""Claims audit for the Hygiene Index copy (test_claims_audit.py pattern).

Each entry quotes site/js/editorial.js verbatim and asserts the number in
site/data/dnssec_adoption.json still sits in a range where the sentence
stays true. Ranges are deliberately tolerant — nightly drift must not trip
them; only a claim becoming untrue should. Never silence a failure here:
fix the copy (and this test's quoted claim + range, in the same commit) or
fix the pipeline. Reference values, live-checked 2026-07-10: world 38.5%
now, 8.6% at the record's 2013-10 start; economy set spans 93.5% (PH) down
to 0.1% (CN).
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


def check_world_line(d: dict) -> None:
    # editorial.js (hygiene.html hero): "climbing from under a tenth when
    # the record starts in 2013 to just under four in ten today"
    first = d["world"]["series"][0]
    latest = d["world"]["latest"]["validating_pc"]
    assert first["month"].startswith("2013"), (
        f"'when the record starts in 2013' — series now starts "
        f"{first['month']}; update the copy"
    )
    assert first["validating_pc"] <= 10, (
        f"'from under a tenth' claims the 2013 start sat below 10%; "
        f"data says {first['validating_pc']}%"
    )
    assert 32 <= latest <= 43, (
        f"'just under four in ten today' claims ~38%; data says {latest}%"
    )


def check_giants_gap(d: dict) -> None:
    # editorial.js (hygiene.html economies): "the top of this list
    # validates for roughly nine of every ten users, the bottom for
    # almost none"
    economies = d["economies"]
    assert economies, "no economies in dnssec_adoption.json"
    top, bottom = economies[0], economies[-1]
    assert 85 <= top["latest_pc"] <= 100, (
        f"'the top of this list validates for roughly nine of every ten "
        f"users' claims ~90%; data says {top['latest_pc']}% ({top['cc']})"
    )
    assert bottom["latest_pc"] <= 5, (
        f"'the bottom for almost none' needs a near-zero laggard; "
        f"data says {bottom['latest_pc']}% ({bottom['cc']})"
    )


CLAIMS = [
    (
        "climbing from under a tenth when the record starts in 2013 to just under four in ten today",
        "dnssec_adoption.json",
        check_world_line,
    ),
    (
        "the top of this list validates for roughly nine of every ten users, the bottom for almost none",
        "dnssec_adoption.json",
        check_giants_gap,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
