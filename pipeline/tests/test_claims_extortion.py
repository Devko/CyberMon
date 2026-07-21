"""Claims audit for the Extortion Ledger copy (test_claims_audit.py's
pattern — see that module's docstring for the rules; short version: each
entry quotes site/js/editorial.js verbatim and asserts the committed data
still sits in a range where the sentence stays true. NEVER silence a
failing claim — fix the copy and the range together, in one commit.

The module skips itself when site/data/ holds sample data (meta.json
"sample": true) or the files are missing — offline-fixture CI smoke runs
write elsewhere, so this audit only ever judges the committed real data.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

# Resolve site/data/ relative to this file so the audit works from any cwd.
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


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return json.loads(path.read_text("utf-8"))


# --------------------------------------------------------------------------
# Claim checks. Assertion messages restate the claim so a failure reads as
# "this sentence is no longer true", not as a raw number.
# --------------------------------------------------------------------------


def check_billion_dollar_floor(d: dict) -> None:
    # editorial.js (extortion.html hero): "Over a billion dollars, settled
    # in public view." The dataset is append-only crowdsourcing, so the
    # total should only grow; the ceiling guards against a unit error.
    total = d["headline"]["total_usd"]
    assert 1_000_000_000 <= total <= 10_000_000_000, (
        f"'Over a billion dollars, settled in public view' needs total "
        f"confirmed USD in [$1B, $10B]; data says ${total:,}"
    )


def check_unattributed_two_thirds(d: dict) -> None:
    # editorial.js (extortion.html families): "The single largest slice of
    # verified revenue — about two thirds — carries no family label at all"
    unattributed = d["families"]["unattributed"]["usd"]
    total = d["catalog"]["total_usd"]
    share = 100.0 * unattributed / total if total else 0.0
    assert 55 <= share <= 80, (
        f"'about two thirds ... carries no family label' claims ~67%; "
        f"data says {share:.1f}% (${unattributed:,} of ${total:,})"
    )
    top_usd = max((f["usd"] for f in d["families"]["top"]), default=0)
    assert unattributed > top_usd, (
        f"'The single largest slice' needs unattributed (${unattributed:,}) "
        f"above the top-ranked family (${top_usd:,})"
    )


# --------------------------------------------------------------------------
def check_last_verified_payment_quarter(d: dict) -> None:
    # editorial.js (extortion): "the ledger's last verified payment landed
    # in Q3 2024" — a hard date one new crowdsourced report invalidates
    # overnight. Failing here means a newer payment landed: update BOTH
    # copy occurrences (revenue caption + payments methodology).
    paid = [q for q in d["revenue_by_quarter"] if q["usd"] > 0]
    assert paid, "no paid quarters on the ledger at all"
    newest = (paid[-1]["year"], paid[-1]["quarter"])
    assert newest == (2024, 3), (
        f"'last verified payment landed in Q3 2024' vs newest paid quarter "
        f"{newest[0]}Q{newest[1]}"
    )


CLAIMS = [
    (
        "the ledger's last verified payment landed in Q3 2024",
        "extortion_ledger.json",
        check_last_verified_payment_quarter,
    ),
    (
        "Over a billion dollars, settled in public view.",
        "extortion_ledger.json",
        check_billion_dollar_floor,
    ),
    (
        "The single largest slice of verified revenue — about two thirds — carries no family label at all",
        "extortion_ledger.json",
        check_unattributed_two_thirds,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
