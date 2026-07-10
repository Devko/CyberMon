"""Claims audit for the ATT&CK Churn module (pattern: test_claims_audit.py).

The attack.html copy (site/js/editorial.js) makes verbal claims about
numbers in site/data/attack_churn.json, and that file refreshes nightly.
Each CLAIMS entry quotes the copy verbatim (grep for it in editorial.js)
and asserts the underlying number still sits in a range where the sentence
remains true. Ranges are deliberately tolerant — normal release-to-release
drift must not trip them; only a claim becoming untrue should — and were
sanity-checked against the live enterprise-attack-19.1 bundle plus
index.json at build time (2026-07-10: 40 releases; 222 active techniques,
475 active sub-techniques).

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim + range, in the same
commit) or the pipeline broke (fix the pipeline). NEVER silence or delete
a failing claim check without doing one of the two.

Skips itself when site/data/ holds sample data or the files are missing —
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


# --------------------------------------------------------------------------
# Claim checks (assertion messages restate the claim so a failure reads as
# "this sentence is no longer true", not as a raw number).
# --------------------------------------------------------------------------


def check_subtechniques_outnumber_techniques(d: dict) -> None:
    # editorial.js (attack.html hero): "sub-techniques now outnumber the
    # techniques they refine"
    h = d["headline"]
    assert h["subtechniques_latest"] > h["techniques_latest"], (
        f"'sub-techniques now outnumber the techniques they refine' needs "
        f"more active sub-techniques ({h['subtechniques_latest']}) than "
        f"techniques ({h['techniques_latest']}) in v{h['latest_version']}"
    )


def check_forty_odd_releases(d: dict) -> None:
    # editorial.js (attack.html churn): "Forty-odd releases in" — at two
    # releases a year, ~40 stays "forty-odd" for years either side.
    n = len(d["versions"])
    assert 36 <= n <= 49, (
        f"'Forty-odd releases in' claims ~40 enterprise releases; the data "
        f"carries {n}"
    )


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "sub-techniques now outnumber the techniques they refine",
        "attack_churn.json",
        check_subtechniques_outnumber_techniques,
    ),
    (
        "Forty-odd releases in",
        "attack_churn.json",
        check_forty_odd_releases,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
