"""Claims audit for the CNA Roster History module (pattern:
test_claims_naming.py).

The roster.html copy (site/js/editorial.js) makes verbal claims about numbers
in site/data/cna_roster.json. The size and flux charts are launch-thin by
design and make no numeric claim; the current-composition section, however,
is real from day one, so those are the claims audited here. Each CLAIMS entry
quotes the copy verbatim (grep for it in editorial.js) and asserts the
underlying number still sits in a range where the sentence stays true.
Ranges are tolerant — normal night-to-night drift must not trip them; only a
claim becoming untrue should.

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim + range, in the same
commit) or the pipeline broke (fix the pipeline). NEVER silence a failing
claim check without doing one of the two.

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


def check_mostly_vendors(d: dict) -> None:
    # editorial.js (roster.html mix hero): "Mostly vendors, speaking for
    # themselves." — Vendor must be the top type and a majority of the roster.
    h = d["headline"]
    total = h["roster_total"]
    share = 100.0 * h["top_type_n"] / total if total else 0.0
    assert h["top_type"] == "Vendor" and share >= 50.0, (
        f"'Mostly vendors' needs Vendor as the plurality type at >=50% of the "
        f"roster; top type is {h['top_type']!r} at {share:.0f}%"
    )


def check_two_roots_mitre_larger(d: dict) -> None:
    # editorial.js (roster.html mix caption): "two top-level roots, MITRE and
    # CISA, that vouch for the rest" — both present, MITRE the larger.
    h = d["headline"]
    assert h["mitre_n"] > 0 and h["cisa_n"] > 0 and h["mitre_n"] > h["cisa_n"], (
        f"'two top-level roots, MITRE and CISA' needs both non-empty with MITRE "
        f"larger; MITRE={h['mitre_n']}, CISA={h['cisa_n']}"
    )


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "Mostly vendors, speaking for themselves.",
        "cna_roster.json",
        check_mostly_vendors,
    ),
    (
        "two top-level roots, MITRE and CISA, that vouch for the rest",
        "cna_roster.json",
        check_two_roots_mitre_larger,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
