"""Claims audit for the Threat-actor Naming Chaos module (pattern:
test_claims_attack.py).

The naming.html copy (site/js/editorial.js) makes verbal claims about numbers
in site/data/naming.json, which refreshes when a new ATT&CK release lands
(~2x a year). Each CLAIMS entry quotes the copy verbatim (grep for it in
editorial.js) and asserts the underlying number still sits in a range where
the sentence stays true. Ranges are tolerant — normal release-to-release
drift must not trip them; only a claim becoming untrue should.

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


def check_most_renamed_at_least_a_dozen(d: dict) -> None:
    # editorial.js (naming.html hero): "The most-renamed answer to a dozen or
    # more names apiece"
    n = d["headline"]["most_renamed_alt_count"]
    assert n >= 12, (
        f"'answer to a dozen or more names apiece' needs the most-renamed "
        f"group to carry at least 12 alternate names; the data has {n}"
    )


def check_roughly_four_in_ten_have_no_alias(d: dict) -> None:
    # editorial.js (naming.html hero): "roughly four in ten tracked groups
    # carry no second name at all"
    total = d["headline"]["total_groups"]
    zero = next((b["n"] for b in d["distribution"] if b["alt_count"] == 0), 0)
    pct = 100.0 * zero / total if total else 0.0
    assert 30.0 <= pct <= 50.0, (
        f"'roughly four in ten tracked groups carry no second name' needs the "
        f"zero-alias share in 30–50%; it is {pct:.1f}% ({zero}/{total})"
    )


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "a dozen or more names apiece",
        "naming.json",
        check_most_renamed_at_least_a_dozen,
    ),
    (
        "roughly four in ten tracked groups carry no second name",
        "naming.json",
        check_roughly_four_in_ten_have_no_alias,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
