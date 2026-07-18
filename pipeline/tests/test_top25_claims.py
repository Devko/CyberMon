"""Claims audit for the CWE Top 25 vs reality module (pattern:
test_claims_naming.py).

The top25.html copy (site/js/editorial.js) makes verbal claims about numbers
in site/data/cwe_top25.json, which refreshes nightly from the corpus. Each
CLAIMS entry quotes the copy verbatim (grep for it in editorial.js) and
asserts the underlying number still sits in a range where the sentence stays
true. Ranges are tolerant — normal night-to-night drift must not trip them;
only a claim becoming untrue should.

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


def _headline(d: dict) -> dict:
    h = d.get("headline")
    if not h:
        pytest.skip("cwe_top25 headline is null (below min_n) — nothing to audit")
    return h


def check_several_official_picks_miss_the_measured_top25(d: dict) -> None:
    # editorial.js (top25_ranks caption): "several never crack the 25 most
    # common weaknesses we actually measure"
    h = _headline(d)
    n = h["outside_measured_top25"]
    assert 3 <= n <= 20, (
        f"'several never crack the 25 most common weaknesses we actually "
        f"measure' needs 3–20 of the official Top 25 to fall outside the "
        f"measured top 25; it is {n}"
    )


def check_almost_all_official_classes_are_exploited(d: dict) -> None:
    # editorial.js (top25_exploited caption): "almost every one of the
    # official Top 25 turns up in the exploited set"
    h = _headline(d)
    n = h["in_kev"]
    assert n >= 15, (
        f"'almost every one of the official Top 25 turns up in the exploited "
        f"set' needs at least 15 of the 25 to carry a KEV entry; it is {n}"
    )


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "several never crack the 25 most common weaknesses we actually measure",
        "cwe_top25.json",
        check_several_official_picks_miss_the_measured_top25,
    ),
    (
        "almost every one of the official Top 25 turns up in the exploited set",
        "cwe_top25.json",
        check_almost_all_official_classes_are_exploited,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
