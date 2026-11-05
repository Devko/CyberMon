"""Claims audit for the Adversary Atlas home card (pattern:
test_claims_naming.py).

The Atlas page keeps its own copy in site/js/atlas.js and fills every
number there from data/attack_atlas.json, so it has nothing to drift. Its
home card in site/js/editorial.js makes one quantified claim, "each MITRE
ATT&CK group", which is pinned here: the atlas must carry every active group
of its release, and the groups must have edges to show.

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim, in the same commit) or
the pipeline broke (fix the pipeline). NEVER silence a failing claim check
without doing one of the two.

Skips itself when site/data/ holds sample data or the files are missing —
this audit only ever judges the committed real data.
"""
from __future__ import annotations

import json

import pytest

from . import claims_support

DATA_DIR = claims_support.DATA_DIR

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
    return claims_support.read_json(path)


def check_each_group_is_linked(d: dict) -> None:
    # editorial.js (home card, Adversary Atlas): "The Atlas links each MITRE
    # ATT&CK group to the software and techniques ATT&CK records it using."
    # (v20.0, 2026-11-05: 178 groups, every one with at least one edge.)
    # "Each group" = every active intrusion-set of the release, which the
    # Threat Group Aliases stage counts independently from the same bundle.
    naming = load("naming.json")
    if naming.get("version") == d["version"] and naming.get("headline"):
        total = naming["headline"]["total_groups"]
        assert d["counts"]["groups"] == total, (
            f"the atlas carries {d['counts']['groups']} groups but ATT&CK "
            f"v{d['version']} has {total} active ones"
        )
    groups = d["counts"]["groups"]
    linked = sum(1 for row in d["uses"][:groups] if row)
    # Margin: a release may add a group before its first edges land; the
    # card is wrong only if that stops being rare.
    assert linked >= 0.9 * groups, (
        f"'links each group to its software and techniques' needs nearly "
        f"every group to have an edge; {linked} of {groups} do"
    )


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "The Atlas links each MITRE ATT&CK group to the software and techniques ATT&CK records it using.",
        "attack_atlas.json",
        check_each_group_is_linked,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
