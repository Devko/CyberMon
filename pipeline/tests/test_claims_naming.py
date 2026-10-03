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


def _groups_with_at_least(d: dict, n: int) -> int:
    return sum(b["n"] for b in d["distribution"] if b["alt_count"] >= n)


def check_most_renamed_at_least_a_dozen(d: dict) -> None:
    # editorial.js (naming.html hero): "The most-renamed ATT&CK groups carry
    # a dozen or more alternate names each." — plural, so at least two
    # groups. (ATT&CK v19.2, 2026-10-03: APT28 and Mustang Panda 15, APT29
    # 14, the next group, OilRig, 11.)
    n = _groups_with_at_least(d, 12)
    assert n >= 2, (
        f"'the most-renamed groups carry a dozen or more names each' needs "
        f"at least two groups with 12 or more alternate names; the data "
        f"has {n}"
    )


def check_most_renamed_more_than_a_dozen(d: dict) -> None:
    # editorial.js (home card 14): "ATT&CK's most-renamed threat groups
    # carry more than a dozen other names each." — at least two groups with
    # 13 or more. (2026-10-03: three, at 15, 15 and 14.)
    n = _groups_with_at_least(d, 13)
    assert n >= 2, (
        f"'more than a dozen other names each' needs at least two groups "
        f"with 13 or more alternate names; the data has {n}"
    )


def check_short_tail_of_ten_or_more(d: dict) -> None:
    # editorial.js (naming.html alias counts): "a short tail of groups has
    # ten or more". (2026-10-03: 6 of 176 groups.)
    total = d["headline"]["total_groups"]
    tail = _groups_with_at_least(d, 10)
    assert 1 <= tail <= total / 10, (
        f"'a short tail of groups has ten or more' needs between one group "
        f"and a tenth of the {total} groups; it is {tail}"
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
        "The most-renamed ATT&CK groups carry a dozen or more alternate names each.",
        "naming.json",
        check_most_renamed_at_least_a_dozen,
    ),
    (
        "a dozen or more names apiece",
        "naming.json",
        check_most_renamed_at_least_a_dozen,
    ),
    (
        "ATT&CK's most-renamed threat groups carry more than a dozen other names each.",
        "naming.json",
        check_most_renamed_more_than_a_dozen,
    ),
    (
        "roughly four in ten tracked groups carry no second name",
        "naming.json",
        check_roughly_four_in_ten_have_no_alias,
    ),
    (
        "Roughly four in ten groups have none",
        "naming.json",
        check_roughly_four_in_ten_have_no_alias,
    ),
    (
        "a short tail of groups has ten or more",
        "naming.json",
        check_short_tail_of_ten_or_more,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
