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


def check_more_than_tripled_since_v1(d: dict) -> None:
    # editorial.js (attack.html hero + home card): "more than three times the
    # techniques and sub-techniques of v1.0 in 2018" / "have more than
    # tripled since v1.0 in 2018". 2026-10-03: v19.2 has 697 against
    # v1.0's 188 (3.71x); it would take 133 net retirements to break. This
    # replaced "has grown every year since 2018", which v19.0's 17
    # revocations left 6 entries from breaking (691 at the end of 2025).
    h = d["headline"]
    assert h["first_version"] == "1.0" and h["released_first"].startswith(
        "2018"), (
        f"'v1.0 in 2018' — the first release on record is "
        f"v{h['first_version']} of {h['released_first']}")
    first = h["techniques_first"] + h["subtechniques_first"]
    latest = h["techniques_latest"] + h["subtechniques_latest"]
    assert latest > 3 * first, (
        f"'more than three times as many techniques and sub-techniques as "
        f"v1.0' — v{h['latest_version']} has {latest} against {first} "
        f"({latest / first:.2f}x)")


def check_growth_mostly_subtechniques(d: dict) -> None:
    # editorial.js (attack.html hero caption): "most of the growth since
    # 2018 has been in sub-techniques". 2026-10-03: +475 sub-techniques and
    # +34 techniques since v1.0 (93% of the growth).
    h = d["headline"]
    sub = h["subtechniques_latest"] - h["subtechniques_first"]
    tech = h["techniques_latest"] - h["techniques_first"]
    assert sub > tech and sub > 0, (
        f"'most of the growth since 2018 has been in sub-techniques' — "
        f"sub-techniques {sub:+d}, techniques {tech:+d} since v1.0")


def check_v7_largest_change(d: dict) -> None:
    # editorial.js (attack.html churn caption): "the largest change was
    # v7.0, which introduced sub-techniques: it added 302 and revoked or
    # deprecated 140". 2026-10-03: v7.0 moved 442 entries; the next largest
    # release, v8.0, moved 97. Released bundles do not change.
    def moved(v):
        c = v["churn"]
        return c["added"] + c["deprecated"] + c["revoked"]

    versions = [v for v in d["versions"] if v.get("churn")]
    v7 = next(v for v in versions if v["version"] == "7.0")
    retired = v7["churn"]["deprecated"] + v7["churn"]["revoked"]
    assert (v7["churn"]["added"], retired) == (302, 140), (
        f"'it added 302 and revoked or deprecated 140' — v7.0 added "
        f"{v7['churn']['added']} and retired {retired}")
    biggest = max(versions, key=moved)
    assert biggest["version"] == "7.0", (
        f"'the largest change was v7.0' — v{biggest['version']} moved "
        f"{moved(biggest)} entries against v7.0's {moved(v7)}")


def check_catalogs_grew_since_2018(d: dict) -> None:
    # editorial.js (attack.html catalog headline): "ATT&CK's catalogs of
    # groups and software have grown since 2018". 2026-10-03: groups 60 ->
    # 176, software 189 -> 825 from v1.0 to v19.2.
    first, latest = d["versions"][0], d["versions"][-1]
    assert first["released"].startswith("2018"), first["released"]
    for key in ("groups", "software"):
        assert latest[key] > first[key], (
            f"'catalogs of groups and software have grown since 2018' — "
            f"{key}: v{first['version']} {first[key]}, "
            f"v{latest['version']} {latest[key]}")


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
        "Across its forty-odd releases",
        "attack_churn.json",
        check_forty_odd_releases,
    ),
    (
        "ATT&CK's enterprise matrix has more than three times the techniques "
        "and sub-techniques of v1.0 in 2018.",
        "attack_churn.json",
        check_more_than_tripled_since_v1,
    ),
    (
        "Active ATT&CK techniques and sub-techniques have more than tripled "
        "since v1.0 in 2018.",
        "attack_churn.json",
        check_more_than_tripled_since_v1,
    ),
    (
        "most of the growth since 2018 has been in sub-techniques",
        "attack_churn.json",
        check_growth_mostly_subtechniques,
    ),
    (
        "the largest change was v7.0, which introduced sub-techniques: it "
        "added 302 and revoked or deprecated 140",
        "attack_churn.json",
        check_v7_largest_change,
    ),
    (
        "ATT&CK's catalogs of groups and software have grown since 2018.",
        "attack_churn.json",
        check_catalogs_grew_since_2018,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
