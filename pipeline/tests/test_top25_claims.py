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


def _headline(d: dict) -> dict:
    h = d.get("headline")
    if not h:
        pytest.skip("cwe_top25 headline is null (below min_n) — nothing to audit")
    return h


def check_some_official_picks_miss_the_measured_top25(d: dict) -> None:
    # editorial.js (top25_ranks caption): "The two orders differ, and not
    # every official pick ranks among the 25 most common weaknesses in the
    # measured window". (2026-10-03, window 2021-2025: 3 outside, CWE-306,
    # CWE-639 and CWE-770 at measured ranks 27, 28 and 31. The window moves
    # to 2022-2026 in January; the 2026 records in the local corpus leave
    # only CWE-770 outside, at rank 28, which is why the copy no longer says
    # "a few".)
    h = _headline(d)
    n = h["outside_measured_top25"]
    assert n >= 1, (
        f"'not every official pick ranks among the 25 most common "
        f"weaknesses' needs at least one official pick outside the measured "
        f"top 25; it is {n}"
    )
    assert any(r["official_rank"] != r["measured_rank"] for r in d["ranks"]), (
        "'the two orders differ' but every official rank equals its "
        "measured rank"
    )


def check_most_official_picks_in_the_measured_top25(d: dict) -> None:
    # editorial.js (home card 15): "Most of MITRE's CWE Top 25 also rank
    # among the 25 most frequent weaknesses in CVEs." — a majority, so at
    # most 12 of the 25 outside. (2026-10-03: 22 in, 3 outside.)
    h = _headline(d)
    total = h["in_measured_top25"] + h["outside_measured_top25"]
    assert h["in_measured_top25"] > total / 2, (
        f"'Most of MITRE's CWE Top 25 also rank among the 25 most frequent' "
        f"needs a majority inside the measured top 25; it is "
        f"{h['in_measured_top25']} of {total}"
    )


def check_almost_all_official_classes_are_exploited(d: dict) -> None:
    # editorial.js (top25_exploited headline and caption): "Almost every CWE
    # Top 25 class appears in KEV" / "almost every one of the official Top
    # 25 turns up in the exploited set". (2026-10-03: 24 of 25; only CWE-770
    # has no KEV entry.) Three or fewer missing still reads as "almost
    # every".
    h = _headline(d)
    n = h["in_kev"]
    assert n >= 22, (
        f"'almost every one of the official Top 25 turns up in the exploited "
        f"set' needs at least 22 of the 25 to carry a KEV entry; it is {n}"
    )


def check_kev_counts_are_uneven(d: dict) -> None:
    # editorial.js (top25_exploited caption): "from over a hundred entries
    # for some classes to one or none for others". (2026-10-03: CWE-787
    # 125, CWE-78 108, CWE-416 104; CWE-476 and CWE-639 1, CWE-770 0.
    # KEV counts only grow while the official list stays the same.)
    counts = sorted(r["kev_n"] for r in d["ranks"])
    assert sum(1 for n in counts if n > 100) >= 2, (
        f"'over a hundred entries for some classes' needs at least two "
        f"classes above 100 KEV entries; the largest are {counts[-3:]}"
    )
    assert counts[0] <= 1, (
        f"'one or none for others' needs a class with at most one KEV "
        f"entry; the smallest count is {counts[0]}"
    )


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "The two orders differ, and not every official pick ranks among the "
        "25 most common weaknesses in the measured window.",
        "cwe_top25.json",
        check_some_official_picks_miss_the_measured_top25,
    ),
    (
        "Most of MITRE's CWE Top 25 also rank among the 25 most frequent "
        "weaknesses in CVEs.",
        "cwe_top25.json",
        check_most_official_picks_in_the_measured_top25,
    ),
    (
        "Almost every CWE Top 25 class appears in KEV, in very uneven numbers.",
        "cwe_top25.json",
        check_almost_all_official_classes_are_exploited,
    ),
    (
        "almost every one of the official Top 25 turns up in the exploited set",
        "cwe_top25.json",
        check_almost_all_official_classes_are_exploited,
    ),
    (
        "Almost every CWE Top 25 class appears in KEV, in very uneven numbers.",
        "cwe_top25.json",
        check_kev_counts_are_uneven,
    ),
    (
        "from over a hundred entries for some classes to one or none for others",
        "cwe_top25.json",
        check_kev_counts_are_uneven,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
