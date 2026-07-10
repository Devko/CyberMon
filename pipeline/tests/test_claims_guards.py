"""Claims audit for the Security Products copy (test_claims_audit.py's
pattern — see that module's docstring for the rules; short version: each
entry quotes site/js/editorial.js verbatim and asserts the committed data
still sits in a range where the sentence stays true. NEVER silence a
failing claim — fix the copy and the range together, in one commit.

Ranges were verified against the live KEV feed (catalog 2026.07.07,
1,635 entries) at module creation: guard share 11.5% of the catalog
("about one in nine"), ransomware-flag share 37.2% for security-product
entries vs 17.9% for the rest (ratio 2.08 — "roughly twice").

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


def check_one_in_nine_guard_share(d: dict) -> None:
    # editorial.js (guards.html hero): "about one in nine entries in the
    # whole catalog is a product sold to enforce security". Live-feed
    # value at module creation: 11.5%. One-in-nine reads honestly for
    # anything from ~1/12 (8%) to ~1/7 (15%).
    share = d["catalog"]["pct_security"]
    assert 8.0 <= share <= 15.0, (
        f"'about one in nine entries ... is a product sold to enforce "
        f"security' needs the catalog guard share in [8%, 15%]; data says "
        f"{share}% ({d['catalog']['security']} of {d['catalog']['total']})"
    )


def check_ransomware_roughly_twice(d: dict) -> None:
    # editorial.js (guards.html overlap): "entries on exploited security
    # products carry that flag roughly twice as often as the rest of the
    # catalog". Live-feed ratio at module creation: 37.2 / 17.9 = 2.08.
    sec = d["ransomware"]["security"]["pct_known"]
    rest = d["ransomware"]["other"]["pct_known"]
    assert rest > 0, "ratio claim needs a nonzero rest-of-catalog share"
    ratio = sec / rest
    assert 1.6 <= ratio <= 2.6, (
        f"'roughly twice as often as the rest of the catalog' needs the "
        f"security/rest ransomware-flag ratio in [1.6, 2.6]; data says "
        f"{sec}% vs {rest}% (ratio {ratio:.2f})"
    )


# --------------------------------------------------------------------------
CLAIMS = [
    (
        "about one in nine entries in the whole catalog is a product sold to enforce security",
        "kev_guards.json",
        check_one_in_nine_guard_share,
    ),
    (
        "entries on exploited security products carry that flag roughly twice as often as the rest of the catalog",
        "kev_guards.json",
        check_ransomware_roughly_twice,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
