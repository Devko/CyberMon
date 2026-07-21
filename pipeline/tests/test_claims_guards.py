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
    # editorial.js (guards.html hero): "more than one entry in nine in the
    # whole catalog is in a product sold to enforce security — and recent
    # years run well above that". Live value at last copy edit: 11.8%.
    # "More than one in nine" needs share > 11.1%, with headroom above.
    share = d["catalog"]["pct_security"]
    assert 11.2 <= share <= 20.0, (
        f"'more than one entry in nine ... is in a product sold to enforce "
        f"security' needs the catalog guard share in [11.2%, 20%]; data says "
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
def check_recent_years_above_catalog_share(d: dict) -> None:
    # editorial.js (guards hero): "More than one entry in nine in the whole
    # catalog is in a product sold to enforce security — and recent years
    # run well above that." Both of the last two complete years must beat
    # the whole-catalog share.
    catalog_pct = d["catalog"]["pct_security"]
    gen_year = int(d["generated_at"][:4])
    complete = [y for y in d["years"] if y["year"] < gen_year]
    for y in complete[-2:]:
        assert y["pct_security"] > catalog_pct, (
            f"'recent years run well above that' vs {y['year']} at "
            f"{y['pct_security']}% against catalog {catalog_pct}%"
        )


CLAIMS = [
    (
        "and recent years run well above that",
        "kev_guards.json",
        check_recent_years_above_catalog_share,
    ),
    (
        "more than one entry in nine in the whole catalog is in a product sold to enforce security",
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
