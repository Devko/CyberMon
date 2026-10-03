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

from . import claims_support

# Resolve site/data/ relative to this file so the audit works from any cwd.
DATA_DIR = claims_support.DATA_DIR

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
    return claims_support.read_json(path)


# --------------------------------------------------------------------------
# Claim checks. Assertion messages restate the claim so a failure reads as
# "this sentence is no longer true", not as a raw number.
# --------------------------------------------------------------------------


def check_one_in_nine_guard_share(d: dict) -> None:
    # editorial.js (guards.html hero headline + home card): "More than one
    # KEV entry in nine is in a security product" / "More than one in nine
    # KEV entries is in a security product". 2026-10-03: 12.3% (213 of
    # 1,733); 11.9-12.3% since late August. "More than one in nine" needs
    # share > 11.1%, with headroom above.
    share = d["catalog"]["pct_security"]
    assert 11.2 <= share <= 20.0, (
        f"'more than one entry in nine ... is in a product sold to enforce "
        f"security' needs the catalog guard share in [11.2%, 20%]; data says "
        f"{share}% ({d['catalog']['security']} of {d['catalog']['total']})"
    )


def check_ransomware_roughly_twice(d: dict) -> None:
    # editorial.js (guards.html overlap headline + caption): "about twice as
    # often" / "roughly twice as often as the rest of the catalog". Ratio at
    # module creation: 37.2 / 17.9 = 2.08; 2026-10-03: 37.1 / 18.6 = 1.99
    # (2.01-2.07 since late August). Band narrowed from 1.6-2.6 to 1.7-2.3
    # on 2026-10-03: 1.6 reads as "about one and a half times".
    sec = d["ransomware"]["security"]["pct_known"]
    rest = d["ransomware"]["other"]["pct_known"]
    assert rest > 0, "ratio claim needs a nonzero rest-of-catalog share"
    ratio = sec / rest
    assert 1.7 <= ratio <= 2.3, (
        f"'roughly twice as often as the rest of the catalog' needs the "
        f"security/rest ransomware-flag ratio in [1.7, 2.3]; data says "
        f"{sec}% vs {rest}% (ratio {ratio:.2f})"
    )


# --------------------------------------------------------------------------
def check_last_two_complete_years_above_catalog_share(d: dict) -> None:
    # editorial.js (guards hero caption): "The stat gives the catalog-wide
    # share, and each of the last two complete years was above it." It
    # said "recent years run well above that" until 2026-10-03, which the
    # guard (strictly above) did not measure. 2026-10-03: 2024 17.2% and
    # 2025 15.1% against 12.3% catalog-wide; after the rollover 2025 and
    # 2026 (17.3% so far).
    catalog_pct = d["catalog"]["pct_security"]
    complete = claims_support.complete_years(d["years"])
    assert len(complete) >= 2, complete
    for y in complete[-2:]:
        assert y["pct_security"] > catalog_pct, (
            f"'each of the last two complete years was above it' vs "
            f"{y['year']} at {y['pct_security']}% against catalog "
            f"{catalog_pct}%"
        )


def check_top_security_vendors_gap_days_to_weeks(d: dict) -> None:
    # editorial.js (guards.html recidivism headline + caption): "For the
    # five most-listed security vendors, the median gap between KEV
    # listings is days to weeks." A security vendor is a flagged row (at
    # least half its entries security products, the board's own rule);
    # "days to weeks" is read as at most 60 days. 2026-10-03: Ivanti 7.5,
    # Fortinet 42, Citrix 10, SonicWall 20, Palo Alto Networks 32.5 (F5 at
    # 112 and Sophos at 159 sit further down the board).
    flagged = [v for v in d["vendors"] if v["pct_security"] >= 50]
    top = sorted(flagged, key=lambda v: -v["entries"])[:5]
    assert len(top) == 5, [v["vendor"] for v in flagged]
    slow = [(v["vendor"], v["median_gap_days"]) for v in top
            if v["median_gap_days"] is None or v["median_gap_days"] > 60]
    assert not slow, (
        f"'the median gap between KEV listings is days to weeks' for the "
        f"five most-listed security vendors; these exceed 60 days: {slow}"
    )


CLAIMS = [
    (
        "and each of the last two complete years was above it",
        "kev_guards.json",
        check_last_two_complete_years_above_catalog_share,
    ),
    (
        "More than one KEV entry in nine is in a security product",
        "kev_guards.json",
        check_one_in_nine_guard_share,
    ),
    (
        "More than one in nine KEV entries is in a security product.",
        "kev_guards.json",
        check_one_in_nine_guard_share,
    ),
    (
        "For the five most-listed security vendors, the median gap between KEV listings is days to weeks.",
        "kev_guards.json",
        check_top_security_vendors_gap_days_to_weeks,
    ),
    (
        "for the five most-listed of those, the median gap is days to weeks",
        "kev_guards.json",
        check_top_security_vendors_gap_days_to_weeks,
    ),
    (
        "entries on exploited security products carry that flag roughly twice as often as the rest of the catalog",
        "kev_guards.json",
        check_ransomware_roughly_twice,
    ),
    (
        "KEV entries in security products carry the ransomware flag about twice as often.",
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
