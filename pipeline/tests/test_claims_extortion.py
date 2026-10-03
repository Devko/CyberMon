"""Claims audit for the Extortion Ledger copy (test_claims_audit.py's
pattern — see that module's docstring for the rules; short version: each
entry quotes site/js/editorial.js verbatim and asserts the committed data
still sits in a range where the sentence stays true. NEVER silence a
failing claim — fix the copy and the range together, in one commit.

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


def check_billion_dollar_floor(d: dict) -> None:
    # editorial.js (extortion.html hero): "Over a billion dollars, settled
    # in public view." The dataset is append-only crowdsourcing, so the
    # total should only grow; the ceiling guards against a unit error.
    total = d["headline"]["total_usd"]
    assert 1_000_000_000 <= total <= 10_000_000_000, (
        f"'Over a billion dollars, settled in public view' needs total "
        f"confirmed USD in [$1B, $10B]; data says ${total:,}"
    )


def check_unattributed_two_thirds(d: dict) -> None:
    # editorial.js (extortion.html families): "The single largest slice of
    # verified revenue — about two thirds — carries no family label at all"
    unattributed = d["families"]["unattributed"]["usd"]
    total = d["catalog"]["total_usd"]
    share = 100.0 * unattributed / total if total else 0.0
    assert 55 <= share <= 80, (
        f"'about two thirds ... carries no family label' claims ~67%; "
        f"data says {share:.1f}% (${unattributed:,} of ${total:,})"
    )
    top_usd = max((f["usd"] for f in d["families"]["top"]), default=0)
    assert unattributed > top_usd, (
        f"'The single largest slice' needs unattributed (${unattributed:,}) "
        f"above the top-ranked family (${top_usd:,})"
    )


# --------------------------------------------------------------------------
def check_last_verified_payment_quarter(d: dict) -> None:
    # editorial.js (extortion): "the ledger's last verified payment landed
    # in Q3 2024" — a hard date one new crowdsourced report invalidates
    # overnight. Failing here means a newer payment landed: update BOTH
    # copy occurrences (revenue caption + payments methodology).
    # The TINY rehearsals fail here by construction: they clone the latest
    # quarter (2024 Q3, paid) into the rehearsal year, which is a new
    # payment. A real new year adds no quarter: the series runs from the
    # first to the last observed payment, so only a payment can extend it.
    # The plain rehearsal passes.
    paid = [q for q in d["revenue_by_quarter"] if q["usd"] > 0]
    assert paid, "no paid quarters on the ledger at all"
    newest = (paid[-1]["year"], paid[-1]["quarter"])
    assert newest == (2024, 3), (
        f"'last verified payment landed in Q3 2024' vs newest paid quarter "
        f"{newest[0]}Q{newest[1]}"
    )


def check_payment_counts_by_era(d: dict) -> None:
    # editorial.js (extortion payments caption): "From 2016 through 2021 the
    # ledger holds hundreds to thousands of payments a year, with medians
    # between about $90 and $3,500. It holds about 150 payments for 2022
    # and about 20 for each of 2023 and 2024, with medians around $100,000
    # or higher." All named, complete years; the ledger has had no new
    # verified payment since Q3 2024. (2026-10-03, unchanged since 09-23:
    # 735–9,324 payments a year in 2016–21 with medians $92.00–$3,451.37;
    # 146 in 2022, 19 in 2023, 19 in 2024; medians $147,039, $99,389,
    # $139,534.) The old wording, "fewer than 150 a year from 2022", held
    # by four payments.
    by = {r["year"]: r for r in d["payments_by_year"]}
    early = [by[y] for y in range(2016, 2022)]
    assert all(100 <= r["payments"] < 10_000 for r in early), (
        f"'hundreds to thousands of payments a year' vs "
        f"{[(r['year'], r['payments']) for r in early]}")
    meds = [r["median_usd"] for r in early]
    assert 80 <= min(meds) <= 100 and 3_000 <= max(meds) <= 4_000, (
        f"'medians between about $90 and $3,500' vs {meds}")
    assert 125 <= by[2022]["payments"] <= 175, (
        f"'about 150 payments for 2022' vs {by[2022]['payments']}")
    for y in (2023, 2024):
        assert 15 <= by[y]["payments"] <= 25, (
            f"'about 20 for each of 2023 and 2024' vs {by[y]['payments']} "
            f"in {y}")
    late = [by[y]["median_usd"] for y in (2022, 2023, 2024)]
    assert min(late) >= 85_000, (
        f"'medians around $100,000 or higher' vs {late}")


def check_median_grew_250_fold(d: dict) -> None:
    # editorial.js (extortion payments caption): "From 2016 to 2022 the
    # median grew some 250-fold." Both years are settled history
    # ($575.54 -> $147,038.94, x255).
    by = {r["year"]: r.get("median_usd") for r in d["payments_by_year"]}
    ratio = by[2022] / by[2016]
    assert 200 <= ratio <= 320, f"'some 250-fold' vs x{ratio:.0f}"


CLAIMS = [
    (
        "From 2016 to 2022 the median grew some 250-fold.",
        "extortion_ledger.json",
        check_median_grew_250_fold,
    ),
    (
        "the ledger's last verified payment landed in Q3 2024",
        "extortion_ledger.json",
        check_last_verified_payment_quarter,
    ),
    (
        "From 2016 through 2021 the ledger holds hundreds to thousands of payments a year, "
        "with medians between about $90 and $3,500. It holds about 150 payments for 2022 "
        "and about 20 for each of 2023 and 2024, with medians around $100,000 or higher.",
        "extortion_ledger.json",
        check_payment_counts_by_era,
    ),
    (
        "Verified ransom payments on the Ransomwhere ledger total over a billion dollars.",
        "extortion_ledger.json",
        check_billion_dollar_floor,
    ),
    (
        # home card (Ransom Payments); $1,018.6M on 2026-10-03
        "Crowdsourced, blockchain-verified ransomware payments total more than a billion dollars.",
        "extortion_ledger.json",
        check_billion_dollar_floor,
    ),
    (
        "The revenue with no family label, about two thirds of the total, is larger than any family's",
        "extortion_ledger.json",
        check_unattributed_two_thirds,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
