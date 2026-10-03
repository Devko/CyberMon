"""Claims audit for the Hygiene Index copy (test_claims_audit.py pattern).

Each entry quotes site/js/editorial.js verbatim and asserts the number in
site/data/dnssec_adoption.json still sits in a range where the sentence
stays true. Ranges are deliberately tolerant — nightly drift must not trip
them; only a claim becoming untrue should. Never silence a failure here:
fix the copy (and this test's quoted claim + range, in the same commit) or
fix the pipeline. Reference values, live-checked 2026-07-10: world 38.5%
now, 8.6% at the record's 2013-10 start; economy set spans 93.5% (PH) down
to 0.1% (CN). Re-guarded 2026-10-03: world 39.0% full validation (48.0%
with partial), 13.2% ten years earlier; economies 93.6% (PH) to 0.4% (CN).
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


# "About / roughly four in ten": the same band wherever the copy says it.
FOUR_IN_TEN = (35.0, 45.0)


def check_world_line(d: dict) -> None:
    # editorial.js (hygiene.html hero): "climbing from under a tenth when
    # the record starts in 2013 to roughly four in ten today"
    first = d["world"]["series"][0]
    assert first["month"].startswith("2013"), (
        f"'when the record starts in 2013' — series now starts "
        f"{first['month']}; update the copy"
    )
    assert first["validating_pc"] <= 10, (
        f"'from under a tenth' claims the 2013 start sat below 10%; "
        f"data says {first['validating_pc']}%"
    )
    check_four_in_ten_validate(d)


def check_four_in_ten_validate(d: dict) -> None:
    # editorial.js (hygiene.html hero headline, home card): "About four in
    # ten internet users are behind resolvers that validate DNSSEC" / "sit
    # behind resolvers that fully validate DNSSEC". validating_pc is APNIC's
    # full-validation rate; partial validation (a mix of validating and
    # non-validating resolvers) is partial_pc and stays out. 2026-10-03:
    # 39.0% full, 48.0% with partial, which is why the card says "fully"
    # (it used to say "fewer than half ... validating", which full plus
    # partial passes at ~1.5 points a month, around late November).
    latest = d["world"]["latest"]["validating_pc"]
    lo, hi = FOUR_IN_TEN
    assert lo <= latest <= hi, (
        f"'about four in ten' users behind fully validating resolvers "
        f"needs {lo}-{hi}%; data says {latest}%"
    )


def check_more_than_twenty_years_to_everyone(d: dict) -> None:
    # editorial.js (hygiene.html hero caption): "At the average rate of the
    # last ten years, reaching every user would take more than twenty
    # years." The rate is the stat's own comparison: newest month against
    # the baseline month ten years earlier. 2026-10-03: 13.2% (2016-09) to
    # 39.0% (2026-09) is 2.58 points a year, so the remaining 61 points
    # take 23.6 years. If the world rate keeps rising ~2.8 points a year
    # while the baseline moves to 2017-09 (12.4%), this nears twenty around
    # autumn 2027: the guard is meant to trip then, not to be widened.
    world = d["world"]
    latest = world["latest"]["validating_pc"]
    base = world["baseline"]
    newest = world["series"][-1]["month"]
    years = (int(newest[:4]) - int(base["month"][:4])
             + (int(newest[5:7]) - int(base["month"][5:7])) / 12)
    assert years > 0, (newest, base)
    rate = (latest - base["validating_pc"]) / years
    if rate <= 0:
        return  # at a flat or falling rate every user is never reached
    to_go = (100.0 - latest) / rate
    assert to_go > 20, (
        f"'reaching every user would take more than twenty years' — at "
        f"{rate:.2f} points a year since {base['month']}, the remaining "
        f"{100 - latest:.1f} points take {to_go:.1f} years"
    )


def check_giants_gap(d: dict) -> None:
    # editorial.js (hygiene.html economies): "the top of this list
    # validates for roughly nine of every ten users, the bottom for
    # almost none"
    economies = d["economies"]
    assert economies, "no economies in dnssec_adoption.json"
    top, bottom = economies[0], economies[-1]
    assert 85 <= top["latest_pc"] <= 100, (
        f"'the top of this list validates for roughly nine of every ten "
        f"users' claims ~90%; data says {top['latest_pc']}% ({top['cc']})"
    )
    assert bottom["latest_pc"] <= 5, (
        f"'the bottom for almost none' needs a near-zero laggard; "
        f"data says {bottom['latest_pc']}% ({bottom['cc']})"
    )


CLAIMS = [
    (
        "climbing from under a tenth when the record starts in 2013 to roughly four in ten today",
        "dnssec_adoption.json",
        check_world_line,
    ),
    (
        "The highest validates for roughly nine of every ten users and the lowest for almost none",
        "dnssec_adoption.json",
        check_giants_gap,
    ),
    (
        "In the ten largest economies, validation ranges from nine in ten users to almost none.",
        "dnssec_adoption.json",
        check_giants_gap,
    ),
    (
        "About four in ten internet users are behind resolvers that validate DNSSEC.",
        "dnssec_adoption.json",
        check_four_in_ten_validate,
    ),
    (
        "About four in ten internet users sit behind resolvers that fully validate DNSSEC.",
        "dnssec_adoption.json",
        check_four_in_ten_validate,
    ),
    (
        "At the average rate of the last ten years, reaching every user would take more than twenty years.",
        "dnssec_adoption.json",
        check_more_than_twenty_years_to_everyone,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
