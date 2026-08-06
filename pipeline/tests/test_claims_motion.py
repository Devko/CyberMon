"""Claims audit for the animated social clips (pattern: test_claims_c2.py).

The clips (site/motion.html, rendered by tools/make_motion.py) carry headlines
that a viewer sees WITHOUT the surrounding page — no methodology block, no
caption, no tooltips. That makes their claims the most exposed copy the project
ships, so each one is pinned here to the committed data it asserts.

Each CLAIMS entry quotes editorial.motion.scenes.<id> verbatim (grep for it in
site/js/editorial.js) and asserts the underlying data still sits where the
sentence stays true.

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim, in the same commit) or the
pipeline broke (fix the pipeline). NEVER silence a failing claim check without
doing one of the two.

Skips itself when site/data/ holds sample data or the files are missing — this
audit only ever judges the committed real data.
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


# --- hype-race ---------------------------------------------------------------

SOURCE = "gdelt"
WINDOW = 12


def _trailing_totals(term: dict) -> list[int]:
    """Trailing WINDOW-month sums, complete windows only.

    Mirrors the arithmetic in site/js/motion/hype_race.js. If the two ever
    disagree the clip is racing different numbers than this audit checks, so
    keep them in step.
    """
    n = [p["n"] for p in term["series"][SOURCE]]
    return [sum(n[i - WINDOW + 1:i + 1]) for i in range(WINDOW - 1, len(n))]


def _race_board(d: dict) -> list[tuple[str, list[int]]]:
    terms = [t for t in d.get("terms", []) if t.get("series", {}).get(SOURCE)]
    return [(t["label"], _trailing_totals(t)) for t in terms]


def check_ransomware_led_then_lost(d: dict) -> None:
    # editorial.motion.scenes["hype-race"].headline: "Ransomware ran security's
    # news cycle. Then it didn't." — two halves, both checkable: Ransomware
    # leads the opening board, and does not lead the closing one.
    board = _race_board(d)
    assert board, "no terms with gdelt series — the race has nothing to render"

    first = sorted(board, key=lambda kv: -kv[1][0])
    last = sorted(board, key=lambda kv: -kv[1][-1])

    assert first[0][0] == "Ransomware", (
        f"'Ransomware ran security's news cycle' — but the opening board is led "
        f"by {first[0][0]} ({first[0][1][0]:,} trailing-12m mentions), not "
        f"Ransomware. Re-write the clip headline or check the collector."
    )
    assert last[0][0] != "Ransomware", (
        f"'Then it didn't' — but Ransomware still leads the closing board "
        f"({last[0][1][-1]:,} trailing-12m mentions). The headline is no longer "
        f"true; re-write it."
    )


def check_race_is_comparable(d: dict) -> None:
    # The scene races raw `n`, NOT the per-term `index`, because index is
    # normalized to each term's own peak and so compares nothing across terms.
    # Guard the field's meaning: if `index` stopped being self-relative this
    # reasoning (and the clip's footnote) would need revisiting.
    peaks = []
    for t in d.get("terms", []):
        s = t.get("series", {}).get(SOURCE) or []
        if len(s) >= WINDOW:
            peaks.append(max(p["index"] for p in s))
    assert peaks, "no gdelt series to check"
    assert all(abs(p - 100.0) < 0.05 for p in peaks), (
        "market_hype `index` is no longer each term's own-peak percentage — "
        "the clip's footnote ('raw article counts, not the site's per-term "
        "index') explains a distinction that may no longer hold."
    )


def check_all_terms_shown(d: dict) -> None:
    # meta: "All {terms} tracked terms shown" — the count is rendered from the
    # data, but the word "all" is a promise: no term with data may be dropped.
    total = len(d.get("terms", []))
    with_data = len([t for t in d.get("terms", []) if t.get("series", {}).get(SOURCE)])
    assert with_data == total, (
        f"'All {{terms}} tracked terms shown' — {total - with_data} of {total} "
        f"tracked terms have no {SOURCE} series and would be silently dropped "
        f"from the race. Either the promise or the collector needs fixing."
    )


# --- severity-flood ----------------------------------------------------------

BUCKETS = ("unscored", "low", "medium", "high", "critical")


def check_critical_is_routine(d: dict) -> None:
    # headline: "“Critical” was an exception. Now it's a product line." — the
    # early record has Critical as a rounding error; the recent record ships it
    # in the thousands.
    years = d.get("years") or []
    assert len(years) >= 10, "not enough years to judge the claim"

    gen_year = int(d["generated_at"][:4])
    complete = [y for y in years if y["year"] != gen_year]
    first, last = complete[0], complete[-1]

    assert first["critical"] < 100, (
        f"'“Critical” was an exception' — but {first['year']} already carries "
        f"{first['critical']:,} Critical records."
    )
    assert last["critical"] >= 1000, (
        f"'Now it's a product line' — but the last complete year "
        f"({last['year']}) carries only {last['critical']:,} Critical records."
    )


def check_era_caveat_holds(d: dict) -> None:
    # meta: "Left of {era}, severity lived in NVD's database, which this chart
    # does not read — the gray band is the record format, not the era."
    # The caveat is only honest if the pre-era years really are dominated by
    # unscored records.
    era = (d.get("record_era") or {}).get("year")
    assert era, "no record_era in the payload — the clip's era caveat has no anchor"

    pre = [y for y in d["years"] if y["year"] < era]
    assert pre, f"no years before the era marker ({era})"
    for y in pre:
        total = sum(y[b] for b in BUCKETS)
        if total < 50:
            continue  # the very earliest years are too thin to judge
        share = y["unscored"] / total
        assert share > 0.5, (
            f"{y['year']}: only {share:.0%} of records are unscored, but the "
            f"clip tells viewers the pre-{era} gray band is a record-format "
            f"artefact. The caveat no longer describes the data."
        )


# --- cna-concentration -------------------------------------------------------

def check_gate_did_not_widen(d: dict) -> None:
    # headline: "The gatekeepers multiplied. The gate did not." — CNA count up
    # by a lot; the top-5's share of output down, not up.
    years = d.get("years") or []
    assert len(years) >= 10, "not enough years to judge the claim"

    gen_year = int(d["generated_at"][:4])
    complete = [y for y in years if y["year"] != gen_year]
    first, last = complete[0], complete[-1]

    assert last["cna_count"] > first["cna_count"] * 10, (
        f"'The gatekeepers multiplied' — CNA count went {first['cna_count']} "
        f"({first['year']}) → {last['cna_count']} ({last['year']}), which is "
        f"not a multiplication worth the word."
    )
    assert last["top5_share"] < first["top5_share"], (
        f"'The gate did not [multiply]' — the top-5 share rose from "
        f"{first['top5_share']}% to {last['top5_share']}%, so concentration "
        f"loosened less than the headline claims, or not at all."
    )
    # Still a genuine concentration story: half the world's CVE numbering
    # remains with five organizations.
    assert last["top5_share"] >= 40.0, (
        f"the top-5 now issue only {last['top5_share']}% — the gate has in fact "
        f"widened, and 'The gate did not' is no longer the story."
    )


CLAIMS = [
    ("Ransomware ran security's news cycle. Then it didn't.",
     "market_hype.json", check_ransomware_led_then_lost),
    ("raw article counts, not the site's per-term index",
     "market_hype.json", check_race_is_comparable),
    ("All {terms} tracked terms shown",
     "market_hype.json", check_all_terms_shown),
    ("“Critical” was an exception. Now it's a product line.",
     "nine_eight_flood.json", check_critical_is_routine),
    ("severity lived in NVD's database, which this chart does not read",
     "nine_eight_flood.json", check_era_caveat_holds),
    ("The gatekeepers multiplied. The gate did not.",
     "cna_concentration.json", check_gate_did_not_widen),
]


@pytest.mark.parametrize(
    "quote,filename,check",
    CLAIMS,
    ids=[c[0][:44] for c in CLAIMS],
)
def test_motion_claim(quote: str, filename: str, check) -> None:
    check(load(filename))
