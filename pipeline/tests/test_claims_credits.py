"""Claims audit for the AI Credits module (pattern: test_claims_naming.py).

The credits.html copy (site/js/editorial.js) makes verbal claims about
numbers in site/data/ai_credits.json, which refreshes nightly and — unlike
most of this site's series — is growing fast: the counts roughly doubled
between July and September 2026. Each CLAIMS entry quotes the copy verbatim
(grep for it in editorial.js) and asserts the underlying number still sits
in a range where the sentence stays true. Ranges are tolerant of normal
nightly drift; several WILL eventually trip as the record grows (the
headline's "a few hundred" first), and that is the design.

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


def _finder(d: dict, key: str) -> dict:
    row = next((r for r in d["board"] if r["key"] == key), None)
    assert row is not None, f"the copy names {key!r} but the board has no row"
    return row


def check_thousands_claimed_a_few_hundred_credited(d: dict) -> None:
    # editorial.js (credits.html hero headline + home card): "AI finds
    # thousands of bugs. The CVE record credits a few hundred."
    biggest = max(c["value"] for c in d["claims"])
    assert biggest >= 2000, (
        f"'AI finds thousands of bugs' needs a committed first-party claim "
        f"of at least 2,000; the largest is {biggest}"
    )
    for kind in ("llm", "vendor"):
        n = d["kinds"][kind]["funnel"]["credited"]
        assert 100 <= n < 1000, (
            f"'The CVE record credits a few hundred' needs each kind's "
            f"credited count in 100–999; {kind} has {n}"
        )


def check_no_ai_finder_before_2025(d: dict) -> None:
    # editorial.js (credits.html 02 headline): "Before 2025 the record names
    # no AI finder at all."
    firsts = [r["first_month"] for r in d["board"]]
    assert firsts and min(firsts) >= "2025-01", (
        f"'Before 2025 the record names no AI finder at all' needs every "
        f"board row's first credit in 2025 or later; earliest is "
        f"{min(firsts) if firsts else None}"
    )


def check_lab_credits_bursts_then_stream(d: dict) -> None:
    # editorial.js (credits.html 02): "began as isolated bursts" ... "before
    # turning into a monthly stream during 2026"
    months = d["kinds"]["llm"]["months"]
    early = [m for m in months if m["month"] < "2026-02"]
    assert any(m["total"] == 0 for m in early) and \
        any(m["total"] >= 10 for m in early), (
            "'began as isolated bursts' needs an early lab month of 10+ "
            "CVEs with empty months around it"
        )
    complete_2026 = [m for m in months[:-1] if m["month"] >= "2026-02"]
    assert complete_2026 and all(m["total"] > 0 for m in complete_2026), (
        "'turning into a monthly stream during 2026' needs every complete "
        "lab month since 2026-02 to be non-empty"
    )


def check_vendors_started_earlier(d: dict) -> None:
    # editorial.js (credits.html 02): "Vendor credits started earlier"
    llm = d["kinds"]["llm"]["headline"]["first_month"]
    vendor = d["kinds"]["vendor"]["headline"]["first_month"]
    assert vendor < llm, (
        f"'Vendor credits started earlier' needs the vendor first month "
        f"({vendor}) before the lab first month ({llm})"
    )


def check_three_finders_lead(d: dict) -> None:
    # editorial.js (credits.html 03 headline): "Three finders lead the count."
    counted = [r["counted"] for r in d["board"]]
    assert len(counted) >= 4 and counted[2] >= 2 * counted[3], (
        f"'Three finders lead the count' needs the third row to be at "
        f"least double the fourth; the top four are {counted[:4]}"
    )


def check_zast_mostly_medium_one_cna(d: dict) -> None:
    # editorial.js (credits.html 03): "ZAST.AI's list is almost entirely
    # medium-severity findings filed through a single CNA"
    r = _finder(d, "zast")
    medium = 100.0 * r["severity"]["medium"] / r["counted"]
    top_cna = 100.0 * r["top_cnas"][0]["n"] / r["cves"]
    assert medium >= 85.0 and top_cna >= 80.0, (
        f"'almost entirely medium-severity findings filed through a single "
        f"CNA' needs ZAST.AI at >=85% medium and >=80% one CNA; it is "
        f"{medium:.1f}% medium, {top_cna:.1f}% via {r['top_cnas'][0]['cna']}"
    )


def check_anthropic_holds_most_criticals(d: dict) -> None:
    # editorial.js (credits.html 03): "Anthropic's row holds the most
    # criticals on the board"
    best = max(d["board"], key=lambda r: r["severity"]["critical"])
    assert best["key"] == "anthropic", (
        f"'Anthropic's row holds the most criticals on the board' — the "
        f"most criticals now belong to {best['label']} "
        f"({best['severity']['critical']})"
    )


def check_openai_named_far_more_than_codex(d: dict) -> None:
    # editorial.js (credits.html 03): "it cuts deepest for OpenAI, whose
    # security team is credited far more often than Codex is"
    named_only = {r["key"]: r["cves"] - r["counted"] for r in d["board"]
                  if r["kind"] == "llm"}
    r = _finder(d, "openai")
    assert max(named_only, key=named_only.get) == "openai" and \
        named_only["openai"] >= 3 * r["counted"], (
            f"'cuts deepest for OpenAI … credited far more often than Codex "
            f"is' needs OpenAI's named-only count to lead the labs and be "
            f">=3x its counted CVEs; named-only {named_only}, counted "
            f"{r['counted']}"
        )


def check_coverage_floor(d: dict) -> None:
    # editorial.js (credits.html 04): "Most CVEs thank no one." and "climbed
    # from almost nothing in 2018 to better than four in ten"
    by_year = {c["year"]: c["pct"] for c in d["coverage"]}
    assert by_year.get(2018, 100.0) < 3.0, (
        f"'almost nothing in 2018' needs the 2018 share under 3%; it is "
        f"{by_year.get(2018)}"
    )
    latest = [by_year[y] for y in sorted(by_year)[-2:]]
    assert all(40.0 <= p < 50.0 for p in latest), (
        f"'better than four in ten' / 'Most CVEs thank no one' needs the "
        f"two latest years in 40–50%; they are {latest}"
    )


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "AI finds thousands of bugs. The CVE record credits a few hundred.",
        "ai_credits.json",
        check_thousands_claimed_a_few_hundred_credited,
    ),
    (
        "Before 2025 the record names no AI finder at all.",
        "ai_credits.json",
        check_no_ai_finder_before_2025,
    ),
    (
        "turning into a monthly stream during 2026",
        "ai_credits.json",
        check_lab_credits_bursts_then_stream,
    ),
    (
        "Vendor credits started earlier",
        "ai_credits.json",
        check_vendors_started_earlier,
    ),
    (
        "Three finders lead the count.",
        "ai_credits.json",
        check_three_finders_lead,
    ),
    (
        "almost entirely medium-severity findings filed through a single CNA",
        "ai_credits.json",
        check_zast_mostly_medium_one_cna,
    ),
    (
        "Anthropic's row holds the most criticals on the board",
        "ai_credits.json",
        check_anthropic_holds_most_criticals,
    ),
    (
        "security team is credited far more often than Codex is",
        "ai_credits.json",
        check_openai_named_far_more_than_codex,
    ),
    (
        "climbed from almost nothing in 2018 to better than four in ten",
        "ai_credits.json",
        check_coverage_floor,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
