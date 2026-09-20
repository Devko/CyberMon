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


def _family(d: dict, key: str) -> dict:
    return next(f for f in d["weaknesses"]["families"] if f["key"] == key)


def check_labs_worse_bugs_nobody_exploiting(d: dict) -> None:
    # editorial.js (credits.html 02 headline): "The labs find worse bugs.
    # Nobody is exploiting them."
    llm, base = d["kinds"]["llm"]["funnel"], d["baseline"]
    gap = llm["high_or_critical_pct"] - base["high_or_critical_pct"]
    assert gap >= 10.0 and \
        d["profile"]["llm"]["median_cvss"] > d["profile"]["baseline"]["median_cvss"], (
            f"'The labs find worse bugs' needs the lab high-or-critical share "
            f"10+ points over the baseline and a higher median CVSS; the gap "
            f"is {gap:.1f} points"
        )
    assert llm["kev"] == 0 and llm["poc_pct"] <= base["poc_pct"], (
        f"'Nobody is exploiting them' needs zero lab CVEs on KEV and a lab "
        f"exploit-code share at or under the baseline; KEV {llm['kev']}, "
        f"exploit code {llm['poc_pct']}% vs {base['poc_pct']}%"
    )


def check_attacker_interest_rows_flat_labs_quietest(d: dict) -> None:
    # editorial.js (credits.html 02): "nothing separates AI-found bugs from
    # anybody else's, and the labs' column is the quietest of the three"
    p = d["profile"]
    for kind in ("llm", "vendor"):
        gap = abs(p[kind]["median_epss_pctile"]
                  - p["baseline"]["median_epss_pctile"])
        assert gap <= 10.0, (
            f"'nothing separates AI-found bugs' needs the {kind} median EPSS "
            f"percentile within 10 of the baseline; it is {gap:.1f} away"
        )
        assert p[kind]["poc_pct"] <= 5.0 and p[kind]["kev_pct"] <= 2.0, (
            f"'nothing separates AI-found bugs' needs {kind} exploit-code and "
            f"KEV shares to stay small; they are {p[kind]['poc_pct']}% and "
            f"{p[kind]['kev_pct']}%"
        )
    for row in ("median_epss_pctile", "poc_pct", "kev_pct"):
        assert p["llm"][row] == min(c[row] for c in p.values()), (
            f"'the labs' column is the quietest of the three' fails on {row}: "
            f"{ {k: c[row] for k, c in p.items()} }"
        )


def check_labs_far_past_baseline_on_memory_safety(d: dict) -> None:
    # editorial.js (credits.html 02): "far past it on memory safety";
    # (05): "Memory-safety bugs are their largest family at several times
    # the baseline share"
    memory = _family(d, "memory")
    ratio = memory["llm"]["pct"] / memory["baseline"]["pct"]
    largest = max(d["weaknesses"]["families"], key=lambda f: f["llm"]["n"])
    assert ratio >= 2.5 and largest["key"] == "memory", (
        f"'largest family at several times the baseline share' needs lab "
        f"memory-safety at 2.5x+ the baseline and the labs' biggest family; "
        f"ratio {ratio:.1f}, largest family {largest['key']}"
    )


def check_ai_credited_under_two_percent_of_baseline(d: dict) -> None:
    # editorial.js (credits.html 02 methodology): "they are under two
    # percent of it"
    ai = sum(d["kinds"][k]["funnel"]["credited"] for k in ("llm", "vendor"))
    pct = 100.0 * ai / d["baseline"]["credited"]
    assert pct < 2.0, (
        f"'under two percent of it' needs the AI-credited CVEs under 2% of "
        f"the baseline; they are {pct:.2f}%"
    )


def check_one_cve_moves_lab_row_half_a_point(d: dict) -> None:
    # editorial.js (credits.html 02 methodology): "a single CVE moves the
    # labs' exploit-code row by half a point"
    n = d["profile"]["llm"]["n"]
    assert 150 <= n <= 280, (
        f"'a single CVE moves the labs' exploit-code row by half a point' "
        f"needs 150–280 lab CVEs (0.36–0.67 points each); there are {n}"
    )


def check_baseline_more_than_a_third_injection(d: dict) -> None:
    # editorial.js (credits.html 05): "more than a third of credited CVEs
    # are injection bugs"
    pct = _family(d, "injection")["baseline"]["pct"]
    assert 33.4 <= pct <= 45.0, (
        f"'more than a third of credited CVEs are injection bugs' needs the "
        f"baseline injection share in 33.4–45%; it is {pct}%"
    )


def check_lab_crypto_over_and_injection_gone(d: dict) -> None:
    # editorial.js (credits.html 05 headline + caption): "memory and
    # crypto"; "crypto and certificate flaws run several times over as
    # well, and injection all but disappears"
    crypto, injection = _family(d, "crypto"), _family(d, "injection")
    ratio = crypto["llm"]["pct"] / crypto["baseline"]["pct"]
    assert ratio >= 2.5 and injection["llm"]["pct"] <= 10.0, (
        f"needs lab crypto at 2.5x+ the baseline and lab injection at 10% "
        f"or less; crypto ratio {ratio:.1f}, injection "
        f"{injection['llm']['pct']}%"
    )


def check_vendors_sit_in_between(d: dict) -> None:
    # editorial.js (credits.html 05): "The vendors sit in between"
    for key in ("memory", "injection"):
        f = _family(d, key)
        lo, hi = sorted((f["llm"]["pct"], f["baseline"]["pct"]))
        assert lo <= f["vendor"]["pct"] <= hi, (
            f"'The vendors sit in between' fails on {key}: labs "
            f"{f['llm']['pct']}%, vendors {f['vendor']['pct']}%, baseline "
            f"{f['baseline']['pct']}%"
        )


def check_half_the_lab_record_is_five_projects(d: dict) -> None:
    # editorial.js (credits.html 06 headline): "Half the labs' record is
    # five projects."
    t = d["targets"]["llm"]
    assert t["top_share_n"] == 5 and 45.0 <= t["top_share_pct"] <= 65.0, (
        f"'Half the labs' record is five projects' needs the top-5 share in "
        f"45–65%; it is {t['top_share_pct']}%"
    )


def check_vendor_tail_and_distribution_first(d: dict) -> None:
    # editorial.js (credits.html 06): "its top five hold about a quarter —
    # and its first row is a distribution, not a project: when Red Hat is
    # the CNA"
    t = d["targets"]["vendor"]
    assert 20.0 <= t["top_share_pct"] <= 33.0, (
        f"'its top five hold about a quarter' needs 20–33%; it is "
        f"{t['top_share_pct']}%"
    )
    first = t["projects"][0]["label"]
    assert "red hat" in first.lower(), (
        f"'its first row is a distribution … when Red Hat is the CNA' — the "
        f"first vendor row is now {first!r}"
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
    (
        "The labs find worse bugs. Nobody is exploiting them.",
        "ai_credits.json",
        check_labs_worse_bugs_nobody_exploiting,
    ),
    (
        "nothing separates AI-found bugs from anybody else's, and the labs' "
        "column is the quietest of the three",
        "ai_credits.json",
        check_attacker_interest_rows_flat_labs_quietest,
    ),
    (
        "Memory-safety bugs are their largest family at several times the "
        "baseline share",
        "ai_credits.json",
        check_labs_far_past_baseline_on_memory_safety,
    ),
    (
        "they are under two percent of it",
        "ai_credits.json",
        check_ai_credited_under_two_percent_of_baseline,
    ),
    (
        "a single CVE moves the labs' exploit-code row by half a point",
        "ai_credits.json",
        check_one_cve_moves_lab_row_half_a_point,
    ),
    (
        "more than a third of credited CVEs are injection bugs",
        "ai_credits.json",
        check_baseline_more_than_a_third_injection,
    ),
    (
        "crypto and certificate flaws run several times over as well, and "
        "injection all but disappears",
        "ai_credits.json",
        check_lab_crypto_over_and_injection_gone,
    ),
    (
        "The vendors sit in between",
        "ai_credits.json",
        check_vendors_sit_in_between,
    ),
    (
        "Half the labs' record is five projects.",
        "ai_credits.json",
        check_half_the_lab_record_is_five_projects,
    ),
    (
        "its top five hold about a quarter",
        "ai_credits.json",
        check_vendor_tail_and_distribution_first,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
