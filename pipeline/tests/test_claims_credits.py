"""Claims audit for the AI Credits module (pattern: test_claims_naming.py).

The credits.html copy (site/js/editorial.js) makes verbal claims about
numbers in site/data/ai_credits.json and ai_credits_ledger.json, which
refresh nightly and — unlike most of this site's series — grow fast: the
counts roughly doubled between July and September 2026. Each CLAIMS entry
quotes the copy verbatim (grep for it in editorial.js) and asserts the
underlying number still sits in a range where the sentence stays true.
Ranges are tolerant of normal nightly drift; several WILL eventually trip as
the record grows (the headline's "Hundreds credited" first), by design.

The copy was rewritten on 2026-09-20 after an external review: it now
describes attribution ("credited"), never discovery, and states what was
measured rather than why. Keep new claims to that standard — a sentence the
data cannot check does not belong on the page.

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


def _family(d: dict, key: str) -> dict:
    return next(f for f in d["weaknesses"]["families"] if f["key"] == key)


def _person_led_vendors(d: dict) -> list[str]:
    """Sizeable vendor rows whose credits mostly name a person, not the
    tool (system-tier matches are under half of what counts)."""
    return [r["label"] for r in d["board"] if r["kind"] == "vendor"
            and r["counted"] >= 5 and r["system"] < r["counted"] / 2]


# ------------------------------------------------------------- 01 · funnel

def check_thousands_announced_hundreds_credited(d: dict) -> None:
    # editorial.js (credits.html hero headline + home card): "Thousands
    # announced. Hundreds credited in CVE records."
    biggest = max(c["value"] for c in d["claims"])
    assert biggest >= 2000, (
        f"'Thousands announced' needs a committed first-party claim "
        f"of at least 2,000; the largest is {biggest}"
    )
    for kind in ("llm", "vendor"):
        n = d["kinds"][kind]["funnel"]["credited"]
        assert 100 <= n < 1000, (
            f"'Hundreds credited' needs each kind's credited count in "
            f"100–999; {kind} has {n}"
        )


def check_four_in_ten_vendor_credits_name_a_person(d: dict) -> None:
    # editorial.js (credits.html 01): "about four in ten vendor credits name
    # a person at the company and not the tool". (The first draft said
    # "most"; this guard is what caught it — 57% name the tool.)
    rows = [r for r in d["board"] if r["kind"] == "vendor"]
    counted = sum(r["counted"] for r in rows)
    person = counted - sum(min(r["system"], r["counted"]) for r in rows)
    pct = 100.0 * person / counted
    assert 33.0 <= pct <= 48.0, (
        f"'about four in ten vendor credits name a person' needs 33–48%; "
        f"it is {pct:.1f}% ({person}/{counted})"
    )


# ------------------------------------------------------------ 02 · profile

def check_lab_credited_score_higher_and_more_memory(d: dict) -> None:
    # editorial.js (credits.html 02): "Lab-credited CVEs score higher." /
    # "a higher median CVSS score and a much larger share of memory-safety
    # weaknesses"
    llm, base = d["profile"]["llm"], d["profile"]["baseline"]
    assert llm["median_cvss"] >= base["median_cvss"] + 0.5, (
        f"'score higher' needs the lab median CVSS 0.5+ over the baseline; "
        f"{llm['median_cvss']} vs {base['median_cvss']}"
    )
    assert llm["memory_pct"] >= 2.5 * base["memory_pct"], (
        f"'a much larger share of memory-safety weaknesses' needs 2.5x the "
        f"baseline; {llm['memory_pct']}% vs {base['memory_pct']}%"
    )


def check_exploitation_rows_within_a_handful_of_records(d: dict) -> None:
    # editorial.js (credits.html 02): "the columns barely differ" / "each AI
    # column is within a handful of records of what the baseline rate would
    # give a population its size"
    base = d["baseline"]
    for kind in ("llm", "vendor"):
        f = d["kinds"][kind]["funnel"]
        for stage in ("poc", "kev"):
            expected = f["credited"] * base[stage] / base["credited"]
            assert abs(f[stage] - expected) <= 6, (
                f"'within a handful of records' fails for {kind} {stage}: "
                f"{f[stage]} observed vs {expected:.1f} at the baseline rate"
            )
        gap = abs(d["profile"][kind]["median_epss_pctile"]
                  - d["profile"]["baseline"]["median_epss_pctile"])
        assert gap <= 5.0, (
            f"'the columns barely differ' needs the {kind} median EPSS "
            f"percentile within 5 of the baseline; it is {gap:.1f} away"
        )


def check_lab_cohort_much_younger(d: dict) -> None:
    # editorial.js (credits.html 02): "the lab-credited cohort is much
    # younger than the baseline"
    llm = d["profile"]["llm"]["recent_pct"]
    base = d["profile"]["baseline"]["recent_pct"]
    assert llm >= 1.5 * base, (
        f"'much younger than the baseline' needs the lab share published in "
        f"the last 90 days at 1.5x the baseline's; {llm}% vs {base}%"
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


def check_small_columns_and_low_epss_medians(d: dict) -> None:
    # editorial.js (credits.html 02 methodology): "one CVE moves the labs'
    # exploit-corpus row by about half a point" / "all three medians are
    # well under 50"
    n = d["profile"]["llm"]["n"]
    assert 150 <= n <= 280, (
        f"'about half a point' needs 150–280 lab CVEs (0.36–0.67 points "
        f"each); there are {n}"
    )
    medians = {k: c["median_epss_pctile"] for k, c in d["profile"].items()}
    assert all(m < 40 for m in medians.values()), (
        f"'all three medians are well under 50' needs each under 40; "
        f"{medians}"
    )


# -------------------------------------------------------------- 03 · lanes

def check_one_counted_credit_before_2025(d: dict) -> None:
    # editorial.js (credits.html 03 headline): "The registry matches one
    # credit before 2025." / "an OpenSSL CVE from October 2024 credited to
    # Google's OSS-Fuzz-Gen"
    ledger = load("ai_credits_ledger.json")
    early = [r for r in ledger["rows"]
             if r["published"] < "2025-01-01" and r["counts_for"]]
    assert [r["published"][:7] for r in early] == ["2024-10"], (
        f"'The registry matches one credit before 2025 … October 2024' — the "
        f"ledger's counted pre-2025 rows are now "
        f"{[(r['cve'], r['published']) for r in early]}"
    )
    row = early[0]
    assert row["matches"][0]["finder"] == "google" and \
        row["cna"].lower() == "openssl", (
            f"the copy says an OpenSSL CVE credited to Google's "
            f"OSS-Fuzz-Gen; the row is {row}"
        )


def check_lab_clusters_then_every_month(d: dict) -> None:
    # editorial.js (credits.html 03): "single-month clusters with empty
    # months between them, and appear in every month from February 2026"
    months = d["kinds"]["llm"]["months"]
    early = [m for m in months if m["month"] < "2026-02"]
    assert any(m["total"] == 0 for m in early) and \
        any(m["total"] >= 10 for m in early), (
            "'single-month clusters with empty months between them' needs an "
            "early lab month of 10+ CVEs and empty months before 2026-02"
        )
    complete = [m for m in months[:-1] if m["month"] >= "2026-02"]
    assert complete and all(m["total"] > 0 for m in complete), (
        "'appear in every month from February 2026' needs every complete "
        "lab month since 2026-02 to be non-empty"
    )


def check_vendor_credits_begin_march_2025(d: dict) -> None:
    # editorial.js (credits.html 03): "Vendor credits begin in March 2025."
    first = d["kinds"]["vendor"]["headline"]["first_month"]
    assert first == "2025-03", (
        f"'Vendor credits begin in March 2025' — the first vendor month is "
        f"now {first}"
    )


# -------------------------------------------------------------- 04 · board

def check_three_finders_hold_most_credits(d: dict) -> None:
    # editorial.js (credits.html 04 headline): "Three finders hold most of
    # the credits"
    counted = [r["counted"] for r in d["board"]]
    share = 100.0 * sum(counted[:3]) / sum(counted)
    assert len(counted) >= 4 and counted[2] >= 2 * counted[3] and \
        share > 50.0, (
            f"'Three finders hold most of the credits' needs the top three "
            f"over half of all counted credits and the third at least double "
            f"the fourth; top four {counted[:4]}, top-three share {share:.1f}%"
        )


def check_zast_mostly_medium_one_cna(d: dict) -> None:
    # editorial.js (credits.html 04): "ZAST.AI's credits are almost all
    # medium-severity records published through one CNA"
    r = _finder(d, "zast")
    medium = 100.0 * r["severity"]["medium"] / r["counted"]
    top_cna = 100.0 * r["top_cnas"][0]["n"] / r["cves"]
    assert medium >= 85.0 and top_cna >= 80.0, (
        f"'almost all medium-severity records published through one CNA' "
        f"needs ZAST.AI at >=85% medium and >=80% one CNA; it is "
        f"{medium:.1f}% medium, {top_cna:.1f}% via {r['top_cnas'][0]['cna']}"
    )


def check_anthropic_has_most_criticals(d: dict) -> None:
    # editorial.js (credits.html 04): "Anthropic's row has the most
    # criticals."
    best = max(d["board"], key=lambda r: r["severity"]["critical"])
    assert best["key"] == "anthropic", (
        f"'Anthropic's row has the most criticals' — the most criticals now "
        f"belong to {best['label']} ({best['severity']['critical']})"
    )


def check_several_vendors_name_a_person(d: dict) -> None:
    # editorial.js (credits.html 04): "for several vendors that is a
    # minority or none, because their credits name a person"
    person_led = _person_led_vendors(d)
    assert len(person_led) >= 3, (
        f"'for several vendors that is a minority or none' needs at least "
        f"three sizeable vendor rows; found {person_led}"
    )


def check_openai_named_far_more_than_codex(d: dict) -> None:
    # editorial.js (credits.html 04): "OpenAI is named on several times more
    # records than Codex is"
    r = _finder(d, "openai")
    assert r["cves"] >= 3 * r["counted"], (
        f"'named on several times more records than Codex is' needs OpenAI's "
        f"matched records at 3x+ its counted CVEs; {r['cves']} vs "
        f"{r['counted']}"
    )


def check_fix_credits_exist_and_never_count(d: dict) -> None:
    # editorial.js (credits.html 04): "records that credit it only for the
    # fix" — the 2026-09-20 review's correction must stay visible
    assert sum(r["fix"] for r in d["board"]) >= 1, (
        "the copy describes fix-only credits but the board records none"
    )
    for r in d["board"]:
        assert r["counted"] <= r["cves"] - r["fix"], (
            f"{r['label']}: a fix credit is being counted"
        )


# ----------------------------------------------------------- 05 · weakness

def check_baseline_largest_family_is_injection(d: dict) -> None:
    # editorial.js (credits.html 05): "The baseline's largest family is
    # injection." / "at more than a third"
    largest = max(d["weaknesses"]["families"],
                  key=lambda f: f["baseline"]["n"])
    pct = _family(d, "injection")["baseline"]["pct"]
    assert largest["key"] == "injection" and 33.4 <= pct <= 45.0, (
        f"needs injection as the baseline's largest family at 33.4–45%; "
        f"largest is {largest['key']}, injection is {pct}%"
    )


def check_lab_memory_and_crypto_several_times_baseline(d: dict) -> None:
    # editorial.js (credits.html 05): "memory safety is the largest, at
    # several times the baseline share; crypto and certificate weaknesses
    # are also several times the baseline share, and injection is small"
    largest = max(d["weaknesses"]["families"], key=lambda f: f["llm"]["n"])
    memory, crypto = _family(d, "memory"), _family(d, "crypto")
    injection = _family(d, "injection")
    m_ratio = memory["llm"]["pct"] / memory["baseline"]["pct"]
    c_ratio = crypto["llm"]["pct"] / crypto["baseline"]["pct"]
    assert largest["key"] == "memory" and m_ratio >= 2.5 and \
        c_ratio >= 2.5 and injection["llm"]["pct"] <= 10.0, (
            f"needs lab memory safety largest and 2.5x+ baseline, crypto "
            f"2.5x+, injection <=10%; largest {largest['key']}, memory "
            f"x{m_ratio:.1f}, crypto x{c_ratio:.1f}, injection "
            f"{injection['llm']['pct']}%"
        )


def check_vendors_fall_between(d: dict) -> None:
    # editorial.js (credits.html 05): "The vendor-credited population falls
    # between the two on both memory safety and injection."
    for key in ("memory", "injection"):
        f = _family(d, key)
        lo, hi = sorted((f["llm"]["pct"], f["baseline"]["pct"]))
        assert lo <= f["vendor"]["pct"] <= hi, (
            f"'falls between the two' fails on {key}: labs "
            f"{f['llm']['pct']}%, vendors {f['vendor']['pct']}%, baseline "
            f"{f['baseline']['pct']}%"
        )


# ------------------------------------------------------------ 06 · targets

def check_five_products_about_half_of_lab_cves(d: dict) -> None:
    # editorial.js (credits.html 06): "Five products account for about half
    # of the lab-credited CVEs." / "a browser, a Java crypto library and an
    # operating system lead the list"
    t = d["targets"]["llm"]
    assert t["top_share_n"] == 5 and 42.0 <= t["top_share_pct"] <= 58.0, (
        f"'about half' needs the lab top-5 share in 42–58%; it is "
        f"{t['top_share_pct']}%"
    )
    top3 = " | ".join(p["label"].lower() for p in t["projects"][:3])
    assert all(word in top3 for word in ("firefox", "bc-java", "freebsd")), (
        f"'a browser, a Java crypto library and an operating system lead the "
        f"list' — the top three are now {top3}"
    )


def check_vendor_top_five_a_quarter_red_hat_first(d: dict) -> None:
    # editorial.js (credits.html 06): "with its top five holding about a
    # quarter. Its first row is Red Hat Enterprise Linux"
    t = d["targets"]["vendor"]
    assert 20.0 <= t["top_share_pct"] <= 33.0, (
        f"'about a quarter' needs 20–33%; it is {t['top_share_pct']}%"
    )
    first = t["projects"][0]["label"]
    assert "red hat enterprise linux" in first.lower(), (
        f"'Its first row is Red Hat Enterprise Linux' — it is now {first!r}"
    )


# ----------------------------------------------------------- 07 · coverage

def check_fewer_than_half_carry_a_credit(d: dict) -> None:
    # editorial.js (credits.html 07): "Fewer than half of published CVEs
    # carry any credit." / "risen from almost nothing in 2018 to better
    # than four in ten"
    by_year = {c["year"]: c["pct"] for c in d["coverage"]}
    assert by_year.get(2018, 100.0) < 3.0, (
        f"'almost nothing in 2018' needs the 2018 share under 3%; it is "
        f"{by_year.get(2018)}"
    )
    latest = [by_year[y] for y in sorted(by_year)[-2:]]
    assert all(40.0 <= p < 50.0 for p in latest), (
        f"'Fewer than half' / 'better than four in ten' needs the two latest "
        f"years in 40–50%; they are {latest}"
    )


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    ("Thousands announced. Hundreds credited in CVE records.",
     "ai_credits.json", check_thousands_announced_hundreds_credited),
    ("about four in ten vendor credits name a person at the company and not "
     "the tool",
     "ai_credits.json", check_four_in_ten_vendor_credits_name_a_person),
    ("a higher median CVSS score and a much larger share of memory-safety "
     "weaknesses",
     "ai_credits.json", check_lab_credited_score_higher_and_more_memory),
    ("each AI column is within a handful of records of what the baseline "
     "rate would give a population its size",
     "ai_credits.json", check_exploitation_rows_within_a_handful_of_records),
    ("the lab-credited cohort is much younger than the baseline",
     "ai_credits.json", check_lab_cohort_much_younger),
    ("they are under two percent of it",
     "ai_credits.json", check_ai_credited_under_two_percent_of_baseline),
    ("moves the labs' exploit-corpus row by about half a point",
     "ai_credits.json", check_small_columns_and_low_epss_medians),
    ("The registry matches one credit before 2025.",
     "ai_credits.json", check_one_counted_credit_before_2025),
    ("single-month clusters with empty months between them, and appear in "
     "every month from February 2026",
     "ai_credits.json", check_lab_clusters_then_every_month),
    ("Vendor credits begin in March 2025.",
     "ai_credits.json", check_vendor_credits_begin_march_2025),
    ("Three finders hold most of the credits",
     "ai_credits.json", check_three_finders_hold_most_credits),
    ("ZAST.AI's credits are almost all medium-severity records published "
     "through one CNA",
     "ai_credits.json", check_zast_mostly_medium_one_cna),
    ("Anthropic's row has the most criticals.",
     "ai_credits.json", check_anthropic_has_most_criticals),
    ("for several vendors that is a minority or none",
     "ai_credits.json", check_several_vendors_name_a_person),
    ("OpenAI is named on several times more records than Codex is",
     "ai_credits.json", check_openai_named_far_more_than_codex),
    ("records that credit it only for the fix",
     "ai_credits.json", check_fix_credits_exist_and_never_count),
    ("The baseline's largest family is injection.",
     "ai_credits.json", check_baseline_largest_family_is_injection),
    ("crypto and certificate weaknesses are also several times the baseline "
     "share, and injection is small",
     "ai_credits.json", check_lab_memory_and_crypto_several_times_baseline),
    ("The vendor-credited population falls between the two on both memory "
     "safety and injection.",
     "ai_credits.json", check_vendors_fall_between),
    ("Five products account for about half of the lab-credited CVEs.",
     "ai_credits.json", check_five_products_about_half_of_lab_cves),
    ("with its top five holding about a quarter",
     "ai_credits.json", check_vendor_top_five_a_quarter_red_hat_first),
    ("Fewer than half of published CVEs carry any credit.",
     "ai_credits.json", check_fewer_than_half_carry_a_credit),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
