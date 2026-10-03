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
    # editorial.js (credits.html hero headline): "AI finders announce
    # thousands of vulnerabilities, and CVE records credit each kind with
    # hundreds." / (home card): "AI finders announce thousands of
    # vulnerabilities; CVE records credit labs and vendors with hundreds
    # each." Each kind is judged alone, never the two summed (795 summed on
    # 2026-10-03, past 1,000 within weeks). Only announcements counted in
    # vulnerabilities or CVEs speak to "thousands of vulnerabilities"; XBOW's
    # 1,060 HackerOne submissions do not. (2026-10-03: largest 10,000,
    # Anthropic with its Glasswing partners; labs 257, vendors 538.)
    biggest = max((c["value"] for c in d["claims"]
                   if c["unit_kind"] in ("vulnerabilities", "cves")),
                  default=0)
    assert biggest >= 2000, (
        f"'announce thousands of vulnerabilities' needs a committed "
        f"first-party count of at least 2,000 vulnerabilities or CVEs; the "
        f"largest is {biggest}"
    )
    for kind in ("llm", "vendor"):
        n = d["kinds"][kind]["funnel"]["credited"]
        assert 100 <= n < 1000, (
            f"'credit labs and vendors with hundreds each' needs each kind's "
            f"credited count in 100–999; {kind} has {n}"
        )


def check_four_or_five_in_ten_vendor_credits_name_a_person(d: dict) -> None:
    # editorial.js (credits.html 01): "four or five in ten vendor credits
    # name the company only through a person there or in a thank-you line" —
    # the org tier, i.e. a share that rounds to four or five tenths: 35–55%.
    # Was "about four in ten" (33–48%) until 2026-10-03, when the share had
    # risen from 42.9% (09-23) to 44.8% and kept climbing: AISLE, the
    # largest vendor row, is about 79% org tier. (The first draft said
    # "most"; this guard is what caught it — 57% were system tier.)
    rows = [r for r in d["board"] if r["kind"] == "vendor"]
    counted = sum(r["counted"] for r in rows)
    person = counted - sum(min(r["system"], r["counted"]) for r in rows)
    pct = 100.0 * person / counted
    assert 35.0 <= pct < 55.0, (
        f"'four or five in ten vendor credits name a person' needs 35–55%; "
        f"it is {pct:.1f}% ({person}/{counted})"
    )


# ------------------------------------------------------------ 02 · profile

def check_lab_median_cvss_higher(d: dict) -> None:
    # editorial.js (credits.html 02 headline): "Lab-credited CVEs have a
    # higher median CVSS score than all credited CVEs." Higher by at least
    # half a point, so a rounding wobble is not a finding. (2026-10-03: 7.8
    # vs 6.9; 7.7–7.8 vs 6.8–6.9 since 09-23.) Replaced "higher CVSS scores
    # and similar EPSS, exploit and KEV figures": the lab exploit-corpus
    # rate is a quarter of the baseline's (0.4% vs 1.6%).
    llm, base = d["profile"]["llm"], d["profile"]["baseline"]
    assert llm["median_cvss"] >= base["median_cvss"] + 0.5, (
        f"'a higher median CVSS score' needs the lab median CVSS 0.5+ over "
        f"the baseline; {llm['median_cvss']} vs {base['median_cvss']}"
    )


def check_lab_credited_score_higher_and_more_memory(d: dict) -> None:
    # editorial.js (credits.html 02): "a higher median CVSS score and a much
    # larger share of memory-safety weaknesses" (2026-10-03: 40.1% vs 9.2%)
    check_lab_median_cvss_higher(d)
    llm, base = d["profile"]["llm"], d["profile"]["baseline"]
    assert llm["memory_pct"] >= 2.5 * base["memory_pct"], (
        f"'a much larger share of memory-safety weaknesses' needs 2.5x the "
        f"baseline; {llm['memory_pct']}% vs {base['memory_pct']}%"
    )


def _at_baseline_rate(d: dict, kind: str, stage: str) -> tuple[int, float]:
    """(observed, expected) records at ``stage`` for ``kind``, expected being
    what the baseline rate gives a population the kind's size."""
    base, f = d["baseline"], d["kinds"][kind]["funnel"]
    return f[stage], f["credited"] * base[stage] / base["credited"]


def check_epss_medians_within_ten_points(d: dict) -> None:
    # editorial.js (credits.html 02): "Median EPSS percentile is within ten
    # points of the baseline in both AI columns." Was "close to the
    # baseline" (within 5) until 2026-10-03: EPSS rescoring moved the vendor
    # gap from 2.0 to 4.9 in a week and the lab gap swung -1.5 → 4.5 → -1.5.
    # (2026-10-03: labs 26.4, vendors 32.4, baseline 27.9 — gaps 1.5 and
    # 4.5; the largest gap since 09-20 is 4.9.)
    for kind in ("llm", "vendor"):
        gap = abs(d["profile"][kind]["median_epss_pctile"]
                  - d["profile"]["baseline"]["median_epss_pctile"])
        assert gap <= 10.0, (
            f"'Median EPSS percentile is within ten points of the baseline' "
            f"fails for {kind}: {gap:.1f} points away"
        )


def check_kev_within_a_handful_of_records(d: dict) -> None:
    # editorial.js (credits.html 02): "On KEV membership, each AI column is
    # within a handful of records of what the baseline rate would give a
    # population its size." (2026-10-03: labs 0 vs 0.3, vendors 3 vs 0.7.)
    # The exploit-corpus rows left this claim: vendors on 2026-09-30 (15 vs
    # 8.5), labs on 2026-10-03 (1 vs 4.0, and 7+ expected by ~445 lab CVEs).
    for kind in ("llm", "vendor"):
        observed, expected = _at_baseline_rate(d, kind, "kev")
        assert abs(observed - expected) <= 6, (
            f"'within a handful of records' fails for {kind} kev: "
            f"{observed} observed vs {expected:.1f} at the baseline rate"
        )


def check_lab_exploit_corpus_below_baseline_rate(d: dict) -> None:
    # editorial.js (credits.html 02): "On exploit-corpus listing, the lab
    # column has fewer records than that rate would give" (2026-10-03: 1 vs
    # 4.0; 1 vs 3.2–3.3 since 09-23). Holds as batches of unlisted lab CVEs
    # arrive, which is how "within a handful" would have failed; it fails
    # if lab CVEs are listed at the baseline rate (4 more listings today).
    observed, expected = _at_baseline_rate(d, "llm", "poc")
    assert observed < expected, (
        f"'the lab column has fewer records than that rate would give' "
        f"fails: {observed} observed vs {expected:.1f} at the baseline rate"
    )


def check_vendor_exploit_corpus_above_baseline_rate(d: dict) -> None:
    # editorial.js (credits.html 02): "and the vendor column has more"
    # records in an exploit corpus than the baseline rate would give.
    # (2026-09-29: 13 vs 8.5; 2026-10-03: 15 vs 8.5.)
    observed, expected = _at_baseline_rate(d, "vendor", "poc")
    assert observed > expected, (
        f"'the vendor column has more' exploit-corpus records than the "
        f"baseline rate gives fails: {observed} observed vs {expected:.1f}"
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
    # editorial.js (credits.html 02 methodology): "The AI columns are small:
    # one CVE moves the labs' exploit-corpus row by half a point or less." /
    # "all three medians are well under 50". One CVE is 100/n points; the
    # row prints one decimal, so 199 lab CVEs (0.503, shown 0.5) still read
    # as half a point. "Small" holds while each AI column is under 1,000
    # CVEs (a tenth of a point or more each). Was "about half a point"
    # (150–280 CVEs) until 2026-10-03. (2026-10-03: 257 lab CVEs, 0.39
    # points; 538 vendor CVEs.)
    n = d["profile"]["llm"]["n"]
    assert round(100.0 / n, 1) <= 0.5, (
        f"'half a point or less' needs 100/n to round to 0.5 or less; "
        f"{n} lab CVEs give {100.0 / n:.2f} points"
    )
    sizes = {k: d["profile"][k]["n"] for k in ("llm", "vendor")}
    assert all(s < 1000 for s in sizes.values()), (
        f"'The AI columns are small' needs each under 1,000 CVEs; {sizes}"
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
    # editorial.js (credits.html 04 headline): "In each column one or two
    # finders hold most of the credits" — judged per kind, never summed
    # across labs and vendors (the two kinds count by different rules).
    # (2026-09-23: Anthropic 159 of 199 lab credits; AISLE + ZAST.AI 383 of
    # 508 vendor-credited CVEs.)
    for kind in ("llm", "vendor"):
        counted = sorted((r["counted"] for r in d["board"]
                          if r["kind"] == kind), reverse=True)
        total = d["kinds"][kind]["funnel"]["credited"] \
            if "funnel" in d["kinds"][kind] else sum(counted)
        top2 = sum(counted[:2])
        assert total and 100.0 * top2 / total > 50.0, (
            f"{kind}: 'one or two finders hold most of the credits' needs "
            f"the top two over half; {counted[:4]} of {total}")


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
    # records than its models are"
    r = _finder(d, "openai")
    assert r["cves"] >= 3 * r["counted"], (
        f"'named on several times more records than its models are' needs OpenAI's "
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


def check_vendors_between_on_injection_above_baseline_on_memory(
        d: dict) -> None:
    # editorial.js (credits.html 05): "The vendor-credited population falls
    # between the two on injection and has a larger memory-safety share than
    # the baseline." (2026-10-03: injection labs 4.3%, vendors 27.9%,
    # baseline 37.9%; memory vendors 25.3% vs baseline 9.2%.) Until
    # 2026-10-03 it fell "between the two on both": the lab memory share
    # fell 45.2% → 40.1% while the vendor share rose 23.0% → 25.3% (09-23 to
    # 10-03), and about 150 more non-memory lab CVEs would have crossed them.
    f = _family(d, "injection")
    lo, hi = sorted((f["llm"]["pct"], f["baseline"]["pct"]))
    assert lo <= f["vendor"]["pct"] <= hi, (
        f"'falls between the two on injection' fails: labs "
        f"{f['llm']['pct']}%, vendors {f['vendor']['pct']}%, baseline "
        f"{f['baseline']['pct']}%"
    )
    m = _family(d, "memory")
    assert m["vendor"]["pct"] > m["baseline"]["pct"], (
        f"'a larger memory-safety share than the baseline' fails: vendors "
        f"{m['vendor']['pct']}%, baseline {m['baseline']['pct']}%"
    )


# ------------------------------------------------------------ 06 · targets

def check_lab_list_more_concentrated(d: dict) -> None:
    # editorial.js (credits.html 06 headline): "Lab-credited CVEs are more
    # concentrated by affected product than vendor-credited CVEs." The
    # caption's measure: the share the top five rows hold. (2026-10-03: labs
    # 42.0%, vendors 26.6%; 46.3–47.7% vs 26.2–27.0% from 09-23 to 09-29.)
    # Two batches of 50 lab CVEs spread over products outside the top five
    # would take the lab share to about 30%, still above.
    # Replaced on 2026-10-03, the day it was written: "Two products account
    # for about a quarter" (24.6%, floor 20%, gone at ~316 lab CVEs).
    lab, vendor = d["targets"]["llm"], d["targets"]["vendor"]
    assert lab["top_share_n"] == vendor["top_share_n"], (
        f"the comparison needs the same top-N for both kinds; "
        f"{lab['top_share_n']} vs {vendor['top_share_n']}"
    )
    assert lab["top_share_pct"] > vendor["top_share_pct"], (
        f"'more concentrated by affected product' needs the lab top-"
        f"{lab['top_share_n']} share above the vendor one; "
        f"{lab['top_share_pct']}% vs {vendor['top_share_pct']}%"
    )


def check_bc_java_and_firefox_in_lab_top_five(d: dict) -> None:
    # editorial.js (credits.html 06): "Bouncy Castle's Java crypto library
    # and the Firefox browser are both in the top five" (2026-10-03: first
    # and second, 32 and 31 CVEs; the fifth row has 13). Replaced "a Java
    # crypto library and a browser lead the list, each well ahead of the
    # third row": Bouncy Castle's C# edition arrived at 18 in one batch, and
    # the order of the leading rows can change with the next one.
    t = d["targets"]["llm"]
    top = [p["label"].lower() for p in t["projects"][:5]]
    assert any("bouncy castle" in lab and "bc-java" in lab for lab in top) \
        and any("firefox" in lab for lab in top), (
            f"'Bouncy Castle's Java crypto library and the Firefox browser "
            f"are both in the top five' — the top five are now {top}"
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

# A current year joins the coverage judgement once it has this many
# published records (about six weeks of 2026's volume): a few days of
# January can put its share anywhere.
COVERAGE_MIN_PUBLISHED = 10_000


def check_fewer_than_half_carry_a_credit(d: dict) -> None:
    # editorial.js (credits.html 07): "Fewer than half of published CVEs
    # carry any credit." / "risen from almost none in 2018 to more than four
    # in ten" — the two latest judged years. (2026-10-03: 2025 47.2%, 2026
    # 42.8% of 73,605 so far.)
    rows = {c["year"]: c for c in d["coverage"]}
    assert rows.get(2018, {}).get("pct", 100.0) < 3.0, (
        f"'almost none in 2018' needs the 2018 share under 3%; it is "
        f"{rows.get(2018, {}).get('pct')}"
    )
    judged = [y for y in sorted(rows) if claims_support.judged(
        y, rows[y]["published"], min_n=COVERAGE_MIN_PUBLISHED)]
    latest = {y: rows[y]["pct"] for y in judged[-2:]}
    assert len(latest) == 2 and all(
        40.0 < p < 50.0 for p in latest.values()), (
        f"'Fewer than half' / 'more than four in ten' needs the two latest "
        f"judged years in 40–50%; they are {latest}"
    )


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    ("AI finders announce thousands of vulnerabilities, and CVE records "
     "credit each kind with hundreds.",
     "ai_credits.json", check_thousands_announced_hundreds_credited),
    ("AI finders announce thousands of vulnerabilities; CVE records credit "
     "labs and vendors with hundreds each.",
     "ai_credits.json", check_thousands_announced_hundreds_credited),
    ("four or five in ten vendor credits name the company only through a "
     "person there or in a thank-you line",
     "ai_credits.json", check_four_or_five_in_ten_vendor_credits_name_a_person),
    ("Lab-credited CVEs have a higher median CVSS score than all credited "
     "CVEs.",
     "ai_credits.json", check_lab_median_cvss_higher),
    ("a higher median CVSS score and a much larger share of memory-safety "
     "weaknesses",
     "ai_credits.json", check_lab_credited_score_higher_and_more_memory),
    ("Median EPSS percentile is within ten points of the baseline in both AI "
     "columns.",
     "ai_credits.json", check_epss_medians_within_ten_points),
    ("On KEV membership, each AI column is within a handful of records of "
     "what the baseline rate would give a population its size.",
     "ai_credits.json", check_kev_within_a_handful_of_records),
    ("On exploit-corpus listing, the lab column has fewer records than that "
     "rate would give and the vendor column has more.",
     "ai_credits.json", check_lab_exploit_corpus_below_baseline_rate),
    ("On exploit-corpus listing, the lab column has fewer records than that "
     "rate would give and the vendor column has more.",
     "ai_credits.json", check_vendor_exploit_corpus_above_baseline_rate),
    ("the lab-credited cohort is much younger than the baseline",
     "ai_credits.json", check_lab_cohort_much_younger),
    ("they are under two percent of it",
     "ai_credits.json", check_ai_credited_under_two_percent_of_baseline),
    ("The AI columns are small: one CVE moves the labs' exploit-corpus row "
     "by half a point or less.",
     "ai_credits.json", check_small_columns_and_low_epss_medians),
    ("The registry matches one credit before 2025.",
     "ai_credits.json", check_one_counted_credit_before_2025),
    ("single-month clusters with empty months between them, and appear in "
     "every month from February 2026",
     "ai_credits.json", check_lab_clusters_then_every_month),
    ("Vendor credits begin in March 2025.",
     "ai_credits.json", check_vendor_credits_begin_march_2025),
    ("In each column one or two finders hold most of the credits",
     "ai_credits.json", check_three_finders_hold_most_credits),
    ("ZAST.AI's credits are almost all medium-severity records published "
     "through one CNA",
     "ai_credits.json", check_zast_mostly_medium_one_cna),
    ("Anthropic's row has the most criticals.",
     "ai_credits.json", check_anthropic_has_most_criticals),
    ("for several vendors that is a minority or none",
     "ai_credits.json", check_several_vendors_name_a_person),
    ("OpenAI is named on several times more records than its models are",
     "ai_credits.json", check_openai_named_far_more_than_codex),
    ("records that credit it only for the fix",
     "ai_credits.json", check_fix_credits_exist_and_never_count),
    ("injection (cross-site scripting, SQL injection, command injection) is the largest family, at more than a third",
     "ai_credits.json", check_baseline_largest_family_is_injection),
    ("crypto and certificate weaknesses are also several times the baseline "
     "share, and injection is small",
     "ai_credits.json", check_lab_memory_and_crypto_several_times_baseline),
    ("The vendor-credited population falls between the two on injection and "
     "has a larger memory-safety share than the baseline.",
     "ai_credits.json",
     check_vendors_between_on_injection_above_baseline_on_memory),
    ("Lab-credited CVEs are more concentrated by affected product than "
     "vendor-credited CVEs.",
     "ai_credits.json", check_lab_list_more_concentrated),
    ("Bouncy Castle's Java crypto library and the Firefox browser are both in "
     "the top five.",
     "ai_credits.json", check_bc_java_and_firefox_in_lab_top_five),
    ("with its top five holding about a quarter",
     "ai_credits.json", check_vendor_top_five_a_quarter_red_hat_first),
    ("Fewer than half of published CVEs carry any credit.",
     "ai_credits.json", check_fewer_than_half_carry_a_credit),
    ("It has risen from almost none in 2018 to more than four in ten.",
     "ai_credits.json", check_fewer_than_half_carry_a_credit),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
