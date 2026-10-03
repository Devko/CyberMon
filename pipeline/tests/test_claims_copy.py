"""Claims audit for the plain-language rewrite of 2026-09-23.

The site copy was rewritten that day to state measured findings plainly
(docs/review-2026-09-23/REVIEW.md). Many new headlines now carry a claim
the old slogans did not, so each is pinned here to the data it describes.
Each CLAIMS entry quotes editorial.js verbatim ({placeholders} are
wildcards for the anchor guard in test_claims_anchors.py).

When a test here fails: either the world changed (rewrite the copy in
site/js/editorial.js AND this test's quoted claim, in the same commit) or
the pipeline broke (fix the pipeline). NEVER silence a failing claim check
without doing one of the two.

Skips itself when site/data/ holds sample data or the files are missing.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from . import claims_support

DATA_DIR = claims_support.DATA_DIR

_meta_path = DATA_DIR / "meta.json"
if not _meta_path.exists():
    pytest.skip("site/data/meta.json missing — no committed data to audit",
                allow_module_level=True)
_META = json.loads(_meta_path.read_text("utf-8"))
if _META.get("sample") is True:
    pytest.skip("site/data holds sample data — claims audit only judges "
                "real data", allow_module_level=True)
GENERATION_YEAR = claims_support.GENERATION_YEAR


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return claims_support.read_json(path)


# ------------------------------------------------------------ market / hygiene

def check_agentic_ai_steepest(d: dict) -> None:
    # risers headline. (2026-09-23: +255.8% GDELT, +583.3% arXiv.)
    for src in ("gdelt", "arxiv"):
        by_id = {t["id"]: t["yoy"].get(src) for t in d["terms"]}
        if (by_id.get("agentic_ai") or {}).get("pct_change") is None:
            agentic_ai_yoy_withheld(d, src)
            continue
        rows = [(y["pct_change"], term_id) for term_id, y in by_id.items()
                if y and y.get("pct_change") is not None]
        top = max(rows)
        assert top[1] == "agentic_ai", f"{src}: steepest riser is {top}"


def agentic_ai_yoy_withheld(d: dict, src: str) -> None:
    """Agentic AI posts no YoY for ``src`` tonight, so the data neither
    confirms nor contradicts the headline; the risers table leaves the row
    off and its eligibility note says why.

    The usual cause is GDELT's rate limit meeting the month rollover
    (market_metrics.term_partial): from a hosted runner about one GDELT
    request in five lands, and a term's YoY stays withheld from the 1st of
    the month until its own fetch lands once. That kept the nightly red
    from 2026-10-01 to 10-03 while the GDELT figure itself (+255.8% against
    +114.5% for the next term on 09-29) was not in doubt.

    So a withheld GDELT figure may ship during the first
    ``ROLLOVER_GRACE_DAYS`` of a month, and only while the lane itself is
    alive (a lane in ``stale_sources`` has not landed any term for three
    days: that is an outage, not the rollover). Once a green night skips the
    08:43 catch-up, the term gets one try a day at about 36% (two requests),
    so ten days leaves about a 1% chance it has still not landed. Anything
    else withheld fails: arXiv rarely misses, and a GDELT gap later in the
    month means the fetch is broken for this term, not waiting.
    """
    day = int(d["generated_at"][8:10])
    assert src == "gdelt", (
        f"{src}: agentic_ai has no published YoY tonight; only a GDELT gap "
        f"after the month rollover may ship unchecked")
    assert src not in d.get("stale_sources", []), (
        f"{src}: the lane is stale, so agentic_ai's missing YoY is an outage")
    assert day <= ROLLOVER_GRACE_DAYS, (
        f"{src}: agentic_ai's YoY is still withheld on day {day} of the "
        f"month (grace is {ROLLOVER_GRACE_DAYS}); its GDELT fetch is not "
        f"landing")


ROLLOVER_GRACE_DAYS = 10


def _market_with(agentic_gdelt, generated_at, stale=()):
    """A minimal market_hype.json for the withheld-YoY rule."""
    def term(term_id, gdelt, arxiv):
        return {"id": term_id, "yoy": {"gdelt": gdelt, "arxiv": arxiv}}
    return {"generated_at": generated_at, "stale_sources": list(stale),
            "terms": [term("agentic_ai", agentic_gdelt, {"pct_change": 500.0}),
                      term("ai_security", {"pct_change": 108.8},
                           {"pct_change": 110.0})]}


@pytest.mark.parametrize(("agentic_gdelt", "generated_at", "stale", "ships"), [
    ({"pct_change": 255.8}, "2026-10-20T02:43:00Z", (), True),   # published, top
    ({"pct_change": 50.0}, "2026-10-02T02:43:00Z", (), False),   # published, beaten
    (None, "2026-10-03T02:43:00Z", (), True),                    # rollover gap
    (None, "2026-10-10T02:43:00Z", (), True),                    # last grace day
    (None, "2026-10-11T02:43:00Z", (), False),                   # past grace
    (None, "2026-10-03T02:43:00Z", ("gdelt",), False),           # lane outage
])
def test_agentic_ai_withheld_rule(agentic_gdelt, generated_at, stale, ships):
    d = _market_with(agentic_gdelt, generated_at, stale)
    if ships:
        check_agentic_ai_steepest(d)
    else:
        with pytest.raises(AssertionError):
            check_agentic_ai_steepest(d)


def test_withheld_arxiv_never_ships():
    d = _market_with({"pct_change": 255.8}, "2026-10-02T02:43:00Z")
    d["terms"][0]["yoy"]["arxiv"] = None
    with pytest.raises(AssertionError, match="only a GDELT gap"):
        check_agentic_ai_steepest(d)


def check_most_economies_half(d: dict) -> None:
    # spread headline: 115 of 202 at 50% or more on 2026-09-23.
    buckets = {b["bucket"]: b["n"] for b in d["spread"]["buckets"]}
    half_up = buckets["50-75%"] + buckets["75%+"]
    assert half_up > d["spread"]["n_economies"] / 2, buckets


def check_japan_us_below_half(d: dict) -> None:
    # economies caption: "Japan and the United States are both below half"
    by = {e["cc"]: e["latest_pc"] for e in d["economies"]}
    assert by["JP"] < 50 and by["US"] < 50, (by["JP"], by["US"])


# ------------------------------------------------------ breaches / extortion

def check_classes_swing_20_points(d: dict) -> None:
    # leaks caption: "some by more than 20 points from one year to the next"
    years = d["class_shares"]["years"]
    classes = [c for c in d["class_shares"]["classes"]
               if c not in ("Email addresses", "Passwords")]
    moves = [abs(b["shares"][c] - a["shares"][c])
             for c in classes for a, b in zip(years, years[1:])
             if a["year"] < GENERATION_YEAR and b["year"] < GENERATION_YEAR
             and c in a["shares"] and c in b["shares"]]
    assert max(moves) > 20, max(moves)


def check_fewer_larger_after_2021(d: dict) -> None:
    # payments headline: "far fewer and far larger after 2021"
    by = {r["year"]: r for r in d["payments_by_year"]}
    before = [by[y] for y in range(2016, 2022)]
    after = [r for y, r in by.items() if 2022 <= y < GENERATION_YEAR]
    assert after
    assert max(r["payments"] for r in after) < min(r["payments"] for r in before) / 2
    assert min(r["median_usd"] for r in after) > 10 * max(r["median_usd"] for r in before)


# ---------------------------------------------------------------- CVE page

def check_volume_rises_every_year(d: dict) -> None:
    # volume headline: each complete year since 2017 above the year before
    # (2026-10-03: 14,642 in 2017 ... 48,152 in 2025). The partial current
    # year is not held to it: until it closes its count is still growing,
    # and no count it reaches can be compared with a full year's. (2026
    # passed 2025 in the summer, 73,605 so far; the 1 January edition judges
    # it complete.)
    by = {y["year"]: y["published"] for y in d["years"]}
    run = [(y, by[y]) for y in range(2016, GENERATION_YEAR)]
    assert all(b > a for (_, a), (_, b) in zip(run, run[1:])), run


# A partial year's shares are held to the copy only from this many records:
# about two and a half months at the 2026 pace, five at 2025's. A few days
# of January can put a share anywhere (the 2026-01 replay had 4.8% missing
# a CWE after 500 records).
PARTIAL_YEAR_MIN_RECORDS = 20_000


def check_one_in_ten_lacks_cwe(d: dict) -> None:
    # quality headline: "About one in ten new CVE records still lacks a
    # weakness class (CWE)" — the latest complete year, and the current year
    # once judged. (2026-10-03: 11.7% in 2025, 10.3% for 2026 so far over
    # 73,605 records; 10.1% on 09-23.)
    by = {y["year"]: y for y in d["years"]}
    for y in (GENERATION_YEAR - 1, GENERATION_YEAR):
        r = by.get(y)
        if r and claims_support.judged(y, r["n"],
                                       min_n=PARTIAL_YEAR_MIN_RECORDS):
            assert 7 <= r["pct_missing_cwe"] <= 14, (y, r["pct_missing_cwe"])
    assert GENERATION_YEAR - 1 in by, "no row for the latest complete year"


def check_xss_first(d: dict) -> None:
    assert d["top_cwes"][0]["id"] == "CWE-79", d["top_cwes"][0]


def check_cwe_shares_2017_2025(d: dict) -> None:
    # cwe caption: "From 2017 to 2025, cross-site scripting rose from about
    # 9% to about 18% of tagged records and SQL injection from about 1% to
    # about 9%. Missing authorization rose from almost nothing to about 5%,
    # improper input validation and out-of-bounds reads fell below 2%, and
    # the other three classes moved by about two points or less."
    # (2026-10-03, unchanged since 09-23: XSS 9.0 -> 18.4, SQLi 1.3 -> 9.3,
    # missing authz 0.1 -> 5.2, input validation 6.7 -> 1.3, OOB read
    # 8.0 -> 1.6; CSRF +2.1, OOB write +0.5, path traversal -0.2.) "About"
    # allows a point either way; both years are complete.
    by = {y["year"]: y["shares"] for y in d["years"]}
    a, b = by[2017], by[2025]

    def about(value: float, target: float) -> bool:
        return abs(value - target) <= 1.0

    for cwe, start, end in (("CWE-79", 9, 18), ("CWE-89", 1, 9)):
        assert about(a[cwe], start) and about(b[cwe], end), (
            f"{cwe}: 'from about {start}% to about {end}%' vs "
            f"{a[cwe]}% -> {b[cwe]}%")
    assert a["CWE-862"] < 1 and about(b["CWE-862"], 5), (
        f"missing authorization 'from almost nothing to about 5%' vs "
        f"{a['CWE-862']}% -> {b['CWE-862']}%")
    for cwe in ("CWE-20", "CWE-125"):
        assert b[cwe] < 2 <= a[cwe], (
            f"{cwe}: 'fell below 2%' vs {a[cwe]}% -> {b[cwe]}%")
    rest = {c for c in a if c != "other"} - {
        "CWE-79", "CWE-89", "CWE-862", "CWE-20", "CWE-125"}
    assert len(rest) == 3, f"'the other three classes' vs {sorted(rest)}"
    moves = {c: round(b[c] - a[c], 1) for c in rest}
    assert all(abs(m) <= 2.5 for m in moves.values()), (
        f"'the other three classes moved by about two points or less' vs "
        f"{moves}")


# ---------------------------------------------------------------- KEV / EPSS

def check_ransomware_one_in_five(d: dict) -> None:
    pct = d["catalog"]["pct_known"]
    assert 17 <= pct <= 24, pct


def check_deadlines_fell(d: dict) -> None:
    # remediation headline: "fell from six months in 2021 to three weeks in
    # 2022–2025 and two weeks or less in 2026"; the methodology repeats the
    # last two. (2026-10-03: 181 d in 2021; 21 d in each of 2022–2025; 2026
    # so far 3 d over 249 listings with p25 3 and p75 14 — 14 d on 09-23
    # and 9.5 d on 09-28. CISA's 2026 deadlines sit at 3 and 14 days, so the
    # median moves between those two as listings arrive; it cannot pass two
    # weeks while three quarters of the year's listings are at 14 days or
    # less.)
    by = {y["year"]: y for y in d["remediation_span_by_year"]}
    assert 150 <= by[2021]["median_days"] <= 200, by[2021]
    for y in range(2022, 2026):
        assert 18 <= by[y]["median_days"] <= 24, (
            f"'three weeks in 2022–2025' vs {by[y]['median_days']} d in {y}")
    r = by.get(2026)
    assert r, "no 2026 row: the headline names 2026"
    if claims_support.judged(2026, r["n"], min_n=100):
        assert r["median_days"] <= 14, (
            f"'two weeks or less in 2026' vs {r['median_days']} d "
            f"over {r['n']} listings")


def check_listing_takes_weeks(d: dict) -> None:
    # latency headline: medians 12–26 days for the complete trend years.
    rows = [y for y in d["latency_by_year"] if y["year"] < GENERATION_YEAR]
    assert rows and all(7 <= y["median_days"] <= 60 for y in rows), rows


def check_movers_exceed_25pp(d: dict) -> None:
    entries = d["movers"]["entries"]
    assert len(entries) == 20 and min(abs(e["delta"]) for e in entries) > 0.25


def check_percentiles_vs_probabilities(d: dict) -> None:
    g = d["gap"]
    assert g["pct_moved_pct"] >= 90 and 0.3 <= g["prob_moved_pct"] <= 2.0, g


# ------------------------------------------------------- ATT&CK / naming / C2

def check_matrix_grew_every_year(d: dict) -> None:
    year_end = {}
    for v in d["versions"]:
        year_end[v["released"][:4]] = v["techniques"] + v["subtechniques"]
    run = [year_end[y] for y in sorted(year_end)]
    assert all(b > a for a, b in zip(run, run[1:])), year_end


def check_churn_in_major_releases(d: dict) -> None:
    vs = d["versions"][1:]
    add = sum(v["churn"]["added"] for v in vs)
    ret = sum(v["churn"]["deprecated"] + v["churn"]["revoked"] for v in vs)
    major = [v for v in vs if v["version"].endswith(".0")]
    add_m = sum(v["churn"]["added"] for v in major)
    ret_m = sum(v["churn"]["deprecated"] + v["churn"]["revoked"] for v in major)
    assert add_m >= 0.95 * add and ret_m >= 0.95 * ret, (add_m, add, ret_m, ret)


def check_most_three_or_fewer(d: dict) -> None:
    dist = d["distribution"]
    total = sum(b["n"] for b in dist)
    le3 = sum(b["n"] for b in dist if b["alt_count"] <= 3)
    assert le3 > total / 2, (le3, total)


def check_handful_of_c2s(d: dict) -> None:
    assert d["c2_today"]["listed_total"] <= 10, d["c2_today"]["listed_total"]


# --------------------------------------------------- rescores / roster / ADP

def check_rescores_mostly_down_and_small(d: dict) -> None:
    m = d["magnitude"]
    small = sum(b["n"] for b in m["buckets"]
                if b["bucket"] in ("-1.9..-0.1", "+0.1..+1.9"))
    assert m["down"] > m["n"] / 2 and small > m["n"] / 2, m


def check_handful_made_most(d: dict) -> None:
    top = sorted((c["rescores"] for c in d["cna_board"]["cnas"]), reverse=True)
    assert sum(top[:5]) > d["catalog"]["totals"]["rescore"] / 2, top[:5]


def check_joined_outnumber_left(d: dict) -> None:
    t = d["roster_flux"]["totals"]
    assert t["onboarded"] > t["departed"], t
    assert d["roster_size"]["net_change"] > 0, d["roster_size"]["net_change"]


def check_cisa_about_half(d: dict) -> None:
    pct = d["headline"]["pct_cisa"]
    assert 40 <= pct <= 60, pct
    assert d["headline"]["first_month"] >= "2024-01", d["headline"]["first_month"]


def check_rejection_tenfold(d: dict) -> None:
    rates = sorted(c["rejected_rate_pct"] for c in d["rejection_leaderboard"]["cnas"])
    assert rates[-1] >= 10 * max(rates[len(rates) // 2], 1.0), rates[-5:]


# ------------------------------------------------------------- home cards

def check_four_to_six_in_ten_since_2020(d: dict) -> None:
    # CVE card: "Between four and six in ten scored CVEs have been rated
    # High or Critical each year since 2020" — every blended year (the line
    # starts in 2020), the current one once judged. (2026-10-03, unchanged
    # since 09-23: 46.7 51.1 46.9 41.6 44.9 43.5 for 2020–2025, and 54.5 for
    # 2026 so far over 58,276 scored CVEs.)
    rows = [y for y in d["blended"]
            if claims_support.judged(y["year"], y["n"],
                                     min_n=PARTIAL_YEAR_MIN_RECORDS)]
    assert rows and min(y["year"] for y in rows) == 2020, (
        f"the card says 'since 2020'; the blended line starts in "
        f"{min((y['year'] for y in rows), default=None)}")
    off = [(y["year"], y["pct_high_critical"]) for y in rows
           if not 40 <= y["pct_high_critical"] <= 60]
    assert not off, f"'between four and six in ten … each year' vs {off}"


def check_hundreds_of_cnas(d: dict) -> None:
    # CNA Concentration card (and the motion scene): "Hundreds of CNAs
    # assign CVEs" — the latest complete year's active CNAs. (2026-10-03:
    # 367 in 2025; 386 in 2026 so far.)
    rows = [y for y in d["years"] if y["year"] < GENERATION_YEAR]
    latest = max(rows, key=lambda y: y["year"])
    assert 200 <= latest["cna_count"] < 1000, (
        f"'Hundreds of CNAs' vs {latest['cna_count']} in {latest['year']}")


def check_kev_mostly_a_week_or_more(d: dict) -> None:
    late = sum(b["pct"] for b in d["latency_buckets"]
               if b["bucket"] not in ("before_publish", "0-7d"))
    assert late > 50, late


def check_top5_about_half_since_2021(d: dict) -> None:
    rows = [y for y in d["years"] if 2021 <= y["year"] < GENERATION_YEAR]
    assert rows and all(40 <= y["top5_share"] <= 62 for y in rows), \
        [(y["year"], y["top5_share"]) for y in rows]


def check_fewer_than_half_validate(d: dict) -> None:
    assert d["world"]["latest"]["validating_pc"] < 50, d["world"]["latest"]


def check_tuesday_busiest_since_2022(d: dict) -> None:
    for y in d["weekday"]["years"]:
        if y["year"] >= 2022:
            assert y["pct"].index(max(y["pct"])) == 1, (y["year"], y["pct"])


def check_exploit_a_week_or_more_since_2021(d: dict) -> None:
    rows = [r for r in d["hero"]["years"] if r["year"] >= 2021]
    assert rows and all(r["median_days"] >= 7 for r in rows), \
        [(r["year"], r["median_days"]) for r in rows]


def check_dozens_of_incident_filings(d: dict) -> None:
    if d["status"] != "ok":
        return
    assert 24 <= d["totals"]["originals"] < 200, d["totals"]["originals"]


# -------------------------------------------------------- AI and PoC Timing

def check_public_code_not_sooner(d: dict) -> None:
    # ai_clock headline: the like-for-like clock at the default (ChatGPT)
    # cutoff did not move earlier. (2026-09-23: 2.0 d -> 9.0 d, "later".)
    lfl = next(m for m in d["banked"]["metrics"] if m["id"] == "poc_like_for_like")
    era = next(e for e in lfl["eras"] if e["era"] == "chatgpt")
    assert era["verdict"] != "accelerated" and era["post"]["value"] >= era["pre"]["value"], era


def check_exploitdb_thinned(d: dict) -> None:
    # ai_clock note: "Exploit-DB dated public exploits for {peak_n} CVEs
    # published in {peak_year} and for {latest_n} published in
    # {latest_year}, so recent medians rest on far fewer CVEs"
    # (2026-09-23: 2,745 in 2007, 154 in 2024).
    rows = next(m for m in d["clock"]["metrics"] if m["id"] == "poc_gap")["years"]
    peak = max(r["n"] for r in rows)
    latest = [r for r in rows if not r["provisional"]][-1]["n"]
    assert peak >= 5 * latest, (peak, latest)


def check_mandiant_figures_recorded(d: dict) -> None:
    # ai_clock caption quotes Mandiant: "an average time-to-exploit of 63
    # days in 2018–19 and five days in 2023, a year in which 70% of the
    # vulnerabilities it saw exploited were zero-days". The quoted figures
    # must match the attributed record the repo keeps.
    from pipeline.ai_timeline_data import EXTERNAL_CONTEXT
    rec = next(r for r in EXTERNAL_CONTEXT if r["attribution"].startswith("Mandiant"))
    for bit in ("Average", "63 days", "5 days (2023)", "70%"):
        assert bit in rec["claim"], (bit, rec["claim"])


CLAIMS = [
    ("Agentic AI has the steepest year-over-year rise in news and in research papers.",
     "market_hype.json", check_agentic_ai_steepest),
    ("In most measured economies, at least half of users have validating resolvers.",
     "dnssec_adoption.json", check_most_economies_half),
    ("Japan and the United States", "dnssec_adoption.json", check_japan_us_below_half),
    ("some by more than 20 points from one year to the next",
     "breach_ledger.json", check_classes_swing_20_points),
    ("The ledger's payments became far fewer and far larger after 2021.",
     "extortion_ledger.json", check_fewer_larger_after_2021),
    ("More CVEs were published in each year since 2017 than in the year before.",
     "volume_curve.json", check_volume_rises_every_year),
    ("About one in ten new CVE records still lacks a weakness class (CWE).",
     "advisory_quality.json", check_one_in_ten_lacks_cwe),
    ("Cross-site scripting is the most common weakness class of the last ten complete years.",
     "cwe_distribution.json", check_xss_first),
    ("From 2017 to 2025, cross-site scripting rose from about 9% to about 18% of tagged "
     "records and SQL injection from about 1% to about 9%. Missing authorization rose "
     "from almost nothing to about 5%, improper input validation and out-of-bounds "
     "reads fell below 2%, and the other three classes moved by about two points or less.",
     "cwe_distribution.json", check_cwe_shares_2017_2025),
    ("CISA flags about one KEV entry in five as used in ransomware campaigns.",
     "kev_ransomware.json", check_ransomware_one_in_five),
    ("Median remediation deadlines fell from six months in 2021 to three weeks in "
     "2022–2025 and two weeks or less in 2026.",
     "kev_latency.json", check_deadlines_fell),
    ("Entries added from 2022 to 2025 had a median deadline of three weeks, and "
     "entries added in 2026 a median of two weeks or less.",
     "kev_latency.json", check_deadlines_fell),
    ("The median KEV listing comes weeks after the CVE record is published.",
     "kev_latency.json", check_listing_takes_weeks),
    ("The twenty largest single-night EPSS probability moves each exceed 25 percentage points.",
     "epss_volatility.json", check_movers_exceed_25pp),
    ("EPSS percentiles move for nearly all CVEs each night; probabilities for about 1%.",
     "epss_volatility.json", check_percentiles_vs_probabilities),
    ("The ATT&CK enterprise matrix has grown every year since 2018.",
     "attack_churn.json", check_matrix_grew_every_year),
    ("Nearly all ATT&CK technique additions and retirements come in major releases.",
     "attack_churn.json", check_churn_in_major_releases),
    ("Most ATT&CK groups have three or fewer alternate names.",
     "naming.json", check_most_three_or_fewer),
    ("Tonight's blocklist holds a handful of C2 servers.",
     "botnet_weather.json", check_handful_of_c2s),
    ("Most rescores lower the score, and most move it by less than two points.",
     "rescore_log.json", check_rescores_mostly_down_and_small),
    ("A handful of CNAs made most of the rescores logged since July 2026.",
     "rescore_log.json", check_handful_made_most),
    ("Since July 2026, more organizations have joined the CVE roster than left it.",
     "cna_roster.json", check_joined_outnumber_left),
    ("Since mid-2024, CISA has enriched about half of all published CVE records.",
     "adp_coverage.json", check_cisa_about_half),
    ("Rejection rates differ by more than tenfold between CNAs.",
     "cna_concentration.json", check_rejection_tenfold),
    ("Between four and six in ten scored CVEs have been rated High or Critical each year since 2020.",
     "severity_inflation.json", check_four_to_six_in_ten_since_2020),
    ("Most KEV entries were listed a week or more after their CVE was published.",
     "kev_latency.json", check_kev_mostly_a_week_or_more),
    ("Hundreds of CNAs assign CVEs;",
     "cna_concentration.json", check_hundreds_of_cnas),
    ("since 2021 the five largest have issued about half",
     "cna_concentration.json", check_top5_about_half_since_2021),
    ("Fewer than half of internet users sit behind DNSSEC-validating resolvers.",
     "dnssec_adoption.json", check_fewer_than_half_validate),
    ("Since 2022, more CVEs have been published on Tuesday than on any other day.",
     "cve_calendar.json", check_tuesday_busiest_since_2022),
    ("Since 2021 the median public exploit has appeared a week or more after the CVE.",
     "time_to_poc.json", check_exploit_a_week_or_more_since_2021),
    ("Public exploit code in Exploit-DB has not appeared sooner since ChatGPT.",
     "ai_alibi.json", check_public_code_not_sooner),
    ("so recent medians rest on far fewer CVEs",
     "ai_alibi.json", check_exploitdb_thinned),
    ("reports an average time-to-exploit of 63 days in 2018–19 and five days in 2023",
     "ai_alibi.json", check_mandiant_figures_recorded),
    ("have filed dozens of material-incident 8-Ks since December 2023",
     "sec_incidents.json", check_dozens_of_incident_filings),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
