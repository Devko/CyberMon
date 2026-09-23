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

DATA_DIR = Path(__file__).resolve().parents[2] / "site" / "data"

_meta_path = DATA_DIR / "meta.json"
if not _meta_path.exists():
    pytest.skip("site/data/meta.json missing — no committed data to audit",
                allow_module_level=True)
_META = json.loads(_meta_path.read_text("utf-8"))
if _META.get("sample") is True:
    pytest.skip("site/data holds sample data — claims audit only judges "
                "real data", allow_module_level=True)
GENERATION_YEAR = int(_META["generated_at"][:4])


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return json.loads(path.read_text("utf-8"))


# ------------------------------------------------------------ market / hygiene

def check_agentic_ai_steepest(d: dict) -> None:
    # risers headline. (2026-09-23: +255.8% GDELT, +583.3% arXiv.)
    for src in ("gdelt", "arxiv"):
        rows = [(t["yoy"][src]["pct_change"], t["id"]) for t in d["terms"]
                if t["yoy"].get(src) and t["yoy"][src].get("pct_change") is not None]
        top = max(rows)
        assert top[1] == "agentic_ai", f"{src}: steepest riser is {top}"


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
    # volume headline: each year since 2017 above the year before (the
    # partial current year included — it already exceeds the last one).
    by = {y["year"]: y["published"] for y in d["years"]}
    run = [by[y] for y in range(2016, GENERATION_YEAR + 1)]
    assert all(b > a for a, b in zip(run, run[1:])), run


def check_one_in_ten_lacks_cwe(d: dict) -> None:
    # quality headline: 11.7% (2025), 10.1% (2026 so far).
    by = {y["year"]: y["pct_missing_cwe"] for y in d["years"]}
    for y in (GENERATION_YEAR - 1, GENERATION_YEAR):
        if y in by:
            assert 7 <= by[y] <= 14, (y, by[y])


def check_xss_first(d: dict) -> None:
    assert d["top_cwes"][0]["id"] == "CWE-79", d["top_cwes"][0]


# ---------------------------------------------------------------- KEV / EPSS

def check_ransomware_one_in_five(d: dict) -> None:
    pct = d["catalog"]["pct_known"]
    assert 17 <= pct <= 24, pct


def check_deadlines_fell(d: dict) -> None:
    # remediation headline: 181 d in 2021, 21 d or less since.
    by = {y["year"]: y["median_days"] for y in d["remediation_span_by_year"]}
    assert 150 <= by[2021] <= 200, by[2021]
    assert all(v <= 21 for y, v in by.items() if y >= 2022), by


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

def check_close_to_half_each_year(d: dict) -> None:
    # 2020-2026: 46.7 51.1 46.9 41.6 44.9 43.5 54.5
    pcts = [y["pct_high_critical"] for y in d["blended"]]
    assert pcts and all(40 <= p <= 56 for p in pcts), pcts


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
    ("CISA flags about one KEV entry in five as used in ransomware campaigns.",
     "kev_ransomware.json", check_ransomware_one_in_five),
    ("Median remediation deadlines fell from six months in 2021 to three weeks or less.",
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
    ("Close to half of scored CVEs are rated High or Critical each year.",
     "severity_inflation.json", check_close_to_half_each_year),
    ("Most KEV entries were listed a week or more after their CVE was published.",
     "kev_latency.json", check_kev_mostly_a_week_or_more),
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
