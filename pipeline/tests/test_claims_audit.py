"""Claims audit: the editorial copy must keep matching the committed data.

The site's copy (site/js/editorial.js) makes verbal claims — "Nearly four in
ten…", "tens of thousands…" — about numbers in site/data/*.json, and those
numbers refresh nightly. This module is the standing guard against claim
drift: each CLAIMS entry quotes the copy verbatim (grep for it in
editorial.js) and asserts the underlying number still sits in a range where
the sentence remains true. Ranges are deliberately tolerant: normal nightly
drift must not trip them; only a claim becoming untrue should.

When a test here fails, one of two things happened:

1. The world changed — the data moved far enough that the sentence is no
   longer true. Fix the copy in site/js/editorial.js (and then this test's
   quoted claim + range, together, in the same commit).
2. The pipeline broke — the number is nonsense. Fix the pipeline.

Either way: NEVER silence or delete the failing test without doing one of
the above. A skipped claims audit is worse than none, because the site keeps
asserting the stale claim with full confidence.

The module skips itself entirely when site/data/ holds sample data
(meta.json "sample": true) or the files are missing — offline-fixture CI
smoke runs write elsewhere, so this audit only ever judges the committed
real data.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from . import claims_support

# Resolve site/data/ relative to this file so the audit works from any cwd:
# pipeline/tests/test_claims_audit.py -> repo root -> site/data.
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

# The generation year: used to find the "latest complete year" in series
# that include the partial current year. Payloads with a headline block
# already encode this (headline is authoritative); raw year series don't.
#
# January rehearsal: CYBERMON_REHEARSE_YEAR=2027 judges every raw-series
# guard as if the edition had been generated in that year — the partial
# current year becomes "complete" with its values as they stand. Headline
# blocks are computed by the pipeline and cannot be rehearsed this way;
# their guards are pinned to named years instead (see docs/backlog.md).
GENERATION_YEAR = claims_support.GENERATION_YEAR


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return claims_support.read_json(path)


def complete_years(rows: list[dict]) -> list[dict]:
    """Rows for complete years only (strictly before the generation year)."""
    return [r for r in rows if r["year"] < GENERATION_YEAR]


# --------------------------------------------------------------------------
# Claim checks. Each returns None; assertion messages restate the claim so a
# failure reads as "this sentence is no longer true", not as a raw number.
# --------------------------------------------------------------------------


def check_severity_headline(d: dict) -> None:
    # editorial.js (cve.html hero): "About half of scored CVEs are rated
    # High or Critical." — the headline block's latest complete year (43.5%
    # for 2025 on 2026-10-03; 2026 so far is 54.5%, so the band holds
    # "about half" on both sides of the January rollover). The caption's
    # "no sustained rise" used to be checked here against the headline
    # baseline; it names 2020–2025 now (check_inflation_2020_2025), which
    # keeps the partial 2026 from tripping it the day it becomes complete.
    pct = d["headline"]["pct_high_critical_latest"]  # share ≥ 7.0, latest complete year
    assert 40 <= pct <= 60, (
        f"'About half of scored CVEs are rated High or Critical' claims "
        f"~50%; data says {pct}% (latest complete year "
        f"{d['headline']['latest_year']})"
    )


def check_inflation_2020_2025(d: dict) -> None:
    # editorial.js (cve.html hero caption): "the v3 line starts earlier" than
    # the blended line, and "From 2020 to 2025 the yearly median stayed
    # close to 7.0, the lower edge of High, and between 40% and 52% of scored
    # CVEs were rated 7.0 or higher each year, with no sustained rise."
    # Named, complete years. (2026-10-03, unchanged since 09-23: medians
    # 6.8 7.1 6.6 6.5 6.5 6.9; shares 46.7 51.1 46.9 41.6 44.9 43.5; the v3
    # line starts in 2017, the blended line in 2020.)
    blended = {y["year"]: y for y in d["blended"]}
    v3_start = min(y["year"] for y in d["series"]["v3"])
    assert v3_start < min(blended), (
        f"'the v3 line starts earlier' vs v3 {v3_start}, blended "
        f"{min(blended)}")
    rows = [blended[y] for y in range(2020, 2026)]
    medians = [(r["year"], r["median"]) for r in rows]
    assert all(abs(m - 7.0) <= 0.6 for _, m in medians), (
        f"'the yearly median stayed close to 7.0' vs {medians}")
    shares = [r["pct_high_critical"] for r in rows]
    assert all(40 <= s <= 52 for s in shares), (
        f"'between 40% and 52% … each year' vs {shares}")
    rises = [b > a for a, b in zip(shares, shares[1:])]
    longest = max((len(run) for run in "".join(
        "r" if r else " " for r in rises).split()), default=0)
    assert longest < 3 and shares[-1] <= shares[0] + 5, (
        f"'with no sustained rise' vs {shares} (longest run of yearly "
        f"rises: {longest})")


def check_epss_disconnect(d: dict) -> None:
    # editorial.js (score vs. reality): "more than six in ten
    # Critical-rated CVEs carry less than a 1% probability of exploitation"
    pct = d["headline"]["pct_critical_epss_below_1pct"]
    assert 60 < pct <= 70, (
        f"'six in ten Critical-rated CVEs carry less than a 1% probability' "
        f"claims ~60%; data says {pct}%"
    )


def check_severity_gradient(d: dict) -> None:
    # editorial.js (score vs. reality): "the share with a better-than-10%
    # chance of exploitation rises about twentyfold from Low to Critical"
    # (0.39% -> 8.21% on the 2026-09-08 edition = 21x). The headline used
    # to say the two "barely correlate"; the grid never supported that.
    tot: dict[str, int] = {}
    hi: dict[str, int] = {}
    for cell in d["grid"]:
        tot[cell["cvss_bucket"]] = tot.get(cell["cvss_bucket"], 0) + cell["n"]
        if cell["epss_bucket"] == "≥10%":
            hi[cell["cvss_bucket"]] = hi.get(cell["cvss_bucket"], 0) + cell["n"]
    low = 100.0 * hi.get("0.0-3.9", 0) / tot["0.0-3.9"]
    crit = 100.0 * hi.get("9.0-10.0", 0) / tot["9.0-10.0"]
    assert low > 0, "no Low-rated CVE above 10% EPSS — the ratio is undefined"
    ratio = crit / low
    assert 10 <= ratio <= 40, (
        f"'rises about twentyfold from Low to Critical' vs Low {low:.2f}% -> "
        f"Critical {crit:.2f}% = {ratio:.1f}x"
    )


def check_in_record_scoring_rise(d: dict) -> None:
    # editorial.js (flood methodology): "in-record scoring was a rounding
    # error in 2017 and covers well over nine in ten records today" — read
    # from advisory_quality.json's missing-score share (2017: 97.1% missing;
    # latest complete year: ~6% missing on the 2026-09-08 edition).
    by_year = {y["year"]: y for y in d["years"]}
    assert by_year[2017]["pct_missing_cvss"] >= 90, (
        f"'a rounding error in 2017' vs {100 - by_year[2017]['pct_missing_cvss']:.1f}% "
        f"of 2017 records scored in-record"
    )
    latest = max(complete_years(d["years"]), key=lambda r: r["year"])
    assert latest["pct_missing_cvss"] <= 10, (
        f"'well over nine in ten records today' vs {latest['pct_missing_cvss']}% "
        f"missing a score in {latest['year']}"
    )


def check_seeding_era_latency(d: dict) -> None:
    # editorial.js (KEV latency methodology): "the seeding era's pooled
    # median 'latency', in the callout, runs near two and a half years; of
    # 2023 additions, twelve days" — 887.5 d pooled, 12.0 d for 2023.
    pooled = d["launch_backfill"]["median_days"]
    assert 700 <= pooled <= 1100, (
        f"'near two and a half years' vs a pooled seeding-era median of "
        f"{pooled} days"
    )
    row = next(r for r in d["latency_by_year"] if r["year"] == 2023)
    assert 8 <= row["median_days"] <= 16, (
        f"'of 2023 additions, twelve days' vs {row['median_days']} days"
    )


def check_kev_below_high(d: dict) -> None:
    # editorial.js (score vs. reality): "{pct} of actively exploited
    # vulnerabilities are rated below High" — copy treats this as a
    # non-trivial slice of KEV, i.e. roughly one in ten.
    pct = d["kev"]["pct_below_high"]
    assert 8 <= pct <= 20, (
        f"'actively exploited vulnerabilities rated below High' share "
        f"expected ~one in ten; data says {pct}%"
    )


def check_modified_pile_ratio(d: dict) -> None:
    # editorial.js (NVD decay methodology): "the Modified pile is more than
    # an order of magnitude larger than the live queue" — 243,574 vs 8,875
    # (27x) on the 2026-09-08 edition; the copy used to say two orders.
    statuses = {s["status"]: s["n"] for s in d["current"]["statuses"]}
    queue = d["current"]["backlog_total"]
    assert queue > 0 and statuses["Modified"] / queue >= 10, (
        f"'more than an order of magnitude larger than the live queue' vs "
        f"Modified {statuses['Modified']} / queue {queue}"
    )


def check_deferred_pile(d: dict) -> None:
    # editorial.js (NVD decay): "tens of thousands of CVEs were quietly
    # stamped “Deferred”"
    deferred = next(
        (s["n"] for s in d["current"]["statuses"] if s["status"] == "Deferred"), 0
    )
    assert deferred >= 20_000, (
        f"'tens of thousands of CVEs were quietly stamped Deferred' needs "
        f">= 20,000; data says {deferred:,}"
    )


def check_cna_nine_plus(d: dict) -> None:
    # editorial.js (CNA leaderboard): "The highest-rating CNAs score more
    # than a third of their CVEs 9.0 or higher." — the two highest on the
    # board above a third (the plural), and the top below half, where "more
    # than a third" would understate it. (2026-10-03, unchanged since 09-23:
    # SolarWinds 44.0% of 100, GovTech CSG 39.8% of 108; third is twcert at
    # 30.3%.) The three-year window slides every January; the 2026-10-03
    # audit forecast a top near 40% once 2024 drops out. The old wording,
    # "three or four in ten", sat about five critical records from its cap.
    top = sorted((c["pct_geq_9"] for c in d["cnas"]), reverse=True)
    assert len(top) >= 2 and top[1] > 100 / 3, (
        f"'The highest-rating CNAs score more than a third' needs two CNAs "
        f"above 33.3%; the board's top two are {top[:2]}")
    assert top[0] < 50, (
        f"'more than a third' understates a top CNA at {top[0]}%")


def _bucket_pct(d: dict, bucket: str) -> float:
    return next(b["pct"] for b in d["latency_buckets"] if b["bucket"] == bucket)


def check_kev_week_bucket(d: dict) -> None:
    # editorial.js (kev.html buckets): "Nearly four in ten KEV listings
    # land inside a week."
    pct = _bucket_pct(d, "0-7d")
    assert 30 <= pct <= 48, (
        f"'Nearly four in ten KEV listings land inside a week' claims ~40%; "
        f"data says {pct}% in the 0-7d bucket"
    )


def check_kev_three_years_late(d: dict) -> None:
    # editorial.js (kev.html buckets): "One in seven lands three years late."
    pct = _bucket_pct(d, "3y+")
    assert 10 <= pct <= 20, (
        f"'One in seven lands three years late' claims ~14%; "
        f"data says {pct}% in the 3y+ bucket"
    )


def check_kev_getting_slower(d: dict) -> None:
    # editorial.js (kev.html trend): "its middle has {middle_verb}, from a
    # median of {baseline_median} days for {baseline_year} listings to
    # {latest_median} for {latest_year}, while the share listed more than a
    # year late has {tail_verb}". Since 2026-09-20 the numbers AND the
    # verbs are filled from the payload by kev_latency.js, so the sentence
    # cannot go stale; what this guards is that the inputs it names exist
    # and describe two different charted years, with the over-a-year tail
    # present for both.
    h = d["headline"]
    by_year = {r["year"]: r for r in d["latency_by_year"]}
    assert h["baseline_year"] in by_year and h["latest_year"] in by_year, (
        f"the caption names {h['baseline_year']} and {h['latest_year']}, "
        f"but the charted years are {sorted(by_year)}"
    )
    assert h["baseline_year"] < h["latest_year"], (
        "the caption compares an earlier baseline year to the latest one"
    )
    for y in (h["baseline_year"], h["latest_year"]):
        assert "pct_over_365d" in by_year[y], f"{y} lacks the tail share"


def check_kev_three_week_rule(d: dict) -> None:
    # editorial.js (kev.html remediation): "The early catalog handed out
    # months; the {latest_year} listings carried a median of
    # {latest_median} days". The numbers are filled from the payload by
    # kev_remediation.js; the one typed claim left is that the EARLY
    # catalog (the 2021 launch cohort) handed out months, which the launch
    # year's median must still support.
    by_year = {r["year"]: r for r in d["remediation_span_by_year"]}
    first = min(by_year)
    assert by_year[first]["median_days"] >= 60, (
        f"'The early catalog handed out months' vs a {first} median of "
        f"{by_year[first]['median_days']} days"
    )
def check_more_assignors_than_ever(d: dict) -> None:
    # editorial.js (concentration.html): "More assignors than ever."
    rows = complete_years(d["years"])
    assert rows, "no complete years in cna_concentration years"
    latest = max(rows, key=lambda r: r["year"])
    peak = max(r["cna_count"] for r in rows)
    assert latest["cna_count"] == peak, (
        f"'More assignors than ever' needs the latest complete year "
        f"({latest['year']}: {latest['cna_count']} CNAs) to be the all-time "
        f"high; the peak is {peak}"
    )


def check_volume_belongs_to_a_handful(d: dict) -> None:
    # editorial.js (concentration.html hero): "five of them published most
    # of 2025's CVEs" — a majority, in the named year (56.6% on 2026-10-03
    # and 09-23). It used to read the headline block's latest year with a
    # 40% floor, which would have judged 2026 against "most of 2025's" from
    # 1 January; check_concentration_reversal pins the same 2025 figure for
    # the caption.
    by_year = {y["year"]: y for y in d["years"]}
    share = by_year[2025]["top5_share"]
    assert share > 50, (
        f"'five of them published most of 2025's CVEs' vs a 2025 top-5 "
        f"share of {share}%"
    )


def check_rejection_share_story(d: dict) -> None:
    # editorial.js (volume curve): "it collapsed from a fifth of everything
    # shipped in 2017 to under two percent by 2023 — and 2024 and 2025
    # bent it back up." Named years: 2026 (0.4% so far) would have failed
    # "the last two complete years" on 2027-01-01 with no data change.
    rows = complete_years(d["years"])
    by_year = {r["year"]: r for r in rows}

    def share(y: int) -> float:
        r = by_year[y]
        total = r["published"] + r["rejected"]
        return 100.0 * r["rejected"] / total if total else 0.0

    assert 15 <= share(2017) <= 27, (
        f"'a fifth of everything shipped in 2017' vs {share(2017):.2f}%"
    )
    assert share(2023) < 2.0, (
        f"'under two percent by 2023' vs {share(2023):.2f}%"
    )
    assert share(2024) > share(2023) and share(2025) > share(2023), (
        f"'2024 and 2025 bent it back up' vs 2024: {share(2024):.2f}%, "
        f"2025: {share(2025):.2f}% against 2023's {share(2023):.2f}%"
    )


def check_flood_critical_volume(d: dict) -> None:
    # editorial.js (9.8 flood caption): "close to four thousand records a
    # year shipped stamped Critical in 2024 and 2025". Named years, bounded
    # both ways: under 3,000 the claim inflates, past ~4,400 it understates.
    by_year = {r["year"]: r for r in d["years"]}
    for y in (2024, 2025):
        assert 3000 <= by_year[y]["critical"] <= 4400, (
            f"'close to four thousand … Critical in 2024 and 2025' vs "
            f"{by_year[y]['critical']} in {y}"
        )


def check_entrants_top3_recruiting(d: dict) -> None:
    # editorial.js (concentration entrants): "every complete year since
    # 2023 has brought in more new CNAs than any year before it". Complete
    # years only: the partial current year is still counting. (2026-09-23:
    # 77 / 64 / 70 for 2023-25 against a pre-2023 best of 50 in 2022.)
    rows = complete_years(d["years"])
    before = max(y["newcomer_count"] for y in rows if y["year"] < 2023)
    since = [(y["year"], y["newcomer_count"]) for y in rows
             if y["year"] >= 2023]
    assert since and all(n > before for _, n in since), (
        f"'every complete year since 2023 has brought in more new CNAs than "
        f"any year before it' — pre-2023 best {before}, since: {since}"
    )


def check_concentration_fell_then_rose(d: dict) -> None:
    # editorial.js (concentration hero caption): "In the decade to 2023 the
    # top-5 share mostly fell as the program added CNAs; from 2023 to 2025
    # it rose." Named years, so the partial 2026 (47.0% on 2026-10-03, 46.9%
    # on 09-23) cannot turn "rose" into a ten-point fall in January.
    # (2026-10-03: 68.4% in 2013 -> 45.3% in 2023, down in 7 of 10 steps,
    # while active CNAs went 19 -> 262; then 53.1% in 2024, 56.6% in 2025.)
    by_year = {y["year"]: y for y in d["years"]}
    decade = [by_year[y]["top5_share"] for y in range(2013, 2024)]
    falls = sum(b < a for a, b in zip(decade, decade[1:]))
    assert falls > len(decade) // 2 and decade[-1] < decade[0], (
        f"'In the decade to 2023 the top-5 share mostly fell' vs {decade}")
    assert by_year[2023]["cna_count"] > by_year[2013]["cna_count"], (
        "'as the program added CNAs' vs the active-CNA counts")
    rise = [by_year[y]["top5_share"] for y in (2023, 2024, 2025)]
    assert rise[0] < rise[1] < rise[2], (
        f"'from 2023 to 2025 it rose' vs {rise}")


def check_concentration_reversal(d: dict) -> None:
    # editorial.js (concentration hero): "the roster grew seventeen-fold
    # between 2015 and 2025, yet in 2025 five of its hundreds of names
    # still shipped a majority of the year's records, their share climbing for a
    # second straight year" (2023 is the low; 2024 and 2025 each rise).
    # Named years: the partial 2026 (48.0%) would
    # have failed "still ship a majority" on 2027-01-01.
    by_year = {y["year"]: y for y in d["years"]}
    a, b, c = by_year[2023], by_year[2024], by_year[2025]
    assert c["top5_share"] > 50.0, (
        f"'in 2025 … still shipped a majority' vs top5 {c['top5_share']}%"
    )
    assert a["top5_share"] < b["top5_share"] < c["top5_share"], (
        f"'climbing for a second straight year' vs "
        f"{[(y['year'], y['top5_share']) for y in (a, b, c)]}"
    )
    growth = c["cna_count"] / by_year[2015]["cna_count"]
    assert 15 <= growth <= 20, (
        f"'grew seventeen-fold between 2015 and 2025' vs "
        f"{by_year[2015]['cna_count']} -> {c['cna_count']} = {growth:.1f}x"
    )


def check_flood_partial_year_mark(d: dict) -> None:
    # editorial.js (flood caption): "2026 passed that mark with months of
    # the year to spare" (the ~four-thousand-Critical mark). Named year:
    # 7,048 at 69% of 2026, so the sentence stays true once 2026 closes.
    row = next((y for y in d["years"] if y["year"] == 2026), None)
    assert row is not None and row["critical"] >= 4400, (
        f"'2026 passed that mark' vs {row['critical'] if row else 0} "
        f"Critical in 2026"
    )


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion) — one row per
# sentence the site commits to. Keep the claim text greppable.
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "every complete year since 2023 has brought in more new CNAs than any year before 2023",
        "cna_concentration.json",
        check_entrants_top3_recruiting,
    ),
    (
        "still shipped a majority of the year's records, their share climbing for a second straight year",
        "cna_concentration.json",
        check_concentration_reversal,
    ),
    (
        "In the decade to 2023 the top-5 share mostly fell as the program added CNAs; from 2023 to 2025 it rose.",
        "cna_concentration.json",
        check_concentration_fell_then_rose,
    ),
    (
        "The Critical count for 2026 passed four thousand with months of the year still to go",
        "nine_eight_flood.json",
        check_flood_partial_year_mark,
    ),
    (
        "Close to four thousand CVEs a year were rated Critical in 2024 and 2025.",
        "nine_eight_flood.json",
        check_flood_critical_volume,
    ),
    (
        "About half of scored CVEs are rated High or Critical.",
        "severity_inflation.json",
        check_severity_headline,
    ),
    (
        "the v3 line starts earlier, on much thinner coverage. From 2020 to 2025 the yearly "
        "median stayed close to 7.0, the lower edge of High, and between 40% and 52% of "
        "scored CVEs were rated 7.0 or higher each year, with no sustained rise.",
        "severity_inflation.json",
        check_inflation_2020_2025,
    ),
    (
        "more than six in ten Critical-rated CVEs carry less than a 1% probability of exploitation",
        "score_vs_reality.json",
        check_epss_disconnect,
    ),
    (
        "rises about twentyfold from Low to Critical",
        "score_vs_reality.json",
        check_severity_gradient,
    ),
    (
        "the Modified count is more than an order of magnitude larger than the live queue",
        "nvd_decay.json",
        check_modified_pile_ratio,
    ),
    (
        "In-record scoring covered fewer than one in ten of 2017's records and covers more than nine in ten today",
        "advisory_quality.json",
        check_in_record_scoring_rise,
    ),
    (
        "pooled median 'latency', in the callout, runs near two and a half years",
        "kev_latency.json",
        check_seeding_era_latency,
    ),
    (
        "{pct} of CISA KEV entries are rated below High",
        "score_vs_reality.json",
        check_kev_below_high,
    ),
    (
        "Tens of thousands of CVEs carry NVD's “Deferred” status.",
        "nvd_decay.json",
        check_deferred_pile,
    ),
    (
        "The highest-rating CNAs score more than a third of their CVEs 9.0 or higher.",
        "cna_leaderboard.json",
        check_cna_nine_plus,
    ),
    (
        "Nearly four in ten KEV listings come within a week",
        "kev_latency.json",
        check_kev_week_bucket,
    ),
    (
        "one in seven after three years",
        "kev_latency.json",
        check_kev_three_years_late,
    ),
    (
        "from a median of {baseline_median} days for {baseline_year} listings to {latest_median} for {latest_year}",
        "kev_latency.json",
        check_kev_getting_slower,
    ),
    (
        "The 2021 launch cohort got deadlines measured in months; the {latest_year} listings carried a median of {latest_median} days",
        "kev_latency.json",
        check_kev_three_week_rule,
    ),
    (
        "There are more CNAs than ever",
        "cna_concentration.json",
        check_more_assignors_than_ever,
    ),
    (
        "five of them published most of 2025's CVEs",
        "cna_concentration.json",
        check_volume_belongs_to_a_handful,
    ),
    (
        "Rejections fell from a fifth of all records in 2017 to under two percent in 2023, then rose again in 2024 and 2025.",
        "volume_curve.json",
        check_rejection_share_story,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
