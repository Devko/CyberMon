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
import os
from pathlib import Path

import pytest

# Resolve site/data/ relative to this file so the audit works from any cwd:
# pipeline/tests/test_claims_audit.py -> repo root -> site/data.
DATA_DIR = Path(__file__).resolve().parents[2] / "site" / "data"

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
GENERATION_YEAR = int(os.environ.get("CYBERMON_REHEARSE_YEAR")
                      or _META["generated_at"][:4])


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return json.loads(path.read_text("utf-8"))


def complete_years(rows: list[dict]) -> list[dict]:
    """Rows for complete years only (strictly before the generation year)."""
    return [r for r in rows if r["year"] < GENERATION_YEAR]


# --------------------------------------------------------------------------
# Claim checks. Each returns None; assertion messages restate the claim so a
# failure reads as "this sentence is no longer true", not as a raw number.
# --------------------------------------------------------------------------


def check_severity_headline(d: dict) -> None:
    # editorial.js (cve.html hero): "About half of all CVEs ship as
    # “High” or worse." — 43.5% in 2025, 53.5% in the partial 2026; the
    # band holds "about half" on both sides of the January rollover.
    pct = d["headline"]["pct_high_critical_latest"]  # share ≥ 7.0, latest complete year
    assert 40 <= pct <= 60, (
        f"'About half of all CVEs ship as High or worse' claims ~50%; "
        f"data says {pct}% (latest complete year {d['headline']['latest_year']})"
    )


def check_epss_disconnect(d: dict) -> None:
    # editorial.js (score vs. reality): "six in ten Critical-rated CVEs
    # carry less than a 1% probability of exploitation"
    pct = d["headline"]["pct_critical_epss_below_1pct"]
    assert 50 <= pct <= 70, (
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
        if cell["epss_bucket"] == ">10%":
            hi[cell["cvss_bucket"]] = hi.get(cell["cvss_bucket"], 0) + cell["n"]
    low = 100.0 * hi.get("0.1-3.9", 0) / tot["0.1-3.9"]
    crit = 100.0 * hi.get("9.0-10.0", 0) / tot["9.0-10.0"]
    assert low > 0, "no Low-rated CVE above 10% EPSS — the ratio is undefined"
    ratio = crit / low
    assert 10 <= ratio <= 40, (
        f"'rises about twentyfold from Low to Critical' vs Low {low:.2f}% -> "
        f"Critical {crit:.2f}% = {ratio:.1f}x"
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
    # editorial.js (CNA leaderboard): "Some CNAs hand a 9+ to a third or
    # more of the CVEs they score" — the three-year window slides every
    # January (39.8% today; ~31% once 2024 drops out), so the copy claims
    # the floor, not the current peak.
    top = max(c["pct_geq_9"] for c in d["cnas"])
    assert 28 <= top <= 60, (
        f"'a 9+ to a third or more of the CVEs they score' needs a top "
        f"per-CNA pct_geq_9 of at least ~30%; data's max is {top}%"
    )


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
    # editorial.js (kev.html trend): "and it has been getting slower,
    # not faster."
    h = d["headline"]
    assert h["median_days_latest"] > h["median_days_baseline"], (
        f"'it has been getting slower, not faster' needs the latest median "
        f"({h['median_days_latest']}d, {h['latest_year']}) above the baseline "
        f"({h['median_days_baseline']}d, {h['baseline_year']})"
    )


def check_kev_three_week_rule(d: dict) -> None:
    # editorial.js (kev.html remediation): "from 2022 through 2025 the
    # standing rule was three weeks — and the 2026 listings are coming in
    # at two." Pinned to named years so the January rollover cannot move
    # the claim; 2026's row is judged whether partial or complete.
    by_year = {r["year"]: r for r in d["remediation_span_by_year"]}
    for y in (2022, 2023, 2024, 2025):
        assert 14 <= by_year[y]["median_days"] <= 28, (
            f"'from 2022 through 2025 the standing rule was three weeks' vs "
            f"{by_year[y]['median_days']}d in {y}"
        )
    assert 7 <= by_year[2026]["median_days"] <= 21, (
        f"'the 2026 listings are coming in at two' (weeks) vs "
        f"{by_year[2026]['median_days']}d"
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
    # editorial.js (concentration.html): "The volume still belongs to a
    # handful."
    share = d["headline"]["top5_share_latest"]
    assert share >= 40, (
        f"'The volume still belongs to a handful' needs a heavyweight top-5 "
        f"share; data says {share}%"
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
    # editorial.js (concentration entrants): "the three biggest recruiting
    # years on record are 2023, 2024 and 2025". Named years: the partial
    # 2026 (46 newcomers vs 2023's 77) would have failed "the last three
    # complete ones" on 2027-01-01. Judged over complete years only, so a
    # later year out-recruiting them fails this the January it happens.
    rows = complete_years(d["years"])
    top3 = sorted(rows, key=lambda y: y["newcomer_count"], reverse=True)[:3]
    assert {y["year"] for y in top3} == {2023, 2024, 2025}, (
        f"'three biggest recruiting years on record are 2023, 2024 and 2025' — "
        f"top3 by newcomers: {[(y['year'], y['newcomer_count']) for y in top3]}"
    )


def check_concentration_reversal(d: dict) -> None:
    # editorial.js (concentration hero): "the roster grew seventeen-fold
    # between 2015 and 2025, yet in 2025 five of its hundreds of names
    # still shipped a majority of the database, their share climbing for a
    # third straight year". Named years: the partial 2026 (48.0%) would
    # have failed "still ship a majority" on 2027-01-01.
    by_year = {y["year"]: y for y in d["years"]}
    a, b, c = by_year[2023], by_year[2024], by_year[2025]
    assert c["top5_share"] > 50.0, (
        f"'in 2025 … still shipped a majority' vs top5 {c['top5_share']}%"
    )
    assert a["top5_share"] < b["top5_share"] < c["top5_share"], (
        f"'climbing for a third straight year' vs "
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
        "the three biggest recruiting years on record are 2023, 2024 and 2025",
        "cna_concentration.json",
        check_entrants_top3_recruiting,
    ),
    (
        "still shipped a majority of the database, their share climbing for a third straight year",
        "cna_concentration.json",
        check_concentration_reversal,
    ),
    (
        "2026 passed that mark with months of the year to spare",
        "nine_eight_flood.json",
        check_flood_partial_year_mark,
    ),
    (
        "close to four thousand records a year shipped stamped Critical in 2024 and 2025",
        "nine_eight_flood.json",
        check_flood_critical_volume,
    ),
    (
        "About half of all CVEs ship as “High” or worse.",
        "severity_inflation.json",
        check_severity_headline,
    ),
    (
        "six in ten Critical-rated CVEs carry less than a 1% probability of exploitation",
        "score_vs_reality.json",
        check_epss_disconnect,
    ),
    (
        "rises about twentyfold from Low to Critical",
        "score_vs_reality.json",
        check_severity_gradient,
    ),
    (
        "{pct} of actively exploited vulnerabilities are rated below High",
        "score_vs_reality.json",
        check_kev_below_high,
    ),
    (
        "tens of thousands of CVEs were quietly stamped “Deferred”",
        "nvd_decay.json",
        check_deferred_pile,
    ),
    (
        "Some CNAs hand a 9+ to a third or more of the CVEs they score",
        "cna_leaderboard.json",
        check_cna_nine_plus,
    ),
    (
        "Nearly four in ten KEV listings land inside a week.",
        "kev_latency.json",
        check_kev_week_bucket,
    ),
    (
        "One in seven lands three years late.",
        "kev_latency.json",
        check_kev_three_years_late,
    ),
    (
        "and it has been getting slower, not faster.",
        "kev_latency.json",
        check_kev_getting_slower,
    ),
    (
        "from 2022 through 2025 the standing rule was three weeks — and the 2026 listings are coming in at two",
        "kev_latency.json",
        check_kev_three_week_rule,
    ),
    (
        "More assignors than ever.",
        "cna_concentration.json",
        check_more_assignors_than_ever,
    ),
    (
        "The volume still belongs to a handful.",
        "cna_concentration.json",
        check_volume_belongs_to_a_handful,
    ),
    (
        "collapsed from a fifth of everything shipped in 2017 to under two percent by 2023 — and 2024 and 2025 bent it back up",
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
