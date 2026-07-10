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
GENERATION_YEAR = int(_META["generated_at"][:4])


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
    # editorial.js (cve.html hero): "Four of every ten CVEs ship as
    # “High” or worse."
    pct = d["headline"]["pct_high_critical_latest"]  # share ≥ 7.0, latest complete year
    assert 33 <= pct <= 55, (
        f"'Four of every ten CVEs ship as High or worse' claims ~40%; "
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
    # editorial.js (CNA leaderboard): "Some CNAs hand a 9+ to two of every
    # five CVEs they score"
    top = max(c["pct_geq_9"] for c in d["cnas"])
    assert 30 <= top <= 60, (
        f"'a 9+ to two of every five CVEs' claims a ~40% top share; "
        f"data's max per-CNA pct_geq_9 is {top}%"
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
    # editorial.js (kev.html remediation): "the standing rule since has
    # been three weeks."
    rows = complete_years(d["remediation_span_by_year"])
    assert rows, "no complete years in remediation_span_by_year"
    latest = max(rows, key=lambda r: r["year"])
    assert 14 <= latest["median_days"] <= 28, (
        f"'the standing rule since has been three weeks' claims a ~21-day "
        f"median; data says {latest['median_days']}d for {latest['year']}"
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


def check_rejections_keep_shrinking(d: dict) -> None:
    # editorial.js (volume curve): the rejection share "runs far below what
    # it was five years ago" — "far below" is enforced as at most 80% of
    # the five-years-ago share, not merely smaller.
    rows = complete_years(d["years"])
    latest = max(rows, key=lambda r: r["year"])
    earlier = next((r for r in rows if r["year"] == latest["year"] - 5), None)
    assert earlier is not None, (
        f"no data for {latest['year'] - 5} to compare rejection share against"
    )

    def share(r: dict) -> float:
        total = r["published"] + r["rejected"]
        return 100.0 * r["rejected"] / total if total else 0.0

    assert share(latest) < 0.8 * share(earlier), (
        f"'far below what it was five years ago' needs {latest['year']}'s "
        f"rejection share ({share(latest):.2f}%) well under "
        f"{earlier['year']}'s ({share(earlier):.2f}%)"
    )


def check_flood_critical_volume(d: dict) -> None:
    # editorial.js (9.8 flood caption): "nearly four thousand records a
    # year now ship stamped Critical". Bounded both ways: under 3,000 the
    # claim inflates, past ~4,400 "nearly four thousand" understates.
    rows = complete_years(d["years"])
    latest = max(rows, key=lambda r: r["year"])
    assert 3000 <= latest["critical"] <= 4400, (
        f"'nearly four thousand … Critical' vs {latest['critical']} "
        f"in {latest['year']}"
    )


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion) — one row per
# sentence the site commits to. Keep the claim text greppable.
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "nearly four thousand records a year now ship stamped Critical",
        "nine_eight_flood.json",
        check_flood_critical_volume,
    ),
    (
        "Four of every ten CVEs ship as “High” or worse.",
        "severity_inflation.json",
        check_severity_headline,
    ),
    (
        "six in ten Critical-rated CVEs carry less than a 1% probability of exploitation",
        "score_vs_reality.json",
        check_epss_disconnect,
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
        "Some CNAs hand a 9+ to two of every five CVEs they score",
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
        "the standing rule since has been three weeks.",
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
        "as a share of what ships, it keeps shrinking",
        "volume_curve.json",
        check_rejections_keep_shrinking,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
