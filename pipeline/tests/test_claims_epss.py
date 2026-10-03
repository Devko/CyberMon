"""Claims audit for the EPSS Report Card module (pattern: test_claims_audit).

The epss.html copy (site/js/editorial.js) makes verbal claims about
numbers in site/data/epss_report.json, and that file refreshes nightly.
Each CLAIMS entry quotes the copy verbatim (grep for it in editorial.js)
and asserts the underlying number still sits in a range where the sentence
remains true. Ranges are deliberately tolerant — normal drift must not
trip them; only a claim becoming untrue should — and were sanity-checked
against live day-before lookups at build time (2026-07-10; FIRST API):

* 40 most recent KEV entries: 31 graded, of which 65% below 1% and 58%
  in the model's bottom half; 9 of 40 had no possible prior score;
* random 60 of the 2025 additions: 44 graded, 61% below 1%, 45% bottom
  half;
* random 60 of the 2021-11-03 launch batch: 57 graded, 28% below 1%,
  25% bottom half — the seeding era grades BETTER (old CVEs, years of
  accumulated signal), so cohort-wide numbers sit between the two eras.

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim + range, in the same
commit) or the pipeline broke (fix the pipeline). NEVER silence or delete
a failing claim check without doing one of the two.

Skips itself when site/data/ holds sample data, the files are missing, or
the module's backfill has not meaningfully completed — this audit only
ever judges committed real data with a real cohort behind it.
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


def graded_report() -> dict:
    """The report, but only once the backfill has substance: judging copy
    against a three-entry partial state would produce noise, not audit."""
    d = load("epss_report.json")
    catalog = d.get("catalog", {})
    if catalog.get("graded", 0) < 200:
        pytest.skip(
            f"epss_report.json has only {catalog.get('graded', 0)} graded "
            f"entries — claims audit waits for the historical backfill"
        )
    return d


# --------------------------------------------------------------------------
# Claim checks (assertion messages restate the claim so a failure reads as
# "this sentence is no longer true", not as a raw number).
# --------------------------------------------------------------------------


def check_flip_coincides_with_model_change(d: dict) -> None:
    # editorial.js (epss.html hero): "the sharp 2022-to-2023 flip in the
    # bars coincides with a model change (v2 to v3, March 2023)" — the era
    # table must carry a boundary in March 2023 for that to be true.
    starts = [e["from"] for e in d["model_eras"] if e.get("label") == "v3"]
    assert starts and starts[0].startswith("2023-03"), (
        f"'a model change (v2 to v3, March 2023)' vs v3 era starting {starts}"
    )


# The current listing year joins "recent" once it holds this many scored
# entries: about half a year of KEV additions at the 2025-26 pace (184 and
# 180 scored). Below it a few weeks of listings can put the share anywhere.
RECENT_MIN_SCORED = 100


def check_most_recent_below_1pct(d: dict) -> None:
    # editorial.js (epss.html hero + home card): "Roughly half or more of
    # recent KEV additions scored under 1% the day before listing" / "had
    # an EPSS score under 1% the day before listing". Recent = the last
    # three complete listing years, plus the current year once it holds
    # RECENT_MIN_SCORED scored entries; each must sit at 45% or more.
    # 2026-10-03: 2023 66.7%, 2024 63.2%, 2025 59.2%, 2026 52.2% (n=180;
    # 47.0-52.2% since July). In January 2027 the window becomes 2024-26.
    # Until 2026-10-03 this read only the latest complete year, with a 40%
    # floor, below what "roughly half" can carry.
    rows = [r for r in d["grade_by_year"] if r["graded"] >= d["min_n"]]
    complete = claims_support.complete_years(rows)[-3:]
    current = [r for r in rows if r["year"] == claims_support.GENERATION_YEAR
               and claims_support.judged(r["year"], r["graded"],
                                         min_n=RECENT_MIN_SCORED)]
    recent = complete + current
    assert len(complete) == 3, [r["year"] for r in rows]
    low = [(r["year"], r["pct_below_1pct"], r["graded"]) for r in recent
           if r["pct_below_1pct"] < 45.0]
    assert not low, (
        f"'roughly half or more of recent KEV additions scored under 1%' "
        f"needs 45% or more in each of {[r['year'] for r in recent]}; "
        f"below it (year, %, n): {low}"
    )


def _below_1pct(d: dict, model: str) -> tuple[float, int, int]:
    row = next(m for m in d["distribution"]["by_model"]
               if m["model"] == model)
    below = row["counts"]["<0.1%"] + row["counts"]["0.1-1%"]
    return 100.0 * below / row["n"], below, row["n"]


def check_models_split_at_1pct(d: dict) -> None:
    # editorial.js (epss.html distribution headline): "EPSS v2 scored most
    # of these entries above 1%; v3 scored most below, and v4 about half."
    # Closed eras, so these only move if KEV drops or re-dates entries.
    # 2026-10-03: v2 22 of 492 below 1% (4.5%), v3 196 of 283 (69.3%), v4
    # 126 of 243 (51.9%). It said "v3 and v4 scored most below" until
    # 2026-10-03; v4's majority was five entries.
    v2, _, _ = _below_1pct(d, "v2")
    v3, _, _ = _below_1pct(d, "v3")
    v4, below4, n4 = _below_1pct(d, "v4")
    assert v2 < 50.0, f"'EPSS v2 scored most of these entries above 1%' — {100 - v2:.1f}% above"
    assert v3 > 50.0, f"'v3 scored most below' — {v3:.1f}% below 1%"
    assert 45.0 <= v4 <= 55.0, (
        f"'and v4 about half' — {below4} of {n4} ({v4:.1f}%) below 1%")


def check_v5_more_than_half_below(d: dict) -> None:
    # editorial.js (epss.html distribution caption): "The v5 model has been
    # in use since June 2026, and so far more than half of its small cohort
    # scored below 1%." 2026-10-03: 43 of 77 (55.8%); 54.7-55.8% on every
    # edition since 09-23. The share has risen as the cohort grew (19 of 40
    # on 08-25, 31 of 62 on 09-11): 22 of the last 28 v5 entries scored
    # below 1%. It said "shows the same pattern so far" until 2026-10-03.
    era = next(e for e in d["model_eras"] if e["label"] == "v5")
    assert era["from"].startswith("2026-06"), (
        f"'in use since June 2026' — the v5 era starts {era['from']}")
    pct, below, n = _below_1pct(d, "v5")
    assert pct > 50.0, (
        f"'so far more than half of its small cohort scored below 1%' — "
        f"{below} of {n} ({pct:.1f}%)")


def check_every_scored_entry_has_a_percentile(d: dict) -> None:
    # editorial.js (epss.html percentile methodology): "Every scored entry
    # carries a day-before percentile, so this chart covers the same
    # entries as the two probability charts." 2026-10-03: 1,414 of 1,414
    # (equal on every edition since 08-25). The copy used to say some
    # early-era entries lacked one and that their count was in the data
    # file; neither was true.
    assert d["percentiles"]["n"] == d["catalog"]["graded"], (
        f"'Every scored entry carries a day-before percentile' — "
        f"{d['percentiles']['n']} percentiles for "
        f"{d['catalog']['graded']} scored entries"
    )


def check_hundred_thousand_ranked_above(d: dict) -> None:
    # editorial.js (epss.html percentile caption): "for a typical entry in
    # that half, more than a hundred thousand CVEs ranked above it on the
    # day before listing". The report carries percentiles but not the size
    # of each day's scored set, so this uses a floor for it: the CVE
    # records published before the score date's year (volume_curve.json),
    # all of which EPSS had scored by then. CVEs ranked above an entry =
    # (1 - percentile) x that floor; the median over bottom-half entries
    # must exceed 100,000. 2026-10-03: 158,476 (floors 146,780 for 2021 up
    # to 308,879 for 2026), so the true figure is higher still.
    vol = load("volume_curve.json")
    published = {r["year"]: r["published"] for r in vol["years"]}

    def floor(score_date: str) -> int:
        year = int(score_date[:4])
        return sum(n for y, n in published.items() if y < year)

    above = sorted((1.0 - e["percentile"]) * floor(e["score_date"])
                   for e in d["entries"]
                   if e.get("percentile") is not None
                   and e["percentile"] < 0.5)
    assert above, "no bottom-half entries — nothing carries the claim"
    median = above[len(above) // 2] if len(above) % 2 else \
        (above[len(above) // 2 - 1] + above[len(above) // 2]) / 2
    assert median > 100_000, (
        f"'more than a hundred thousand CVEs ranked above it' — the median "
        f"bottom-half entry has at least {median:,.0f} above it"
    )


def check_bottom_half_share(d: dict) -> None:
    # editorial.js (epss.html percentile section): "about three in ten of
    # the graded cohort sat in the bottom half" — live value at last copy
    # edit: 30.1% cohort-wide.
    pct = d["percentiles"]["bottom_half"]["pct"]
    assert 25.0 <= pct <= 35.0, (
        f"'about three in ten of the graded cohort sat in the bottom half' "
        f"needs the cohort-wide bottom-half share ({pct}%) to stay in "
        f"that neighbourhood"
    )


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "coincides with a model change (v2 to v3, March 2023)",
        check_flip_coincides_with_model_change,
    ),
    (
        "Roughly half or more of recent KEV additions scored under 1% the day before listing",
        check_most_recent_below_1pct,
    ),
    (
        "Roughly half or more of recent KEV additions had an EPSS score under 1% the day before listing.",
        check_most_recent_below_1pct,
    ),
    (
        "About three in ten scored KEV additions ranked in EPSS's bottom half",
        check_bottom_half_share,
    ),
    (
        "EPSS v2 scored most of these entries above 1%; v3 scored most below, and v4 about half.",
        check_models_split_at_1pct,
    ),
    (
        "The v5 model has been in use since June 2026, and so far more than "
        "half of its small cohort scored below 1%.",
        check_v5_more_than_half_below,
    ),
    (
        "Every scored entry carries a day-before percentile, so this chart "
        "covers the same entries as the two probability charts.",
        check_every_scored_entry_has_a_percentile,
    ),
    (
        "for a typical entry in that half, more than a hundred thousand CVEs "
        "ranked above it on the day before listing",
        check_hundred_thousand_ranked_above,
    ),
]


@pytest.mark.parametrize(
    ("claim", "check"),
    CLAIMS,
    ids=[c[1].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, check) -> None:
    check(graded_report())
