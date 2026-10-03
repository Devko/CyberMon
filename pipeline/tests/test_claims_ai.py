"""Claims audit for The AI Alibi copy (test_claims_poc.py pattern).

Each entry quotes site/js/editorial.js VERBATIM (test_claims_anchors.py
enforces the anchor) and asserts the committed number still sits in a
range where the sentence stays true. Ranges are calibrated from the
committed edition of 2026-08-01 (92.2% of the gap metric's travel banked
by 2013; 0 of 3 judged metrics accelerated at the ChatGPT cutoff; Agentic
AI 0.0 -> 53.4 index while the clock held a 16-day band; 2 no-uplift
reports dated 2024-02 and 2025-01) and deliberately tolerant — nightly
drift must not trip them, only a claim becoming untrue should.

This module carries more weight than most: the page's whole argument is
that a widely repeated causal story does not survive contact with the
data. If the data ever stops saying that, the copy must change the same
night — so when one of these fails, fix the copy AND this test together,
or fix the pipeline. Never silence it.

Skips itself when site/data holds sample data or the file is missing (the
file first appears after the module's first nightly run).
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
_META = json.loads(_meta_path.read_text("utf-8"))
if _META.get("sample") is True:
    pytest.skip(
        "site/data holds sample data — claims audit only judges real data",
        allow_module_level=True,
    )


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return claims_support.read_json(path)


def _gap_by_year(d: dict) -> dict[int, float]:
    gap = next(m for m in d["clock"]["metrics"] if m["id"] == "poc_gap")
    return {r["year"]: r["value"] for r in gap["years"]}


def _mean(by_year: dict[int, float], start: int, end: int) -> float | None:
    vals = [by_year[y] for y in range(start, end + 1) if y in by_year]
    return sum(vals) / len(vals) if vals else None


# --------------------------------------------------------------------------
# Claim checks (verbatim copy in the comments — grep it in editorial.js).
# --------------------------------------------------------------------------


def check_collapse_finished_a_decade_left_of_the_band(d: dict) -> None:
    # editorial.js (ai.html hero): "a collapse that finished a decade to
    # the left of that band". The band opens at the default cutoff
    # (ChatGPT, 2022) — so a decade to its left is ~2013. (Committed
    # edition 2026-08: 92.2% of the gap metric's travel from its opening
    # level to its pre-cutoff level was done by 2013.)
    by_year = _gap_by_year(d)
    early = _mean(by_year, 1999, 2003)
    decade_left = _mean(by_year, 2009, 2013)
    pre = _mean(by_year, 2017, 2021)
    if early is None or decade_left is None or pre is None:
        pytest.skip("the clock does not yet span 1999-2021")
    travel = pre - early
    assert abs(travel) > 20, (
        f"'a collapse that finished' needs a collapse to have happened; "
        f"the gap metric only travelled {travel:.1f} days"
    )
    done = 100.0 * (decade_left - early) / travel
    assert done >= 80.0, (
        f"'a collapse that finished a decade to the left of that band' "
        f"needs most of the movement banked by 2013; data says {done:.1f}%"
    )


def check_nothing_bends_at_the_cutoff(d: dict) -> None:
    # editorial.js (ai.html · 2 headline): "Nothing bends toward faster at
    # the cutoff." (Exploit-DB-dated clock, 2026-09-22: 0 of 4 judged
    # metric-era cells accelerated; all 4 read "slowed". Was 0 of 7 until
    # the raw metrics stopped counting the provisional 2025 cohort, which
    # withheld their three GPT-4 cells.)
    head = d["headline"]
    assert head["judged"] >= 1, (
        "'Nothing bends toward faster at the cutoff' needs at least one "
        "judged cell to be a statement about anything"
    )
    assert head["accelerated"] == 0, (
        f"'Nothing bends toward faster at the cutoff' is falsified: "
        f"{head['accelerated']} of {head['judged']} judged metric-era "
        f"cells accelerated. Rewrite the page — the data changed sides."
    )


def check_raw_median_moves_later_in_band(d: dict) -> None:
    # editorial.js (ai.html hero): "The raw median made most of its move
    # toward zero by 2013 ... and inside the band it moves later if it
    # moves at all." The raw median is the poc_gap metric, and the band
    # starts at whichever AI-era date the menu picks, so every era with a
    # post level is held to it. (2026-10-03: ChatGPT 1.8 d before, 91.0 d
    # after, "decelerated"; GPT-4 6.0 d → 166.5 d on one settled year, not
    # yet judged; the 2025 cutoff has no post level.) Until 2026-10-03 this
    # read the headline block, which is the like-for-like clock.
    raw = next(m for m in d["banked"]["metrics"] if m["id"] == "poc_gap")
    for era in raw["eras"]:
        assert era["verdict"] != "accelerated", (
            f"'inside the band it moves later if it moves at all' — the raw "
            f"median accelerated at the {era['era']} cutoff: {era}"
        )
        post, pre = era["post"]["value"], era["pre"]["value"]
        if post is None or era["verdict"] == "no_inflection":
            continue
        assert post >= pre, (
            f"'moves later if it moves at all' — at the {era['era']} cutoff "
            f"the raw median went from {pre} d to {post} d"
        )


def _window_means(months: list[dict], width: int = 12) -> tuple[float, float]:
    """Mean index of the first and of the last ``width`` months: a single
    month at either end swings with one conference or one news cycle."""
    first = [m["index"] for m in months[:width]]
    last = [m["index"] for m in months[-width:]]
    return sum(first) / len(first), sum(last) / len(last)


def check_attention_rose_clock_did_not(d: dict) -> None:
    # editorial.js (ai.html · 3): "Attention to AI security rose while the
    # public exploit clock stayed within a narrow band." / "Over the window
    # attention to both terms rose, while the clock's annual median stayed
    # inside a band of days." Both terms (AI Security, Agentic AI) are held
    # to it, each by the mean of its last twelve months against its first
    # twelve, and "rose" means by 10 index points or more. (2026-10-03: AI
    # Security 22.1 → 48.8, Agentic AI 0.0 → 61.1; clock 4.5–11.0 d over
    # 2021–2024.) Until 2026-10-03 the copy said "multiplied" and only the
    # lead term was checked; AI Security's single-month endpoints ran 2.4x
    # (09-29) to 2.7x (10-03), and its start month moves with the window.
    att = d["attention"]
    if not att.get("available") or not att.get("terms"):
        pytest.skip("attention lanes unavailable in this edition")
    head = att["headline"]
    if head is None:
        pytest.skip("no attention headline in this edition")
    for term in att["terms"]:
        if len(term["months"]) < 24:
            pytest.skip(f"{term['label']}: under 24 months of attention")
        first, last = _window_means(term["months"])
        assert last - first >= 10.0, (
            f"'attention to both terms rose' fails for {term['label']}: "
            f"{first:.1f} over its first twelve months, {last:.1f} over its "
            f"last twelve"
        )

    # The overlaid clock is the settled like-for-like series (editions
    # since 2026-09-21), so "a band of days" is a claim about it.
    if att.get("clock_metric") is None:
        pytest.skip("edition predates the like-for-like attention clock")
    band = head["clock_max"] - head["clock_min"]
    assert band <= 21.0, (
        f"'stayed within a narrow band' needs the clock's annual median "
        f"inside three weeks over the same window; it spans {band:.0f} days "
        f"({head['clock_min']:.0f} to {head['clock_max']:.0f})"
    )


def check_clock_varies_under_two_weeks(d: dict) -> None:
    # editorial.js (ai.html · 3 methodology): "Over this window the clock
    # varies by less than two weeks" (2026-10-03: 4.5 d to 11.0 d over
    # 2021–2024, 6.5 days). Was "a few days", held only to 21 days.
    att = d["attention"]
    head = att.get("headline") if att.get("available") else None
    if head is None or att.get("clock_metric") is None:
        pytest.skip("no like-for-like attention clock in this edition")
    band = head["clock_max"] - head["clock_min"]
    assert band < 14.0, (
        f"'varies by less than two weeks' — the clock's annual median spans "
        f"{band:.1f} days over the window ({head['clock_min']} to "
        f"{head['clock_max']})"
    )


def check_attention_window_is_sixty_months(d: dict) -> None:
    # editorial.js (ai.html · 3 methodology): "The window is the market
    # module's 60 months, and the note under the chart gives the month it
    # starts." (2026-10-03: 2021-11 to 2026-09.) Replaced "it starts roughly
    # a year before ChatGPT", which the monthly window outgrows: 12 months
    # before on 2026-10-03, none from late 2027.
    att = d["attention"]
    if not att.get("available"):
        pytest.skip("attention lanes unavailable in this edition")
    assert att["window_months"] == 60, (
        f"'the market module's 60 months' — the window is now "
        f"{att['window_months']} months"
    )
    longest = max(len(t["months"]) for t in att["terms"])
    assert longest <= 60, f"a term carries {longest} months, past the window"
    assert att["headline"] is None or att["headline"]["month_first"] == min(
        t["months"][0]["month"] for t in att["terms"]), (
        "the note's start month must be the window's first month"
    )


def check_cohort_rate_2008_to_2024(d: dict) -> None:
    # editorial.js (ai.html · 2 methodology): "That rate was about 45% for
    # CVEs published in 2008 and 2009 and under 1% for those published in
    # 2024: over those years annual CVE volume grew from roughly 5,700 to
    # 40,000, and the number of CVEs whose public exploit Exploit-DB dates
    # fell to under a tenth of its 2008 level." (2026-10-03: 2,550 of 5,673
    # = 44.9% and 2,634 of 5,732 = 46.0%; 154 of 39,924 = 0.4%; 154 is 6.0%
    # of 2,550.) Until 2026-10-03 the copy said "across the record" (true
    # only while the record ended in 2024) and gave the fall as "almost
    # entirely because" volume grew, when volume grew 7x and the dated
    # cohort shrank 17x.
    volume = {r["year"]: r["published"]
              for r in load("volume_curve.json")["years"]}
    dated = {r["year"]: r["n"] for r in next(
        m for m in d["clock"]["metrics"] if m["id"] == "poc_gap")["years"]}
    for year in (2008, 2009):
        rate = 100.0 * dated[year] / volume[year]
        assert 40.0 <= rate < 50.0, (
            f"'about 45% for CVEs published in 2008 and 2009' — {year} is "
            f"{rate:.1f}% ({dated[year]} of {volume[year]})"
        )
        assert 5200 <= volume[year] <= 6200, (
            f"'roughly 5,700' — {year} volume is {volume[year]}"
        )
    rate = 100.0 * dated[2024] / volume[2024]
    assert rate < 1.0, (
        f"'under 1% for those published in 2024' — it is {rate:.2f}%"
    )
    assert 37000 <= volume[2024] <= 43000, (
        f"'roughly ... 40,000' — 2024 volume is {volume[2024]}"
    )
    assert dated[2024] < 0.1 * dated[2008], (
        f"'fell to under a tenth of its 2008 level' — {dated[2024]} vs "
        f"{dated[2008]}"
    )


def check_dated_cohort_well_under_a_fifth(d: dict) -> None:
    # editorial.js (ai.html hero methodology): "the dated cohort per year is
    # well under a fifth of its late-2000s size". "Well under" is held to an
    # eighth of the 2005–2009 mean. (2026-10-03: the latest settled year,
    # 2024, has 154 against a 2005–2009 mean of 2,473, 6.2%.) The copy test
    # check_exploitdb_thinned holds only peak >= 5x latest.
    rows = next(m for m in d["clock"]["metrics"]
                if m["id"] == "poc_gap")["years"]
    late_2000s = [r["n"] for r in rows if 2005 <= r["year"] <= 2009]
    latest = [r for r in rows if not r["provisional"]][-1]
    mean = sum(late_2000s) / len(late_2000s)
    assert latest["n"] < mean / 8, (
        f"'well under a fifth of its late-2000s size' — {latest['year']} has "
        f"{latest['n']} against a 2005–2009 mean of {mean:.0f} "
        f"({100 * latest['n'] / mean:.1f}%)"
    )


def check_chatgpt_none_earlier_later_dates_by_rule(d: dict) -> None:
    # editorial.js (home card, AI and PoC Timing): "At the ChatGPT date none
    # of the judged measures moved earlier; each later date is judged once
    # two complete, settled years follow it." (2026-10-03: ChatGPT 4 of 4
    # judged, all later; GPT-4 has one settled year after it and is
    # withheld, until about the 2027-03-31 nightly settles 2025; the 2025
    # cutoff has none.) Replaced "the later dates do not yet have enough
    # complete years to judge", which GPT-4 outgrows then.
    judged = 0
    for metric in d["banked"]["metrics"]:
        for era in metric["eras"]:
            settled = era["post"]["years"]
            if era["era"] == "chatgpt":
                assert era["verdict"] != "accelerated", (
                    f"'At the ChatGPT date none of the judged measures moved "
                    f"earlier' — {metric['id']} did: {era}"
                )
                judged += era["verdict"] != "insufficient"
                continue
            assert (era["verdict"] == "insufficient") == (settled < 2), (
                f"'each later date is judged once two complete, settled "
                f"years follow it' — {metric['id']} at {era['era']} has "
                f"{settled} settled year(s) and verdict {era['verdict']!r}"
            )
    assert judged >= 1, "no measure is judged at the ChatGPT date"


def check_two_shops_found_no_uplift(d: dict) -> None:
    # editorial.js (ai.html hero methodology): "the two largest vendor
    # threat-intel shops looked specifically for offensive capability
    # uplift in 2024 and early 2025 and reported finding none". (Committed
    # timeline: Microsoft+OpenAI 2024-02-14, Google GTIG 2025-01.)
    no_uplift = [m for m in d["milestones"] if m["kind"] == "no_uplift"]
    assert len(no_uplift) >= 2, (
        f"'the two largest vendor threat-intel shops' needs at least two "
        f"no-uplift rows on the timeline; found {len(no_uplift)}"
    )
    years = {m["date"][:4] for m in no_uplift}
    assert {"2024", "2025"} <= years, (
        f"the claim dates those findings to 2024 and early 2025; the "
        f"committed timeline carries no-uplift rows for {sorted(years)}"
    )
    assert d["headline"]["no_uplift_reports"] == len(no_uplift), (
        "the hero stat counts no-uplift reports and must agree with the "
        "timeline it counts"
    )


def check_every_milestone_is_sourced(d: dict) -> None:
    # editorial.js (ai.html hero): "Every dot is dated, categorised and
    # linked below the chart." The rail is the module's audit trail — an
    # unsourced marker would make it decoration.
    unsourced = [m["label"] for m in d["milestones"]
                 if not m.get("source", "").startswith("https://")]
    assert not unsourced, (
        f"'Every dot is dated, categorised and linked' is falsified by "
        f"unsourced milestones: {unsourced}"
    )


def check_newest_milestones_sit_past_the_testable_edge(d: dict) -> None:
    # editorial.js (ai.html hero): "the 2026 milestones … sit beyond what
    # this page can test". The claim is structural — the timeline must
    # run past the clock's last complete year, or the sentence describes a
    # gap that isn't there. It is pinned to 2026 ON PURPOSE: on 2027-01-01
    # the clock absorbs 2026 and this guard fails, which is the intended
    # trigger to re-examine the argument against 2026's completed data
    # (not a calendar accident — the copy must change then, not the test).
    last_year = d["clock"]["last_year"]
    assert last_year < 2026, (
        f"'the 2026 milestones sit beyond what this page can test' — the "
        f"clock now ends {last_year}, so 2026 is inside the tested span; "
        f"re-examine the AI Alibi argument against 2026 and rewrite the hero"
    )
    beyond = [m for m in d["milestones"] if int(m["date"][:4]) > last_year]
    assert beyond, (
        f"'sit beyond what this page can test' needs at least one milestone "
        f"after the clock's last complete year ({last_year}); "
        f"the timeline ends at {d['milestones'][-1]['date']}"
    )


def check_like_for_like_holds_a_narrow_band(d: dict) -> None:
    # editorial.js (ai.html hero): "every settled year since 2005 has sat
    # inside a three-week band around zero". The like-for-like clock is
    # the page's strongest evidence, so its headline description gets a
    # hard check — over SETTLED years only, because the copy says so and
    # a cohort still being indexed reads slow by construction.
    # (Exploit-DB-dated clock, 2026-09-21: settled 2005-2024 medians run
    # -8d to +11d, a 19-day spread.)
    if d.get("attention", {}).get("clock_metric") is None:
        pytest.skip("edition predates the Exploit-DB-only clock")
    rows = [r for r in d.get("like_for_like", {}).get("years", [])
            if r["year"] >= 2005 and not r.get("provisional")]
    if len(rows) < 5:
        pytest.skip("like-for-like series too short to judge")
    lo = min(r["value"] for r in rows)
    hi = max(r["value"] for r in rows)
    assert hi - lo <= 21.0, (
        f"'inside a three-week band' needs the settled like-for-like "
        f"medians within 21 days of each other; they span {lo:+.0f}d to "
        f"{hi:+.0f}d ({hi - lo:.0f} days)"
    )
    # And the band must straddle zero — "arming happens at disclosure" is
    # the claim, not "arming happens two weeks late".
    assert lo <= 0.0 <= hi, (
        f"the band should contain zero; it runs {lo:+.0f}d to {hi:+.0f}d"
    )


CLAIMS = [
    (
        "median made most of its move toward zero by 2013, a decade before the ChatGPT band opens",
        "ai_alibi.json",
        check_collapse_finished_a_decade_left_of_the_band,
    ),
    (
        "No judged timing metric moved toward earlier public exploit code after the cutoff.",
        "ai_alibi.json",
        check_nothing_bends_at_the_cutoff,
    ),
    (
        "inside the band it moves later if it moves at all",
        "ai_alibi.json",
        check_raw_median_moves_later_in_band,
    ),
    (
        "Attention to AI security rose while the public exploit clock stayed within a narrow band.",
        "ai_alibi.json",
        check_attention_rose_clock_did_not,
    ),
    (
        "attention to both terms rose, while the clock's annual median stayed inside a band of days",
        "ai_alibi.json",
        check_attention_rose_clock_did_not,
    ),
    (
        "Over this window the clock varies by less than two weeks",
        "ai_alibi.json",
        check_clock_varies_under_two_weeks,
    ),
    (
        "The window is the market module's 60 months, and the note under the chart gives the month it starts.",
        "ai_alibi.json",
        check_attention_window_is_sixty_months,
    ),
    (
        "That rate was about 45% for CVEs published in 2008 and 2009 and under 1% for those published in 2024: over those years annual CVE volume grew from roughly 5,700 to 40,000, and the number of CVEs whose public exploit Exploit-DB dates fell to under a tenth of its 2008 level.",
        "ai_alibi.json",
        check_cohort_rate_2008_to_2024,
    ),
    (
        "the dated cohort per year is well under a fifth of its late-2000s size",
        "ai_alibi.json",
        check_dated_cohort_well_under_a_fifth,
    ),
    (
        "At the ChatGPT date none of the judged measures moved earlier; each later date is judged once two complete, settled years follow it.",
        "ai_alibi.json",
        check_chatgpt_none_earlier_later_dates_by_rule,
    ),
    (
        "the largest vendor threat-intelligence teams looked specifically for offensive capability uplift in 2024 and early 2025 and reported finding none",
        "ai_alibi.json",
        check_two_shops_found_no_uplift,
    ),
    (
        "Every dot is dated, categorised and linked below the chart.",
        "ai_alibi.json",
        check_every_milestone_is_sourced,
    ),
    (
        "sit beyond what this page can test",
        "ai_alibi.json",
        check_newest_milestones_sit_past_the_testable_edge,
    ),
    (
        "every settled year since 2005 has sat inside a three-week band",
        "ai_alibi.json",
        check_like_for_like_holds_a_narrow_band,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
