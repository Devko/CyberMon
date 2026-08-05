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


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return json.loads(path.read_text("utf-8"))


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
    # editorial.js (ai.html · 2 headline): "Nothing bends at the cutoff."
    # (Committed edition 2026-08: 0 of 3 judged metric-era cells at the
    # default cutoff accelerated; across all cutoffs, 0 of 6.)
    head = d["headline"]
    assert head["judged"] >= 1, (
        "'Nothing bends at the cutoff' needs at least one judged cell to "
        "be a statement about anything"
    )
    assert head["accelerated"] == 0, (
        f"'Nothing bends at the cutoff' is falsified: "
        f"{head['accelerated']} of {head['judged']} judged metric-era "
        f"cells accelerated. Rewrite the page — the data changed sides."
    )


def check_headline_metric_shows_no_inflection(d: dict) -> None:
    # editorial.js (ai.html hero): "a line that does nothing in particular
    # once it enters". (Committed edition 2026-08: the gap metric's
    # verdict at the default ChatGPT cutoff is no_inflection, on a shift
    # of +0.1% of its total travel.)
    head = d["headline"]
    assert head["verdict"] in {"no_inflection", "decelerated"}, (
        f"'a line that does nothing in particular once it enters' needs "
        f"the headline metric to show no acceleration at the default "
        f"cutoff; verdict is {head['verdict']!r}"
    )


def check_attention_multiplied_clock_did_not(d: dict) -> None:
    # editorial.js (ai.html · 3): "One of these multiplied. The other
    # stayed inside a band of days." (Committed edition 2026-08: Agentic
    # AI runs 0.0 -> 53.4 on the composite index while the clock's annual
    # median holds a 16-day band, -12d to +4d.)
    att = d["attention"]
    if not att.get("available") or not att.get("terms"):
        pytest.skip("attention lanes unavailable in this edition")
    head = att["headline"]
    if head is None:
        pytest.skip("no attention headline in this edition")

    rise = head["index_last"] - head["index_first"]
    assert rise >= 20.0, (
        f"'One of these multiplied' needs a real climb on the attention "
        f"index; the lead term moved {rise:+.1f} points"
    )
    # "Multiplied" in the ordinary sense, for any lane that started above
    # zero — the lead term may legitimately start at a flat 0 (Agentic AI
    # has no coverage in any lane before 2022), where a ratio is undefined
    # and the absolute climb above already carries the claim.
    if head["index_first"] > 1.0:
        ratio = head["index_last"] / head["index_first"]
        assert ratio >= 2.0, (
            f"'One of these multiplied' claims a multiple; the lead term "
            f"grew {ratio:.1f}x"
        )

    band = head["clock_max"] - head["clock_min"]
    assert band <= 45.0, (
        f"'The other stayed inside a band of days' needs the clock's "
        f"annual median inside a narrow band over the same window; it "
        f"spans {band:.0f} days ({head['clock_min']:.0f} to "
        f"{head['clock_max']:.0f})"
    )


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
    # editorial.js (ai.html hero): "sit past the edge of anything this page
    # can test". The claim is structural — the timeline must actually run
    # past the clock's last complete year, or the sentence describes a gap
    # that isn't there. (Committed edition 2026-08: the clock ends 2025 and
    # four 2026 rows sit beyond it.)
    last_year = d["clock"]["last_year"]
    beyond = [m for m in d["milestones"] if int(m["date"][:4]) > last_year]
    assert beyond, (
        f"'sit past the edge of anything this page can test' needs at least "
        f"one milestone after the clock's last complete year ({last_year}); "
        f"the timeline ends at {d['milestones'][-1]['date']}"
    )


CLAIMS = [
    (
        "a collapse that finished a decade to the left of that band",
        "ai_alibi.json",
        check_collapse_finished_a_decade_left_of_the_band,
    ),
    (
        "Nothing bends at the cutoff.",
        "ai_alibi.json",
        check_nothing_bends_at_the_cutoff,
    ),
    (
        "a line that does nothing in particular once it enters",
        "ai_alibi.json",
        check_headline_metric_shows_no_inflection,
    ),
    (
        "One of these multiplied. The other stayed inside a band of days.",
        "ai_alibi.json",
        check_attention_multiplied_clock_did_not,
    ),
    (
        "the two largest vendor threat-intel shops looked specifically for "
        "offensive capability uplift in 2024 and early 2025 and reported "
        "finding none",
        "ai_alibi.json",
        check_two_shops_found_no_uplift,
    ),
    (
        "Every dot is dated, categorised and linked below the chart.",
        "ai_alibi.json",
        check_every_milestone_is_sourced,
    ),
    (
        "sit past the edge of anything this page can test",
        "ai_alibi.json",
        check_newest_milestones_sit_past_the_testable_edge,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
