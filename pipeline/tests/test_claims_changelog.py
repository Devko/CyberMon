"""Claims audit for the KEV Changelog module (pattern: test_claims_audit).

The changelog.html copy (site/js/editorial.js) makes verbal claims about
numbers in site/data/kev_changelog.json, and that file refreshes nightly.
Each CLAIMS entry quotes the copy verbatim (grep for it in editorial.js)
and asserts the underlying number still sits in a range where the sentence
remains true. Ranges are deliberately tolerant — normal drift must not
trip them; only a claim becoming untrue should — and were calibrated
against a full live Wayback backfill trial at build time (2026-07-11; 53
usable captures, 2021-12-23 through 2026-07):

* 4,240 events on record: 1,335 additions (excluded from edits), 2,905
  edits, 9 removals — all of them documented public incidents (Owl Labs,
  D-Link DIR-816L, GPAC, Chromium CVE-2025-4664, Rapid7 Velociraptor);
* 285 Unknown->Known ransomware flips, zero reversals; lag from listing
  to observed flip: median 626 days, p25 400, p75 768 (the October 2023
  introduction of the flag column contributes a ~200-flip step, dated to
  the first capture carrying the column);
* most-edited entry: 12 logged edits (Ivanti Pulse Connect Secure);
  bulk-revision waves of 279/691/1,170 text edits in single capture
  months (2022-04, 2023-06, 2024-09).

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim + range, in the same
commit) or the pipeline broke (fix the pipeline). NEVER silence or delete
a failing claim check without doing one of the two.

Skips itself when site/data/ holds sample data, the files are missing, or
the record has no meaningful backfill behind it — this audit only ever
judges committed real data with a real record behind it.
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


def backfilled_changelog() -> dict:
    """The changelog, but only once the record has substance: judging the
    copy against a baseline-night file would produce noise, not audit."""
    d = load("kev_changelog.json")
    events = d.get("catalog", {}).get("events_total", 0)
    if events < 500:
        pytest.skip(
            f"kev_changelog.json has only {events} events on record — "
            f"claims audit waits for the Wayback backfill"
        )
    return d


# --------------------------------------------------------------------------
# Claim checks (assertion messages restate the claim so a failure reads as
# "this sentence is no longer true", not as a raw number).
# --------------------------------------------------------------------------


def check_hundred_flips_after_listing(d: dict) -> None:
    # editorial.js (changelog.html flag section headline, 2026-11-04): "CISA
    # has changed the ransomware flag to “Known” on more than a hundred KEV
    # entries after listing them." Flips after the step month only (the
    # step records the new column, not reassessments). The ledger is
    # append-only, so the count can only grow. 2026-11-04: 111 (206 in the
    # step). It said "CISA often adds the ransomware flag months or years
    # after listing" until 2026-11-04; section 03 owns the timing.
    flips = d["flips"]
    step = flips.get("step_month_flips", flips["by_month"][0]["flips"])
    after = flips.get("total_after_step", flips["total"] - step)
    claims_support.record(after, lo=100, unit="flips",
                          note="after the step month")
    assert after > 100, (
        f"'more than a hundred KEV entries' flipped after listing — the "
        f"record holds {after} flips after the {flips.get('step_month')} step"
    )


def check_flags_often_a_year_late(d: dict) -> None:
    # editorial.js (kev.html ransomware caption, 2026-11-04): "CISA sets
    # some flags after listing, often more than a year later". "Often" is
    # held to at least a third of the post-step flips landing more than 365
    # days after dateAdded, and to at least a third of the day-accurate
    # nightly-diff flips too, so capture dating alone cannot carry it.
    # 2026-11-04: 60 of 111 (54%); nightly 20 of 33. Recent listings flip
    # faster (2026 listing-year median 34 days), so this share will drift
    # down. The caption said "frequently more than a year later" unguarded
    # until 2026-11-04.
    lag = d.get("flag_lag")
    if lag is None:
        pytest.skip("kev_changelog.json predates the flag_lag block")
    n = lag["n_capture"] + lag["n_daily"]
    assert n >= 25, f"'often more than a year later' rests on {n} flips"
    late = sum(b["capture"] + b["daily"] for b in lag["buckets"]
               if b["lo"] > 365)
    late_daily = sum(b["daily"] for b in lag["buckets"] if b["lo"] > 365)
    assert late / n >= 1 / 3, (
        f"'often more than a year later' — {late} of {n} post-step flips "
        f"came more than a year after listing")
    assert lag["n_daily"] and late_daily / lag["n_daily"] >= 1 / 3, (
        f"'often more than a year later' — {late_daily} of {lag['n_daily']} "
        f"nightly-diff flips came more than a year after listing")


def check_step_is_set_apart(d: dict) -> None:
    # editorial.js (changelog.html flag section stat note): "not counting
    # the {step_flips} flips logged together in {step_month}, the month
    # the flag column first appears in the captures" — the headline count
    # is the record minus the step. The step must be real (trial: 206 of
    # the first 308 flips in 2023-12) and what remains a real cohort, not
    # an anecdote. Editions before 2026-09-20 lack the split keys; the
    # site derives the same split from by_month, so the audit does too.
    flips = d["flips"]
    step_month = flips.get("step_month")
    assert step_month, (
        "the note names the step month, but the record has none"
    )
    first = flips["by_month"][0]
    step_flips = flips.get("step_month_flips", first["flips"])
    after = flips.get("total_after_step", flips["total"] - step_flips)
    assert first["month"] == step_month and step_flips == first["flips"], (
        f"the step month {step_month} must be the first month of the "
        f"series with {first['flips']} flips (got {step_flips})"
    )
    assert step_flips >= 25, (
        f"'flips logged together in {step_month}' describes a schema step, "
        f"not {step_flips} flips"
    )
    assert after >= 25, (
        f"'entries flipped to Known after they were already listed' needs "
        f"a real cohort beyond the step ({after} flips is an anecdote)"
    )
    assert step_flips + after == flips["total"], (
        "the step and the headline count must reconcile with the ledger"
    )


def check_every_edit_kind_exists(d: dict) -> None:
    # editorial.js (module card 12 blurb): "due dates that moved,
    # ransomware flags that flipped, descriptions that were rewritten,
    # entries that quietly vanished" — each named kind must exist in the
    # record (trial: 20 due-date moves, 285 flips, ~2,590 text revisions,
    # 9 removals).
    totals = {"due_date": 0, "ransomware_flag": 0, "text": 0, "removed": 0}
    for row in d["months"]:
        for key in totals:
            totals[key] += row[key]
    for key, n in totals.items():
        claims_support.record(n, lo=1, unit="events", note=key)
        assert n >= 1, (
            f"the module blurb names every edit kind, but the record "
            f"holds zero '{key}' events — trim the blurb or fix the diff"
        )


def check_additions_excluded(d: dict) -> None:
    # editorial.js (changelog.html hero stat note): "new listings excluded:
    # {additions}" (the caption also said "New listings are not counted"
    # until 2026-11-04) — the exclusion must be real and disclosed (trial:
    # 1,335 additions).
    catalog = d["catalog"]
    assert catalog["additions_excluded"] >= 100, (
        f"'new listings are deliberately not counted' implies a "
        f"meaningful excluded count ({catalog['additions_excluded']})"
    )
    assert catalog["edits_total"] + catalog["additions_excluded"] == \
        catalog["events_total"], (
        "the exclusion arithmetic no longer adds up — the audit block "
        "must always reconcile"
    )


def check_entries_never_stop_changing(d: dict) -> None:
    # editorial.js (changelog.html receipts): "Some KEV entries have been
    # edited eight or more times after listing" — the board's top entry
    # (2026-09-23: every one of the top 12 has 8 or more edits).
    board = d["board"]["most_edited"]
    assert board, "the most-edited claim with an empty board"
    claims_support.record(board[0]["edits"], lo=8, unit="edits",
                          note=board[0]["cve"])
    assert board[0]["edits"] >= 8, (
        f"'edited eight or more times' needs the most-edited entry "
        f"({board[0]['cve']}, {board[0]['edits']} edits) to have a real "
        f"revision history"
    )


def check_removals_are_named(d: dict) -> None:
    # editorial.js (changelog.html receipts): "every entry observed
    # leaving the catalog" is listed — the record holds real removals
    # (trial: 9, including the Owl Labs and Chromium withdrawals), and
    # each row carries a name and a date.
    removals = d["board"]["removals"]
    assert len(removals) >= 1, (
        "'entries that quietly vanished' needs at least one observed "
        "removal on record"
    )
    for row in removals:
        assert row["cve"] and row["removed"], (
            f"a removal row must name its CVE and removal date: {row!r}"
        )


def check_flag_lag_lands_late(d: dict) -> None:
    # editorial.js (changelog.html flag-lag section): headline "Most
    # ransomware flags land long after the listing." — at build
    # (2026-09-22): 110 flips after the 2023-12 step, 87 of them (79%)
    # more than 90 days after dateAdded, median 437.5 days. "Most" dies
    # below half; "long after" dies when the median drops under 90 days.
    # The listing-year tooltip says "fewer than 10 flips — no median
    # published", which holds only while min_n is 10. Editions before
    # 2026-09-22 lack the block; the section renders a no-block card.
    lag = d.get("flag_lag")
    if lag is None:
        pytest.skip("kev_changelog.json predates the flag_lag block")
    n = lag["n_capture"] + lag["n_daily"]
    assert n >= 25, (
        f"'Most ransomware flags land long after the listing' needs a real "
        f"cohort ({n} flips is an anecdote)"
    )
    late = sum(b["capture"] + b["daily"] for b in lag["buckets"]
               if b["lo"] > 90)
    claims_support.record(100 * late / n, lo=50, unit="%",
                          note=f"{late} of {n} flips after 90 days")
    claims_support.record((lag.get("overall") or {}).get("median_days"),
                          lo=90,
                          unit="days", note="median lag")
    assert late / n > 0.5, (
        f"'Most ransomware flags land long after the listing': only "
        f"{late} of {n} flips landed more than 90 days after listing"
    )
    median = lag["overall"]["median_days"]
    assert median is not None and median >= 90.0, (
        f"'long after the listing' needs the median lag ({median} days) "
        f"to stay above three months"
    )
    assert d["min_n"] == 10, (
        f"'fewer than 10 flips — no median published' quotes min_n, which "
        f"is now {d['min_n']}"
    )


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    ("CISA has changed the ransomware flag to “Known” on more than a hundred "
     "KEV entries after listing them.",
     check_hundred_flips_after_listing),
    ("CISA sets some flags after listing, often more than a year later",
     check_flags_often_a_year_late),
    (
        "not counting the {step_flips} flips logged together in "
        "{step_month}, the month the flag column first appears in the "
        "captures",
        check_step_is_set_apart,
    ),
    (
        "changed due dates, changed ransomware flags, rewritten descriptions "
        "and notes, and removed entries",
        check_every_edit_kind_exists,
    ),
    (
        # home card headline (KEV Changelog): due-date and ransomware-flag
        # changes must both be in the log.
        "CISA changes KEV entries after listing them, including due dates "
        "and ransomware flags.",
        check_every_edit_kind_exists,
    ),
    ("new listings excluded: {additions}", check_additions_excluded),
    (
        "Most ransomware-flag flips come more than three months after listing",
        check_flag_lag_lands_late,
    ),
    ("fewer than 10 flips — no median published", check_flag_lag_lands_late),
    ("Some KEV entries have been edited eight or more times after listing",
     check_entries_never_stop_changing),
    ("every entry observed leaving the catalog", check_removals_are_named),
]


@pytest.mark.parametrize(
    ("claim", "check"),
    CLAIMS,
    ids=[c[1].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, check) -> None:
    check(backfilled_changelog())
