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

DATA_DIR = Path(__file__).resolve().parents[2] / "site" / "data"

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
    return json.loads(path.read_text("utf-8"))


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


def check_flag_arrives_late(d: dict) -> None:
    # editorial.js (changelog.html flag section): headline "The ransomware
    # flag arrives late." and caption "entries that have sat in the
    # catalog for months or years" — trial: median 626 days over 285
    # flips. The range tolerates drift down to two months (below that
    # "months or years" dies) and up to a decade.
    flips = d["flips"]
    assert flips["total"] >= 25, (
        f"'the flag gets flipped on entries…' needs a real flip cohort "
        f"({flips['total']} observed flips is an anecdote)"
    )
    median = flips["lag"]["median_days"]
    assert median is not None, (
        "'entries that have sat in the catalog for months or years' has "
        "no published median to stand on"
    )
    # Additive since 2026-09-08: the post-step lag (flips observed after
    # the month the flag column first appears) must tell the same story.
    post = flips.get("lag_post_step")
    if post is not None and post.get("median_days") is not None:
        assert 60.0 <= post["median_days"] <= 3650.0, (
            f"post-step median gap {post['median_days']}d no longer reads "
            f"as 'months or years'"
        )
    assert 60.0 <= median <= 3650.0, (
        f"'entries that have sat in the catalog for months or years' "
        f"needs the median listing-to-flip gap ({median} days) to stay in "
        f"months-to-years territory"
    )


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
        assert n >= 1, (
            f"the module blurb names every edit kind, but the record "
            f"holds zero '{key}' events — trim the blurb or fix the diff"
        )


def check_additions_excluded(d: dict) -> None:
    # editorial.js (changelog.html hero): "New listings are deliberately
    # not counted — a growing catalog is the system working" — the
    # exclusion must be real and disclosed (trial: 1,335 additions).
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
    ("CISA often adds the ransomware flag months or years after listing",
     check_flag_arrives_late),
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
        "New listings are deliberately not counted",
        check_additions_excluded,
    ),
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
