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
    assert 60.0 <= median <= 3650.0, (
        f"'entries that have sat in the catalog for months or years' "
        f"needs the median listing-to-flip gap ({median} days) to stay in "
        f"months-to-years territory"
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
    # editorial.js (changelog.html receipts): "Some entries never stop
    # changing." — the board's top entry needs a real edit history
    # (trial: 12 edits; the range dies below a handful).
    board = d["board"]["most_edited"]
    assert board, "'Some entries never stop changing' with an empty board"
    assert board[0]["edits"] >= 4, (
        f"'Some entries never stop changing' needs the most-edited entry "
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


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    ("The ransomware flag arrives late", check_flag_arrives_late),
    (
        "due dates that moved, ransomware flags that flipped, descriptions "
        "that were rewritten, entries that quietly vanished",
        check_every_edit_kind_exists,
    ),
    (
        "New listings are deliberately not counted",
        check_additions_excluded,
    ),
    ("Some entries never stop changing", check_entries_never_stop_changing),
    ("every entry observed leaving the catalog", check_removals_are_named),
]


@pytest.mark.parametrize(
    ("claim", "check"),
    CLAIMS,
    ids=[c[1].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, check) -> None:
    check(backfilled_changelog())
