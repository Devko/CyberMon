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


def check_most_recent_below_1pct(d: dict) -> None:
    # editorial.js (epss.html hero): "in its recent years most arrive
    # having been scored below one percent the day before" — live samples
    # put the last complete year at ~61% (2025) and the newest additions
    # at ~65%; the range tolerates drift down to a bare majority and up
    # to near-unanimity before the sentence dies.
    h = d["headline"]
    assert h is not None, "headline is null — nothing graded at all"
    pct = h["pct_below_1pct_latest"]
    assert 45.0 <= pct <= 90.0, (
        f"'most arrive having been scored below one percent the day "
        f"before' needs the latest complete year's share below 1% "
        f"({pct}% for {h['latest_year']}, n={h['graded_latest']}) to stay "
        f"a rough majority"
    )


def check_bottom_half_share(d: dict) -> None:
    # editorial.js (epss.html percentile section): "roughly a third of the
    # graded cohort sat in the bottom half of that day's ranking" — live
    # estimate: seeding era ~25%, live era ~45-58%, cohort-wide ~35%.
    pct = d["percentiles"]["bottom_half"]["pct"]
    assert 20.0 <= pct <= 55.0, (
        f"'roughly a third of the graded cohort sat in the bottom half' "
        f"needs the cohort-wide bottom-half share ({pct}%) to stay in "
        f"that neighbourhood"
    )


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "most arrive having been scored below one percent the day before",
        check_most_recent_below_1pct,
    ),
    (
        "roughly a third of the graded cohort sat in the bottom half",
        check_bottom_half_share,
    ),
]


@pytest.mark.parametrize(
    ("claim", "check"),
    CLAIMS,
    ids=[c[1].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, check) -> None:
    check(graded_report())
