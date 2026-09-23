"""Claims audit for the Incident Clock module (pattern: test_claims_c2.py).

Every count on incidents.html is filled from site/data/sec_incidents.json
by the renderer, so the numeric claims audited here are the few the copy
states in words: the window's start date, the receipts board's size, and
the structural promises (filing dates only; every receipt links to its
EDGAR filing; the methodology prints the queries the edition ran). Each
CLAIMS entry quotes the copy verbatim (grep for it in editorial.js).

The empty edition (status "empty", before the first nightly EDGAR read)
is a legal state: its checks assert it claims nothing — no series, no
totals, no receipts — rather than skipping.

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim, in the same commit) or
the pipeline broke (fix the pipeline). NEVER silence a failing claim check
without doing one of the two.

Skips itself when site/data/ holds sample data or the files are missing.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parents[2] / "site" / "data"

_meta_path = DATA_DIR / "meta.json"
if not _meta_path.exists():
    pytest.skip("site/data/meta.json missing — no committed data to audit",
                allow_module_level=True)
if json.loads(_meta_path.read_text("utf-8")).get("sample") is True:
    pytest.skip("site/data holds sample data — claims audit only judges "
                "real data", allow_module_level=True)


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return json.loads(path.read_text("utf-8"))


_EDGAR_URL = re.compile(
    r"^https://www\.sec\.gov/Archives/edgar/data/[1-9]\d*/\d{18}/"
    r"\d{10}-\d{2}-\d{6}-index\.htm$")


def check_rule_start(d: dict) -> None:
    # editorial.js (incidents_clock caption + note): "Since 18 December
    # 2023" / "the rule took effect on 18 December 2023" — the window the
    # counts cover must start exactly there.
    assert d["window"]["start"] == "2023-12-18"
    if d["status"] == "ok":
        assert d["monthly"][0]["month"] == "2023-12"
        assert d["monthly"][0]["partial"] is True


def check_receipts_size(d: dict) -> None:
    # editorial.js (incidents_receipts methodology): "Up to the 25 newest
    # Item 1.05 filings in the window, newest first"
    rows = d["recent"]
    assert len(rows) <= 25
    keys = [(r["date"], r["adsh"]) for r in rows]
    assert keys == sorted(keys, reverse=True)
    if d["status"] == "ok":
        n = d["totals"]["originals"] + d["totals"]["amendments"]
        assert len(rows) == min(25, n)


def check_receipts_link_to_edgar(d: dict) -> None:
    # editorial.js (incidents_receipts caption): "each linked to its filing
    # index on EDGAR"
    for r in d["recent"]:
        assert _EDGAR_URL.match(r["url"]), r["url"]
        assert r["adsh"] in r["url"] and f"/data/{r['cik']}/" in r["url"]


def check_empty_claims_nothing(d: dict) -> None:
    # editorial.js (incidents_clock nodata): "nothing has been counted, so
    # nothing is drawn as zero" — an empty edition carries no counts.
    if d["status"] != "empty":
        return
    assert d["monthly"] == [] and d["quarterly"] == [] and d["recent"] == []
    assert d["totals"] is None and d["amendment_lag"] is None


def check_queries_printed(d: dict) -> None:
    # editorial.js (incidents_clock methodology): "Item 1.05: the phrase
    # {q105} in form {forms105} filings" — the page prints the edition's own
    # query, so the edition must carry the measurement definitions.
    from pipeline.fetch_sec_incidents import QUERIES
    assert d["definitions"] == QUERIES


def check_originals_counted(d: dict) -> None:
    # editorial.js (incidents_clock statLabel): "Item 1.05 incident
    # disclosures on EDGAR (original 8-Ks)" and methodology "so it returns
    # the 8-K/A amendments too" — one query must yield both forms. The
    # first editions sent forms=8-K,8-K/A, which EDGAR answers with the
    # amendments only, and printed 0 originals beside 26 amendments. A
    # rule in force since December 2023 cannot have more amendments than
    # original disclosures across the window.
    if d["status"] != "ok":
        return
    t = d["totals"]
    assert t["originals"] > 0
    assert t["originals"] >= t["amendments"]
    assert 0 < t["companies_105"] <= t["originals"]


def check_one_or_two_a_month(d: dict) -> None:
    # incidents_clock headline: "Companies file one or two Item 1.05
    # incident disclosures in a typical month." — the median complete
    # month. (2026-09-23: 1.5 over 32 complete months.)
    if d["status"] != "ok":
        return
    import statistics
    months = [r["originals"] for r in d["monthly"] if not r["partial"]]
    med = statistics.median(months)
    assert 1 <= med <= 2, f"median originals per complete month {med}"


def check_third_amended_most_within_90(d: dict) -> None:
    # incidents_amend headline: "About a third of Item 1.05 disclosures have
    # been amended, most within 90 days." (2026-09-23: 19 of 57; 17 of the
    # 19 first amendments within 90 days.)
    if d["status"] != "ok":
        return
    lag = d["amendment_lag"]
    pct = 100.0 * lag["amended"] / lag["originals"]
    assert 25 <= pct <= 42, f"{lag['amended']} of {lag['originals']} amended"
    within = sum(b["n"] for b in lag["buckets"][:3])  # 0-7, 8-30, 31-90
    assert within > lag["amended"] / 2, (within, lag["amended"])


CLAIMS = [
    ("Companies file one or two Item 1.05 incident disclosures in a typical month.",
     "sec_incidents.json", check_one_or_two_a_month),
    ("About a third of Item 1.05 disclosures have been amended, most within 90 days.",
     "sec_incidents.json", check_third_amended_most_within_90),
    ("Item 1.05 incident disclosures on EDGAR (original 8-Ks)",
     "sec_incidents.json", check_originals_counted),
    ("the rule took effect on 18 December 2023", "sec_incidents.json",
     check_rule_start),
    ("Up to the 25 newest Item 1.05 filings in the window, newest first",
     "sec_incidents.json", check_receipts_size),
    ("each linked to its filing index on EDGAR", "sec_incidents.json",
     check_receipts_link_to_edgar),
    ("nothing has been counted, so nothing is drawn as zero",
     "sec_incidents.json", check_empty_claims_nothing),
    ("Item 1.05: the phrase {q105} in form {forms105} filings",
     "sec_incidents.json", check_queries_printed),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
