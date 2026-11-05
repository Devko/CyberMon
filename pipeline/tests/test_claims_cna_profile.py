"""Claims audit for the CNA profile section (concentration.html, section
04; pattern: test_claims_c2.py).

The section's copy (site/js/editorial.js, ``sections.cna_profile``) makes
one finding across CNAs in its headline and a handful of structural
promises in its caption, window line and methodology, all about
site/data/cna_profiles.json. Each CLAIMS entry quotes the copy verbatim
(grep for it in editorial.js) and asserts the data still sits where the
sentence stays true.

The window is the last five COMPLETE years, so the numbers move only as
old records are edited or rejected, and once a year when the window
shifts. The headline thresholds leave room for both: on the 2026-11-05
edition (window 2021-2025) 12 of 107 listed CNAs named a CWE on fewer
than 5% of their records and 17 on every one; recomputed over 2022-2026
as it stood that day, 9 and 31.

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim + range, in the same
commit) or the pipeline broke (fix the pipeline). NEVER silence a failing
claim check without doing one of the two.

Skips itself when site/data/ holds sample data or the file is missing —
this audit only ever judges the committed real data.
"""
from __future__ import annotations

import json
import statistics

import pytest

from . import claims_support

DATA_DIR = claims_support.DATA_DIR

_meta_path = DATA_DIR / "meta.json"
if not _meta_path.exists():
    pytest.skip("site/data/meta.json missing — no committed data to audit",
                allow_module_level=True)
if json.loads(_meta_path.read_text("utf-8")).get("sample") is True:
    pytest.skip("site/data holds sample data — claims audit only judges "
                "real data", allow_module_level=True)

FILE = "cna_profiles.json"


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return claims_support.read_json(path)


def check_cwe_spread(d: dict) -> None:
    # editorial.js (cna_profile headline): "Among CNAs with at least 100
    # records in five years, some name a weakness type (CWE) on fewer than
    # one record in twenty and others on every record." The numbers in the
    # sentence are the file's floor and window; "some" and "others" each
    # need at least two CNAs. "Every record" is read from the counts, not
    # the rounded share (99.96% rounds to 100.0).
    assert d["min_published"] == 100, (
        f"'at least 100 records' vs min_published {d['min_published']}")
    assert d["window"]["years"] == 5, (
        f"'in five years' vs a {d['window']['years']}-year window")
    rows = d["cnas"]
    low = [r["cna"] for r in rows
           if r["counts"]["cwe"] < 0.05 * r["published"]]
    full = [r["cna"] for r in rows
            if r["counts"]["cwe"] == r["published"]]
    assert len(low) >= 2, (
        f"'some name a CWE on fewer than one record in twenty' — only "
        f"{low} of {len(rows)} CNAs")
    assert len(full) >= 2, (
        f"'others on every record' — only {full} of {len(rows)} CNAs")


def check_listed_cnas_meet_the_floor(d: dict) -> None:
    # editorial.js (cna_profile caption): "against every CNA that published
    # at least {min_published} records in those years" — every listed CNA
    # meets the floor, the floor is the one the copy is filled with, and
    # the window is complete years only.
    floor = d["min_published"]
    short = [r["cna"] for r in d["cnas"] if r["published"] < floor]
    assert not short, f"listed below the {floor}-record floor: {short}"
    assert d["cnas"], "no CNA meets the floor — the picker would be empty"
    edition_year = int(d["generated_at"][:4])
    assert d["window"]["to"] == edition_year - 1, (
        f"window ends {d['window']['to']}, not the last complete year "
        f"before the {edition_year} edition")


def check_window_line(d: dict) -> None:
    # editorial.js (cna_profile window line): "{n} of the {all} CNAs that
    # published in those years had at least {min_published} records" — n
    # (the listed CNAs) cannot exceed all (every CNA with a published
    # record in the window), and the pooled count covers the listed ones.
    pooled = d["all"]
    assert len(d["cnas"]) <= pooled["cna_count"], (
        len(d["cnas"]), pooled["cna_count"])
    assert sum(r["published"] for r in d["cnas"]) <= pooled["published"]


def check_score_panel_against_all(d: dict) -> None:
    # editorial.js (cna_profile caption): "The top panel compares the CNA's
    # CVSS (Common Vulnerability Scoring System) base scores with all CNAs'
    # records." — the pooled histogram holds every CNA's scored records,
    # so it is at least the listed CNAs' scored records put together.
    pooled = d["all"]
    assert sum(pooled["score_bins"]) == pooled["scored"] > 0
    listed = [sum(b) for b in zip(*(r["score_bins"] for r in d["cnas"]))]
    assert all(a >= b for a, b in zip(pooled["score_bins"], listed)), (
        "a band of the pooled histogram holds fewer records than the "
        "listed CNAs alone")


def check_median_line_and_rank_one(d: dict) -> None:
    # editorial.js (cna_profile caption): "every listed CNA is a tick and
    # the dashed line is the median CNA; rank 1 is the highest value" —
    # summary.median is the median of the listed CNAs' values, and rank 1
    # goes to the highest value, for every metric.
    for m in d["metrics"]:
        vals = [r["values"][m] for r in d["cnas"]
                if r["values"][m] is not None]
        if not vals:
            continue
        assert d["summary"][m]["median"] == round(
            float(statistics.median(vals)), 1), m
        top = max(vals)
        tops = {r["ranks"][m] for r in d["cnas"] if r["values"][m] == top}
        assert tops == {1}, f"{m}: the highest value ranks {tops}"


def check_ties_share_the_best_rank(d: dict) -> None:
    # editorial.js (cna_profile methodology): "Tied CNAs share the best
    # rank." — competition ranks (1, 2, 2, 4) on the shipped values.
    for m in d["metrics"]:
        vals = [r["values"][m] for r in d["cnas"]
                if r["values"][m] is not None]
        for r in d["cnas"]:
            v = r["values"][m]
            if v is None:
                continue
            assert r["ranks"][m] == 1 + sum(1 for x in vals if x > v), (
                m, r["cna"])


def check_median_needs_min_scored(d: dict) -> None:
    # editorial.js (cna_profile methodology): "A median score is ranked
    # only for CNAs with at least {min_scored} scored records."
    k = d["min_scored"]
    for r in d["cnas"]:
        ranked = r["ranks"]["score_median"] is not None
        assert ranked == (r["counts"]["scored"] >= k), (
            r["cna"], r["counts"]["scored"], k)


def check_rescore_log_began(d: dict) -> None:
    # editorial.js (cna_profile methodology): "Score changes count
    # same-version changes to a CNA-assigned score on the nightly rescore
    # log, which began on {log_from}." — the log has a start date, and the
    # per-CNA counts never exceed the log's rescore total.
    log = d["rescore_log"]
    assert log["first_observed"], "the rescore log has no start date"
    assert sum(r["values"]["rescores"] for r in d["cnas"]) <= log["rescores"]


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "Among CNAs with at least 100 records in five years, some name a "
        "weakness type (CWE) on fewer than one record in twenty and others "
        "on every record.",
        FILE,
        check_cwe_spread,
    ),
    (
        "against every CNA that published at least {min_published} records "
        "in those years",
        FILE,
        check_listed_cnas_meet_the_floor,
    ),
    (
        "{n} of the {all} CNAs that published in those years had at least "
        "{min_published} records",
        FILE,
        check_window_line,
    ),
    (
        "The top panel compares the CNA's CVSS (Common Vulnerability "
        "Scoring System) base scores with all CNAs' records.",
        FILE,
        check_score_panel_against_all,
    ),
    (
        "every listed CNA is a tick and the dashed line is the median CNA; "
        "rank 1 is the highest value",
        FILE,
        check_median_line_and_rank_one,
    ),
    (
        "Tied CNAs share the best rank.",
        FILE,
        check_ties_share_the_best_rank,
    ),
    (
        "A median score is ranked only for CNAs with at least {min_scored} "
        "scored records.",
        FILE,
        check_median_needs_min_scored,
    ),
    (
        "Score changes count same-version changes to a CNA-assigned score "
        "on the nightly rescore log, which began on {log_from}.",
        FILE,
        check_rescore_log_began,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))


def test_file_stays_small() -> None:
    # Brief: data files in site/data stay under about 200 KB. The file
    # grows with the number of CNAs over the floor (107 on 2026-11-05,
    # 74 KB); this fails before it gets heavy.
    path = DATA_DIR / FILE
    if not path.exists():
        pytest.skip(f"{FILE} missing — nothing to audit")
    assert path.stat().st_size < 200_000, path.stat().st_size
