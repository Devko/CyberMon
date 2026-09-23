"""Claims audit for module 23 (Record Tags), the CVSS 4.0 adoption section
of module 01, and the Linux-kernel toggle notes (modules 01 and 04).

Pattern: test_claims_c2.py. Each CLAIMS entry quotes site/js/editorial.js
verbatim (test_claims_anchors.py keeps the quote anchored) and asserts the
committed data still sits where the sentence stays true. Numbers inside
the copy are filled from the data by the renderer ({placeholders}); what is
audited here is the verbal part around them — "keeps climbing", "flat",
"most", "almost entirely", "nearly every". Ranges are tolerant: nightly
drift must not trip them, only a claim becoming untrue should.

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim + range, in the same
commit) or the pipeline broke (fix the pipeline). NEVER silence a failing
claim check without doing one of the two.

Skips itself when site/data/ holds sample data or the files are missing —
this audit only ever judges the committed real data.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parents[2] / "site" / "data"

_meta_path = DATA_DIR / "meta.json"
if not _meta_path.exists():
    pytest.skip("site/data/meta.json missing — no committed data to audit",
                allow_module_level=True)
_META = json.loads(_meta_path.read_text("utf-8"))
if _META.get("sample") is True:
    pytest.skip("site/data holds sample data — claims audit only judges "
                "real data", allow_module_level=True)

# Raw-series guards judge complete years only (see test_claims_audit.py for
# the January rehearsal knob).
GENERATION_YEAR = int(os.environ.get("CYBERMON_REHEARSE_YEAR")
                      or _META["generated_at"][:4])
UWA = "unsupported-when-assigned"


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return json.loads(path.read_text("utf-8"))


def _share(n: int, d: int) -> float:
    return 100.0 * n / d if d else 0.0


# ------------------------------------------------------------ Record Tags

def check_unsupported_climbing(d: dict) -> None:
    # tags_trend headline + home card: "More CVEs are tagged as issued for
    # products the vendor no longer supports." — the latest complete year beats the
    # one before it, and sits far above the tag's first year.
    full = [r for r in d["years"] if r["year"] < GENERATION_YEAR]
    assert len(full) >= 2, "no complete years to judge"
    last, prev = full[-1]["counts"][UWA], full[-2]["counts"][UWA]
    h = d["headline"]
    assert last > prev, (
        f"'more CVEs are issued for unsupported products' needs growth: "
        f"{full[-1]['year']} has {last} vs {prev} the year before")
    assert h["unsupported_latest"] >= 5 * max(h["unsupported_first"], 1), (
        "the tag's growth since its first year is no longer large")


def check_disputed_flat(d: dict) -> None:
    # tags_trend caption: "it does not grow with the corpus — between {dmin}
    # and {dmax} records a year from {dfrom} to {dto}, while yearly
    # publications more than doubled, so its share of the year fell."
    h = d["headline"]
    by = {r["year"]: r for r in d["years"]}
    first, last = by[h["disputed_from"]], by[h["disputed_to"]]
    assert h["disputed_max"] <= 2 * h["disputed_min"], (
        f"disputed ranges {h['disputed_min']}–{h['disputed_max']}: no "
        f"longer flat")
    assert last["published"] >= 2 * first["published"], (
        "yearly publications no longer 'more than doubled' over the window")
    assert _share(last["counts"]["disputed"], last["published"]) < \
        _share(first["counts"]["disputed"], first["published"]), (
        "disputed share of the year no longer fell across the window")


def check_home_blurb(d: dict) -> None:
    # home card: "the first tag keeps climbing, the second lags the
    # corpus." (disputed counts rose 85 -> 137 over 2021-25 while yearly
    # publications more than doubled — the share fell.)
    check_unsupported_climbing(d)
    check_disputed_flat(d)


def check_most_cnas_never_tag(d: dict) -> None:
    # tags_trend caption: "most CNAs never set these tags." and the board
    # headline "A few CNAs set the tags. Most never do."
    for tag in (UWA, "disputed"):
        b = d["boards"][tag]
        assert b["active_cnas"] and b["cna_count"] <= 0.25 * b["active_cnas"], (
            f"{tag}: {b['cna_count']} of {b['active_cnas']} active CNAs set "
            f"it — 'most never do' needs rewording")


def check_disputed_one_cna(d: dict) -> None:
    # tags_board caption: "“disputed” is set mostly by one CNA"
    top1 = d["boards"]["disputed"]["top1_share_pct"]
    assert top1 >= 75.0, f"top CNA sets only {top1}% of disputed tags"


def check_unsupported_rated_critical_more(d: dict) -> None:
    # tags_severity headline: tagged records are rated Critical more often
    # than the same CNAs' other records (and than all records).
    sev = d["severity"]

    def crit(c):
        return _share(c["critical"], sum(c.values()))

    tagged = crit(sev[UWA]["tagged"])
    same = crit(sev[UWA]["same_cnas_untagged"])
    everyone = crit(sev["all"])
    assert tagged >= same + 2.0 and tagged > everyone, (
        f"tagged critical {tagged:.1f}% vs same-CNA {same:.1f}% / all "
        f"{everyone:.1f}% — the headline no longer holds")


def check_adp_tags_complete(d: dict) -> None:
    # tags_trend context note: "ADP containers carry only {adp}." — the
    # listed ADP tags must be the complete list (the builder keeps 6).
    assert 0 < len(d["context"]["adp_tags"]) < 6, (
        "ADP tag list is empty or truncated — 'carry only' would mislead")


# ---------------------------------------------------------- CVSS 4.0 (01)

def check_v4_minority(d: dict) -> None:
    # cvss4 fallback headline: "Most new CVE records do not carry a CVSS 4.0
    # score from their CNA." and caption "Since CVSS 4.0 was published in
    # late 2023"
    assert d["since_month"] == "2023-11"
    assert d["headline"]["v4_share_current_pct"] < 50.0, (
        "v4.0 is now on most new records — rewrite the fallback headline")


def check_v4_few_assigners_dual(d: dict) -> None:
    # cvss4 caption: "Three assigners supply most of that volume, and most
    # v4.0 scores arrive next to a v3.x score rather than instead of one."
    ad = d["adopters"]
    top3 = sum(r["v4"] for r in ad["cnas"][:3])
    assert top3 > 0.5 * ad["window_v4"], (
        f"top three adopters hold {top3} of {ad['window_v4']} v4 scores")
    recent = [r for r in d["years"] if r["year"] >= 2024]
    both = sum(r["both"] for r in recent)
    only = sum(r["v4_only"] for r in recent)
    assert both > only, (
        f"v4.0-only ({only}) now outnumbers dual-scored ({both}) records")


# ------------------------------------------------- Linux-kernel toggle notes

def check_kernel_starts_2024(d: dict) -> None:
    # volume linuxNote: "The kernel's records start in 2024"
    wl = d["without_linux"]["years"]
    diff = [f["year"] for f, w in zip(d["years"], wl)
            if (f["published"], f["rejected"]) != (w["published"], w["rejected"])]
    assert diff and diff[0] == 2024, f"kernel records first differ in {diff[:1]}"


def check_rejection_rebound_is_kernel(d: dict) -> None:
    # volume linuxNote: "most of the 2024–25 rejection rebound is its own"
    # — of each year's rise in rejections over 2023, the kernel's records
    # are the larger part. (2026-09-23: 155 of +211 and 128 of +171.)
    full = {r["year"]: r["rejected"] for r in d["years"]}
    wl = {r["year"]: r["rejected"] for r in d["without_linux"]["years"]}
    for y in (2024, 2025):
        rise = full[y] - full[2023]
        kernel = full[y] - wl[y]
        assert rise > 0 and kernel > rise / 2, (
            f"{y}: rejections +{rise} over 2023, kernel {kernel}")


def check_unscored_is_kernel(d: dict) -> None:
    # flood linuxNote: "Since 2024 nearly every record with no score
    # anywhere in it is a kernel record"
    full = {r["year"]: r for r in d["years"]}
    wl = {r["year"]: r for r in d["without_linux"]["years"]}
    years = [y for y in full if 2024 <= y < GENERATION_YEAR]
    assert years, "no complete year since 2024"
    all_unscored = sum(full[y]["unscored"] for y in years)
    left = sum(wl[y]["unscored"] for y in years)
    assert all_unscored and left <= 0.05 * all_unscored, (
        f"{left} of {all_unscored} unscored records since 2024 are not "
        f"the kernel's — 'nearly every' no longer holds")


def check_concentration_survives(d: dict) -> None:
    # concentration linuxNote: "Without the kernel the top-5 share still
    # climbs after 2023"
    wl = {r["year"]: r for r in d["without_linux"]["years"]}
    latest = max(y for y in wl if y < GENERATION_YEAR)
    assert wl[latest]["top5_share"] > wl[2023]["top5_share"], (
        f"without the kernel, top-5 share {wl[latest]['top5_share']} in "
        f"{latest} is not above 2023's {wl[2023]['top5_share']}")


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    ("More CVEs are tagged as issued for products the vendor no longer supports.",
     "cve_tags.json", check_unsupported_climbing),
    ("the first tag keeps climbing and the second has not kept pace with the corpus",
     "cve_tags.json", check_home_blurb),
    ("It appeared on between {dmin} and {dmax} records a year from {dfrom} to {dto}, while yearly publications more than doubled, so its share of each year's records fell.",
     "cve_tags.json", check_disputed_flat),
    ("most CNAs never set these tags.", "cve_tags.json",
     check_most_cnas_never_tag),
    ("Most active CNAs set neither tag in the last five years", "cve_tags.json",
     check_most_cnas_never_tag),
    ("“disputed” is set mostly by one CNA", "cve_tags.json",
     check_disputed_one_cna),
    ("Records tagged unsupported are rated Critical more often than their "
     "CNAs' other records.", "cve_tags.json",
     check_unsupported_rated_critical_more),
    ("ADP containers carry only {adp}.", "cve_tags.json",
     check_adp_tags_complete),
    ("Most new CVE records do not carry a CVSS 4.0 score from their CNA.",
     "cvss_v4.json", check_v4_minority),
    ("three CNAs account for most v4.0 scores, and most records with a v4.0 score also carry a v3.x score.",
     "cvss_v4.json", check_v4_few_assigners_dual),
    ("The kernel's records start in 2024", "volume_curve.json",
     check_kernel_starts_2024),
    ("most of the rise in rejections in 2024 and 2025 comes from them", "volume_curve.json",
     check_rejection_rebound_is_kernel),
    ("Since 2024 nearly every record with no score anywhere in it is a "
     "kernel record", "nine_eight_flood.json", check_unscored_is_kernel),
    ("Without the kernel the top-5 share still climbs after 2023",
     "cna_concentration.json", check_concentration_survives),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[f"{c[2].__name__}-{i}" for i, c in enumerate(CLAIMS)],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
