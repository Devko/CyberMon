"""Claims audit for module 27 (AI Product CVEs).

Pattern: test_claims_tags.py. Each CLAIMS entry quotes site/js/editorial.js
verbatim (test_claims_anchors.py keeps the quote anchored) and asserts the
committed data still sits where the sentence stays true. Numbers inside the
copy are filled from the data by the renderer ({placeholders}); what is
audited here is the verbal part around them — "risen in every complete
year", "mostly", "fewer than one in a hundred", "at least twice", "about as
often", "most". Thresholds leave room for a month of nightly drift.

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim + range, in the same
commit) or the pipeline broke (fix the pipeline). A classifier change
(pipeline/ai_products.py, CLASSIFIER_VERSION) can also move these numbers;
re-check every claim when the table changes.

Skips itself when site/data/ holds sample data or the file is missing.
"""
from __future__ import annotations

import json

import pytest

from . import claims_support

DATA_DIR = claims_support.DATA_DIR

_meta_path = DATA_DIR / "meta.json"
if not _meta_path.exists():
    pytest.skip("site/data/meta.json missing — no committed data to audit",
                allow_module_level=True)
_META = json.loads(_meta_path.read_text("utf-8"))
if _META.get("sample") is True:
    pytest.skip("site/data holds sample data — claims audit only judges "
                "real data", allow_module_level=True)

GENERATION_YEAR = claims_support.GENERATION_YEAR
FILE = "ai_products.json"


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return claims_support.read_json(path)


def _share(n: int, d: int) -> float:
    return 100.0 * n / d if d else 0.0


# ------------------------------------------------------------------ 01

def check_share_rising_since_2023(d: dict) -> None:
    # aisurface_years headline, repeated word for word on the home card:
    # "AI products' share of published CVEs has risen in every complete year
    # since 2023." Every complete year after 2023 has a higher share than
    # the year before it, and there are at least two such steps.
    # (2026-11-05: 0.31% in 2023, 1.11% in 2024, 1.44% in 2025; 2026 so
    # far 3.46% over 91,568 records, so the January edition, which judges
    # 2026 complete, still passes.) The first complete year after 2026 must
    # beat 2026's share for this to keep holding; reword then if it does
    # not ("rose from 2023 to 2026").
    shares = {r["year"]: _share(r["ai"], r["published"]) for r in d["years"]
              if 2023 <= r["year"] < GENERATION_YEAR}
    years = sorted(shares)
    assert len(years) >= 3 and years[0] == 2023, years
    for prev, year in zip(years, years[1:]):
        assert shares[year] > shares[prev], (
            f"'risen in every complete year since 2023': {year} at "
            f"{shares[year]:.2f}% vs {shares[prev]:.2f}% in {prev}")


def check_before_2023_mostly_tensorflow(d: dict) -> None:
    # aisurface_years caption: "Before 2023 the count is mostly
    # TensorFlow." Over the years before 2023, the TensorFlow records (each
    # year's largest product where that is TensorFlow) are more than half of
    # the AI-product CVEs. (2026-11-05: TensorFlow leads 2019-2022 and holds
    # 379 of the 407 AI-product CVEs before 2023.) Past years only: the
    # partial year never enters.
    early = [r for r in d["years"] if r["year"] < 2023]
    total = sum(r["ai"] for r in early)
    tf = sum(r["top_product"]["n"] for r in early
             if r["top_product"] and r["top_product"]["label"] == "TensorFlow")
    assert total and tf > 0.5 * total, (
        f"TensorFlow holds {tf} of {total} AI-product CVEs before 2023")


def check_headline_block(d: dict) -> None:
    # aisurface_years caption: "{latest_ai} were published in {latest_year},
    # {latest_share} of that year's CVEs, and {current_ai} so far in
    # {current_year}" — the headline block is the latest COMPLETE year and
    # the edition's year, read from the same series the chart draws.
    h = d["headline"]
    by = {r["year"]: r for r in d["years"]}
    latest = by[h["latest_year"]]
    assert h["latest_year"] == int(d["generated_at"][:4]) - 1
    assert h["latest_ai"] == latest["ai"]
    assert h["current_ai"] == by[h["current_year"]]["ai"]


# ------------------------------------------------------------------ 02

# A share claim needs this many AI-product CVEs in the window.
CWE_MIN_N = 500


def check_ai_cwes_rare(d: dict) -> None:
    # aisurface_cwe headline: "Fewer than one in a hundred AI-product CVEs
    # cites a weakness type written for AI." (2026-11-05: 3 of 4,392.)
    c = d["cwe"]
    assert c["n"] >= CWE_MIN_N, f"only {c['n']} AI-product CVEs in the window"
    assert c["ai_specific"]["n"] < 0.01 * c["n"], (
        f"{c['ai_specific']['n']} of {c['n']} cite an AI-specific CWE")


SERVER_SIDE = ("CWE-22", "CWE-918", "CWE-502", "CWE-94")


def check_server_side_twice(d: dict) -> None:
    # aisurface_cwe caption: "Path traversal, server-side request forgery
    # (SSRF), deserialization of untrusted data and code injection are each
    # at least twice as common on AI-product CVEs as on the others.
    # Cross-site scripting is less common." All five are drawn (in the top
    # ten), the four are at least 2x their year-matched baseline and XSS is
    # below its own. (2026-11-05: 8.2/2.8, 8.0/1.6, 5.2/1.2, 5.0/1.3;
    # XSS 3.4 vs 11.0.)
    top = {t["cwe"]: t for t in d["cwe"]["top"]}
    assert len(d["cwe"]["top"]) == 10, "the caption says ten weakness types"
    for cwe in SERVER_SIDE:
        assert cwe in top, f"{cwe} is no longer among the ten drawn"
        t = top[cwe]
        assert t["pct"] >= 2 * t["baseline_pct"], (
            f"{cwe}: {t['pct']}% vs baseline {t['baseline_pct']}%")
    assert "CWE-79" in top and top["CWE-79"]["pct"] < \
        top["CWE-79"]["baseline_pct"], "XSS is no longer less common"


def check_one_year_dominates(d: dict) -> None:
    # aisurface_cwe methodology: "because most AI-product CVEs in these
    # years come from a single year" — one year holds more than half the
    # window. (2026-11-05: 2026 holds 72.1%. In January the window moves to
    # 2024-2027 and 2026 still holds about three quarters.)
    # The weights describe the window as published (partial year
    # included), which is what the sentence is about.
    weights = [w["pct"] for w in d["window"]["weights"]]
    assert weights and max(weights) > 50.0, d["window"]["weights"]


def check_window_recent(d: dict) -> None:
    # aisurface_exploited methodology: "most AI-product CVEs here are
    # recent" — the window's last two publication years hold more than half
    # of its AI-product CVEs. (2026-11-05: 2025 + 2026 = 87.9%.)
    w = d["window"]
    recent = sum(x["pct"] for x in w["weights"] if x["year"] >= w["to"] - 1)
    assert recent > 50.0, w["weights"]


# ------------------------------------------------------------------ 03

# The KEV comparison is judged only from this many KEV-listed or expected
# AI-product CVEs: below it a single listing moves the ratio by a fifth.
KEV_MIN = 5


def check_kev_about_baseline(d: dict) -> None:
    # aisurface_exploited headline: "AI-product CVEs are on CISA's KEV
    # catalog about as often as other CVEs from the same years." The count
    # on KEV is within a factor of 1.5 of the count expected at the
    # year-matched baseline rate. (2026-11-05: 11 on KEV vs 12.2 expected,
    # ratio 0.90; six of the eleven are Langflow.)
    e = d["exploited"]
    assert max(e["kev"], e["kev_expected"]) >= KEV_MIN, e
    ratio = e["kev"] / e["kev_expected"] if e["kev_expected"] else 99.0
    assert 2 / 3 <= ratio <= 3 / 2, (
        f"{e['kev']} on KEV vs {e['kev_expected']} expected (ratio "
        f"{ratio:.2f}) — 'about as often' no longer holds")


def check_nuclei_twice(d: dict) -> None:
    # aisurface_exploited caption: "Nuclei templates ... cover {nuclei},
    # more than twice the {nuclei_exp} expected."
    e = d["exploited"]
    assert e["nuclei"] > 2 * e["nuclei_expected"], (
        f"{e['nuclei']} templated vs {e['nuclei_expected']} expected")


# ------------------------------------------------------------------ 04

TOP3 = {"GitHub_M", "VulnCheck", "@huntr_ai"}


def check_three_cnas_most(d: dict) -> None:
    # aisurface_products headline: "Three CNAs assigned most of the
    # AI-product CVEs published in recent years." (2026-11-05: 69.0%.)
    assert d["cnas"]["top3_pct"] > 50.0, d["cnas"]


def check_three_cnas_named(d: dict) -> None:
    # aisurface_products caption: "GitHub assigns CVEs for advisories on
    # projects it hosts, VulnCheck for reports sent to it, and huntr runs a
    # bug-bounty programme for AI and machine-learning projects." — the
    # prose describes exactly the three CNAs the {cna_list} placeholder
    # fills in. (2026-11-05: GitHub_M 28.0%, VulnCheck 25.0%, @huntr_ai
    # 16.0%; next VulDB 10.0%.)
    names = {r["cna"] for r in d["cnas"]["top"][:3]}
    assert names == TOP3, f"top three CNAs are now {sorted(names)}"


def check_lead_product(d: dict) -> None:
    # aisurface_products caption: "{lead} alone accounts for {lead_n} of
    # them" — the headline's lead is the board's first row.
    h, top = d["headline"], d["products"][0]
    assert (h["lead_label"], h["lead_n"]) == (top["label"], top["n"])


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    ("AI products' share of published CVEs has risen in every complete year "
     "since 2023.", FILE, check_share_rising_since_2023),
    ("Before 2023 the count is mostly TensorFlow.", FILE,
     check_before_2023_mostly_tensorflow),
    ("{latest_ai} were published in {latest_year}, {latest_share} of that "
     "year's CVEs, and {current_ai} so far in {current_year}", FILE,
     check_headline_block),
    ("Fewer than one in a hundred AI-product CVEs cites a weakness type "
     "written for AI.", FILE, check_ai_cwes_rare),
    ("Path traversal, server-side request forgery (SSRF), deserialization of "
     "untrusted data and code injection are each at least twice as common on "
     "AI-product CVEs as on the others. Cross-site scripting is less common.",
     FILE, check_server_side_twice),
    ("because most AI-product CVEs in these years come from a single year",
     FILE, check_one_year_dominates),
    ("most AI-product CVEs here are recent", FILE, check_window_recent),
    ("AI-product CVEs are on CISA's KEV catalog about as often as other CVEs "
     "from the same years.", FILE, check_kev_about_baseline),
    ("more than twice the {nuclei_exp} expected.", FILE, check_nuclei_twice),
    ("Three CNAs assigned most of the AI-product CVEs published in recent "
     "years.", FILE, check_three_cnas_most),
    ("GitHub assigns CVEs for advisories on projects it hosts, VulnCheck for "
     "reports sent to it, and huntr runs a bug-bounty programme for AI and "
     "machine-learning projects.", FILE, check_three_cnas_named),
    ("{lead} alone accounts for {lead_n} of them", FILE, check_lead_product),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[f"{c[2].__name__}-{i}" for i, c in enumerate(CLAIMS)],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
