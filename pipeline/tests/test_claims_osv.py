"""Claims audit for the two OSV-fed modules: Advisory Gap (advisories.html)
and Registry Malware (malware.html). Pattern: test_claims_c2.py.

Every verbal claim in their editorial.js copy that is not filled from the
data at render time is quoted here verbatim, next to an assertion that the
committed data still sits where the sentence stays true. Ranges are
tolerant — nightly drift must not trip them; only a claim becoming untrue
should.

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim + range, in the same
commit) or the pipeline broke (fix the pipeline). NEVER silence a failing
claim check without doing one of the two.

Skips itself when site/data/ holds sample data or the files are missing.
"""
from __future__ import annotations

import json
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
    obj = json.loads(path.read_text("utf-8"))
    count = obj.get("catalog", {}).get(
        "advisories" if name == "advisory_gap.json" else "reports")
    if not count:
        pytest.skip(f"{name} is an empty edition — the page shows its "
                    f"'no edition yet' card and makes no claim")
    return obj


def _eco(d: dict, name: str) -> dict:
    for e in d["ecosystems"]:
        if e["ecosystem"] == name:
            return e
    raise AssertionError(f"{name} missing from ecosystems[]")


def _sev(d: dict, level: str) -> dict:
    return next(s for s in d["severity"] if s["level"] == level)


# ---- advisory_gap.json ------------------------------------------------------------

def check_most_get_a_cve(d: dict) -> None:
    pct = d["catalog"]["without_cve_pct"]
    assert pct < 50, (f"'Most reviewed advisories get a CVE' needs a no-CVE "
                      f"share below half; it is {pct}%")


def check_rust_quarter(d: dict) -> None:
    # "a quarter" / "one advisory in four": 21-30% reads as a quarter.
    pct = _eco(d, "crates.io")["without_cve_pct"]
    assert pct is not None and 21 <= pct <= 30, (
        f"'a quarter of Rust's do not' needs crates.io's no-CVE share near "
        f"25%; it is {pct}%")


def check_rust_is_highest(d: dict) -> None:
    # The ecosystem chart accents the top share and the headline names Rust.
    ranked = [e for e in d["ecosystems"] if e["without_cve_pct"] is not None]
    top = max(ranked, key=lambda e: e["without_cve_pct"])
    assert top["ecosystem"] == "crates.io", (
        f"the headline leads with Rust, but {top['ecosystem']} now has the "
        f"highest no-CVE share ({top['without_cve_pct']}%)")


def check_maven_almost_all(d: dict) -> None:
    pct = _eco(d, "Maven")["without_cve_pct"]
    assert pct is not None and pct <= 3, (
        f"'In Maven, almost all have one' needs Maven's no-CVE share at 3% "
        f"or less; it is {pct}%")


def check_not_the_minor_ones(d: dict) -> None:
    crit = _sev(d, "CRITICAL")
    assert crit["without_cve_pct"] > crit["with_cve_pct"], (
        f"'not the minor ones': the no-CVE set is no longer more often "
        f"Critical ({crit['without_cve_pct']}% vs {crit['with_cve_pct']}%)")


def check_more_low_as_well(d: dict) -> None:
    low = _sev(d, "LOW")
    assert low["without_cve_pct"] > low["with_cve_pct"], (
        f"'More of them are rated Low as well' is no longer true "
        f"({low['without_cve_pct']}% vs {low['with_cve_pct']}%)")


def check_reviewed_only(d: dict) -> None:
    n = d["catalog"]["not_reviewed"]
    assert n == 0, (f"'OSV mirrors only GitHub-reviewed advisories': {n} live "
                    f"GHSA records in the exports lack the reviewed flag")


def check_twelve_ecosystems(d: dict) -> None:
    assert len(d["ecosystems_read"]) == 12, (
        f"the methodology names twelve ecosystems; the edition read "
        f"{len(d['ecosystems_read'])}")


# ---- registry_malware.json ----------------------------------------------------------

def check_six_in_ten_one_month(d: dict) -> None:
    pct = d["catalog"]["peak_share_pct"]
    assert 54 <= pct <= 66, (f"'Six in ten of the feed's reports landed in "
                             f"one month' needs a peak-month share near 60%; "
                             f"it is {pct}%")


def check_peak_names_a_contributor(d: dict) -> None:
    top = d["bursts"][0]
    assert top["top_source"] != "unattributed", (
        "the caption says the peak month's reports 'name one contributor', "
        "but most of them credit none")
    assert top["top_source_reports"] >= 0.9 * top["reports"], (
        f"'{top['top_source_reports']} of them name one contributor' reads "
        f"as nearly all of the month; it is no longer")


def check_typical_month_window(d: dict) -> None:
    first, last = d["catalog"]["median_window"]
    span = (int(last[:4]) - int(first[:4])) * 12 + int(last[5:]) - int(first[5:]) + 1
    assert span == 24, (f"'a typical month of the last two years' is a "
                        f"median over {span} months")


def check_npm_almost_every(d: dict) -> None:
    npm = _eco(d, "npm")["reports"]
    pct = 100 * npm / d["catalog"]["reports"]
    assert pct >= 85, (f"'npm carries almost every report' needs npm at 85% "
                       f"or more of all reports; it is {pct:.1f}%")


def check_pypi_2023(d: dict) -> None:
    y = next(r for r in d["years"] if r["year"] == 2023)
    pypi = y["by_ecosystem"].get("PyPI", 0)
    assert pypi > y["total"] / 2, (
        f"'in 2023 PyPI carried most of the year's reports' — PyPI holds "
        f"{pypi} of {y['total']}")


def check_almost_none_withdrawn(d: dict) -> None:
    pct = d["catalog"]["withdrawn_pct"]
    assert pct is not None and pct < 1, (
        f"'Almost no report is taken back' needs under 1% withdrawn; it is "
        f"{pct}%")


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    ("Most reviewed advisories get a CVE.", "advisory_gap.json",
     check_most_get_a_cve),
    ("A quarter of Rust's do not.", "advisory_gap.json", check_rust_quarter),
    ("In Rust, one advisory in four has no CVE.", "advisory_gap.json",
     check_rust_quarter),
    ("In Rust, one advisory in four has no CVE.", "advisory_gap.json",
     check_rust_is_highest),
    ("In Maven, almost all have one.", "advisory_gap.json",
     check_maven_almost_all),
    ("The advisories without a CVE are not the minor ones.",
     "advisory_gap.json", check_not_the_minor_ones),
    ("More of them are rated Low as well", "advisory_gap.json",
     check_more_low_as_well),
    ("OSV mirrors only GitHub-reviewed advisories", "advisory_gap.json",
     check_reviewed_only),
    ("each of the twelve GitHub advisory ecosystems", "advisory_gap.json",
     check_twelve_ecosystems),
    ("Six in ten of the feed's reports landed in one month.",
     "registry_malware.json", check_six_in_ten_one_month),
    ("of them name one contributor, {peak_top_source}",
     "registry_malware.json", check_peak_names_a_contributor),
    ("In a typical month of the last two years the feed published",
     "registry_malware.json", check_typical_month_window),
    ("npm carries almost every report.", "registry_malware.json",
     check_npm_almost_every),
    ("in 2023 PyPI carried most of the year's reports",
     "registry_malware.json", check_pypi_2023),
    ("Almost no report is taken back.", "registry_malware.json",
     check_almost_none_withdrawn),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[f"{c[2].__name__}-{i}" for i, c in enumerate(CLAIMS)],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
