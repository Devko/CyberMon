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

from . import claims_support

DATA_DIR = claims_support.DATA_DIR

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
    obj = claims_support.read_json(path)
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


def check_fewer_than_one_in_ten(d: dict) -> None:
    # gap_years headline: "Fewer than one GitHub-reviewed advisory in ten
    # carries no CVE id." — under 10%, and no lower than one in sixteen
    # (6.25%), below which the phrase would overstate the gap. (2026-11-04:
    # 2,900 of 36,279 = 8.0%.) Was "About one … in twelve" (7.7-9.1%) until
    # 2026-11-04. That guard's note expected two years of margin, but the
    # no-CVE count does not grow: CVE aliases reach older advisories as fast
    # as new no-CVE ones arrive (2,904 on 09-23, 2,900 on 11-04) while the
    # total grows by about 1,100 a month, so the share fell 8.35% → 7.99%
    # in six weeks and would have left "one in twelve" around December. With
    # the count flat it reaches one in sixteen at about 46,400 advisories,
    # around August 2027.
    cat = d["catalog"]
    pct = 100.0 * cat["without_cve"] / cat["advisories"]
    assert 100 / 16 <= pct < 10, (
        f"'Fewer than one advisory in ten' needs a no-CVE share of "
        f"6.25-10%; it is {pct:.1f}% ({cat['without_cve']} of "
        f"{cat['advisories']})")


def check_rust_quarter(d: dict) -> None:
    # "a quarter" / "one advisory in four": 21-30% reads as a quarter.
    # (2026-10-03: 26.4%, 395 of 1,497.)
    pct = _eco(d, "crates.io")["without_cve_pct"]
    assert pct is not None and 21 <= pct <= 30, (
        f"'a quarter of Rust's do not' needs crates.io's no-CVE share near "
        f"25%; it is {pct}%")


# Ecosystems a reader would set Rust beside: the large registries.
_LARGE_ECOSYSTEM = 1000  # advisories, all publication years


def check_rust_highest_of_large(d: dict) -> None:
    # The gap_ecosystems headline and the Advisories home card single out
    # Rust's no-CVE share, which reads as Rust standing out among the main
    # package registries. Among ecosystems with 1,000+ advisories it must be
    # the highest. (2026-10-03: crates.io 26.4% of 1,497; next npm 15.1% of
    # 7,238.) Smaller ecosystems are not ranked here, because the copy says
    # nothing about them: GitHub Actions (25.5%, 14 of 55) sits one advisory
    # from Rust's share, and the chart's accent on the top bar is a drawing
    # rule, not a claim.
    large = [e for e in d["ecosystems"] if e["total"] >= _LARGE_ECOSYSTEM
             and e["without_cve_pct"] is not None]
    assert any(e["ecosystem"] == "crates.io" for e in large), (
        "crates.io has fewer than 1,000 advisories in this edition")
    top = max(large, key=lambda e: e["without_cve_pct"])
    assert top["ecosystem"] == "crates.io", (
        f"the copy singles out Rust, but {top['ecosystem']} now has the "
        f"highest no-CVE share among the large ecosystems "
        f"({top['without_cve_pct']}%)")


def check_maven_almost_all(d: dict) -> None:
    pct = _eco(d, "Maven")["without_cve_pct"]
    assert pct is not None and pct <= 3, (
        f"'In Maven, almost all have one' needs Maven's no-CVE share at 3% "
        f"or less; it is {pct}%")


def check_not_the_minor_ones(d: dict) -> None:
    # gap_severity headline: "No-CVE advisories are rated Critical or Low
    # more often" — more often Critical AND more often Low than the CVE set.
    # (2026-11-04: Critical 22.2% vs 12.2%, Low 12.8% vs 6.8%.)
    crit = _sev(d, "CRITICAL")
    check_more_low_as_well(d)
    assert crit["without_cve_pct"] > crit["with_cve_pct"], (
        f"'rated Critical … more often': the no-CVE set is no longer more "
        f"often Critical ({crit['without_cve_pct']}% vs "
        f"{crit['with_cve_pct']}%)")


def check_more_low_as_well(d: dict) -> None:
    low = _sev(d, "LOW")
    assert low["without_cve_pct"] > low["with_cve_pct"], (
        f"'rated … Low more often' is no longer true "
        f"({low['without_cve_pct']}% vs {low['with_cve_pct']}%)")


# No-CVE Critical advisories that are malicious-package notices, by GitHub's
# advisory API on 2026-09-23 (367 of them npm from 2020). The export does not
# flag them (docs/backlog.md: tag them in the pipeline), so this dated count
# stands in for a measured one; the methodology quotes it with its date.
MALWARE_CRITICAL_NOTICES = 400


def check_criticals_net_of_malware_notices(d: dict) -> None:
    # gap_severity headline: "hundreds of the Criticals are malware notices";
    # caption: "Without the malicious-package notices, the no-CVE advisories
    # are rated Critical less often than the ones with a CVE." (2026-11-04:
    # 645 no-CVE Criticals; net of 400 notices, 245 of 2,500 = 9.8% against
    # 12.2% with a CVE.)
    crit = _sev(d, "CRITICAL")
    assert crit["without_cve"] >= MALWARE_CRITICAL_NOTICES, (
        f"the export has {crit['without_cve']} no-CVE Critical advisories, "
        f"fewer than the {MALWARE_CRITICAL_NOTICES} malware notices quoted")
    rest = crit["without_cve"] - MALWARE_CRITICAL_NOTICES
    pool = d["catalog"]["without_cve"] - MALWARE_CRITICAL_NOTICES
    pct = 100.0 * rest / pool
    assert pct < crit["with_cve_pct"], (
        f"'Without the malicious-package notices … rated Critical less "
        f"often' fails: {pct:.1f}% of the rest vs {crit['with_cve_pct']}% "
        f"with a CVE")


def check_reviewed_only(d: dict) -> None:
    n = d["catalog"]["not_reviewed"]
    assert n == 0, (f"'OSV mirrors only GitHub-reviewed advisories': {n} live "
                    f"GHSA records in the exports lack the reviewed flag")


def check_twelve_ecosystems(d: dict) -> None:
    assert len(d["ecosystems_read"]) == 12, (
        f"the methodology names twelve ecosystems; the edition read "
        f"{len(d['ecosystems_read'])}")


# ---- registry_malware.json ----------------------------------------------------------

def check_more_than_half_one_month(d: dict) -> None:
    # mal_months headline and the Malicious Packages home card: more than
    # half of all reports on file were published in one calendar month.
    # (2026-10-03: November 2025, 142,256 of 239,077 = 59.5%. The old "six
    # in ten" fell below 60% on 2026-09-23 and loses ~0.3 points every 11
    # days as the feed grows. Half is ~45,000 more reports away: two to
    # three years at 2026's pace of ~1,900 a month, unless a new burst.)
    cat = d["catalog"]
    pct = 100.0 * cat["peak_reports"] / cat["reports"]
    assert pct > 50, (f"'More than half of the feed's reports were published "
                      f"in a single month' — the peak month ({cat['peak_month']}) "
                      f"holds {pct:.1f}%")


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
    # mal_share headline: "npm accounts for almost every report on file".
    # (2026-10-03: 222,193 of 239,077 = 92.9%. 2026's reports are 73% npm,
    # so the share sinks slowly: some 40,000 more reports at that mix
    # before it reaches 90%.)
    npm = _eco(d, "npm")["reports"]
    pct = 100 * npm / d["catalog"]["reports"]
    assert pct >= 90, (f"'npm carries almost every report' needs npm at 90% "
                       f"or more of all reports; it is {pct:.1f}%")


def check_pypi_2023(d: dict) -> None:
    y = next(r for r in d["years"] if r["year"] == 2023)
    pypi = y["by_ecosystem"].get("PyPI", 0)
    assert pypi > y["total"] / 2, (
        f"'PyPI had most of 2023's' — PyPI holds "
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
    # home card (Advisories Without a CVE). The Rust half said "a quarter
    # of Rust's do not" until 2026-11-04 (25.4% that night, a point lower
    # than on 10-03, against a floor of 21); it now states the ranking.
    ("Most GitHub-reviewed advisories carry a CVE id", "advisory_gap.json",
     check_most_get_a_cve),
    ("Rust's lack one more often than those of any other large registry.",
     "advisory_gap.json", check_rust_highest_of_large),
    # advisories.html
    ("Fewer than one GitHub-reviewed advisory in ten carries no CVE id.",
     "advisory_gap.json", check_fewer_than_one_in_ten),
    ("About one Rust advisory in four has no CVE id", "advisory_gap.json",
     check_rust_quarter),
    ("About one Rust advisory in four has no CVE id", "advisory_gap.json",
     check_rust_highest_of_large),
    ("almost every Maven advisory has one", "advisory_gap.json",
     check_maven_almost_all),
    ("No-CVE advisories are rated Critical or Low more often",
     "advisory_gap.json", check_not_the_minor_ones),
    ("and hundreds of the Criticals are malware notices",
     "advisory_gap.json", check_criticals_net_of_malware_notices),
    ("Without the malicious-package notices, the no-CVE advisories are rated "
     "Critical less often than the ones with a CVE.",
     "advisory_gap.json", check_criticals_net_of_malware_notices),
    ("OSV mirrors only GitHub-reviewed advisories", "advisory_gap.json",
     check_reviewed_only),
    ("each of the twelve GitHub advisory ecosystems", "advisory_gap.json",
     check_twelve_ecosystems),
    # home card (Malicious Packages), then malware.html
    ("More than half of the reports in the OpenSSF malicious-packages feed "
     "were published in a single month.", "registry_malware.json",
     check_more_than_half_one_month),
    ("More than half of the feed's reports were published in a single month.",
     "registry_malware.json", check_more_than_half_one_month),
    ("of them name one contributor, {peak_top_source}",
     "registry_malware.json", check_peak_names_a_contributor),
    ("In a typical month of the last two years the feed published",
     "registry_malware.json", check_typical_month_window),
    ("npm accounts for almost every report on file", "registry_malware.json",
     check_npm_almost_every),
    ("but PyPI had most of 2023's", "registry_malware.json",
     check_pypi_2023),
    ("Almost no report in the feed has been withdrawn", "registry_malware.json",
     check_almost_none_withdrawn),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[f"{c[2].__name__}-{i}" for i, c in enumerate(CLAIMS)],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
