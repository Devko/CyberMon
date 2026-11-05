"""Claims audit for the Machine-Readable Advisories module (csaf.html; the
test_claims_c2.py pattern).

The csaf.html copy (site/js/editorial.js, sections csaf_*, and the home
card) makes verbal claims about site/data/csaf_adoption.json. Each CLAIMS
entry quotes the copy verbatim and asserts the data still sits where the
sentence stays true. The wording was chosen with margin (2026-11-05: VEX
61.6% of documents against the 50% "most" line; Red Hat 99.9% of VEX
documents; 2026 at 36,321 documents against 23,960 for 2024 and 2025
together; pooled advisory/VEX field gaps of 33-36 points), so a month of
ordinary drift cannot trip them; only a claim becoming untrue should.

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim + assertion, in the same
commit) or the pipeline broke (fix the pipeline). Never silence a failing
claim check without doing one of the two.

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
if json.loads(_meta_path.read_text("utf-8")).get("sample") is True:
    pytest.skip("site/data holds sample data — claims audit only judges "
                "real data", allow_module_level=True)


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return claims_support.read_json(path)


def _year(d: dict, year: int) -> int:
    return next((y["n"] for y in d["years"] if y["year"] == year), 0)


def check_most_documents_are_vex(d: dict) -> None:
    # editorial.js (csaf.html hero headline and the home card): "Most
    # documents in the listed CSAF feeds are VEX documents, and Red Hat
    # publishes nearly all of them." Most = more than half of all counted
    # documents (estimated per distribution from the sample; Red Hat's VEX
    # documents sit in their own all-VEX directory). Nearly all = at least
    # nine in ten of the VEX documents. (2026-11-05: 75,584 of 122,714 =
    # 61.6%; Red Hat 99.9% of them.)
    t = d["totals"]
    assert t["documents"] > 0, "no documents counted"
    assert t["vex_pct"] > 50.0, (
        f"'most documents ... are VEX documents' vs {t['vex_pct']}%")
    assert (t["vex_top_name"] or "").startswith("Red Hat"), (
        f"'Red Hat publishes nearly all of them' — the largest VEX "
        f"publisher is now {t['vex_top_name']!r}")
    assert t["vex_top_share_pct"] >= 90.0, (
        f"'nearly all of them' vs Red Hat's {t['vex_top_share_pct']}% of "
        f"VEX documents")


def check_2026_beats_2024_and_2025(d: dict) -> None:
    # editorial.js (csaf.html years headline): "More documents in the listed
    # feeds were first released in 2026 than in 2024 and 2025 combined."
    # The sentence names 2026, the current partial year in this edition;
    # its count only grows until the year ends, so a January edition cannot
    # falsify it — judged() still gates the read, as for every
    # current-year guard. (2026-11-05: 36,321 vs 11,622 + 12,338.)
    n2026 = _year(d, 2026)
    if not claims_support.judged(2026, n2026, min_n=1):
        pytest.skip("2026 has no counted documents in this edition")
    earlier = _year(d, 2024) + _year(d, 2025)
    assert n2026 > earlier, (
        f"'more ... first released in 2026 than in 2024 and 2025 combined' "
        f"vs {n2026} against {earlier}")


def check_converted_older_advisories(d: dict) -> None:
    # editorial.js (csaf.html years caption): "It can predate the CSAF file,
    # because providers have converted older advisories to CSAF." Holds
    # while some counted provider lists documents first released before
    # 2017, years before the CSAF 2.0 format existed. (2026-11-05: Red Hat
    # from 1999, Siemens from 2011, BSI from 2013, Schneider Electric from
    # 2015.)
    firsts = [r["first_year"] for r in d["sources"]
              if r["status"] in ("measured", "carried") and r["first_year"]]
    assert firsts and min(firsts) < 2017, (
        f"'providers have converted older advisories' — earliest first "
        f"release year is {min(firsts) if firsts else None}")


def check_advisories_more_complete_than_vex(d: dict) -> None:
    # editorial.js (csaf.html fields headline): "In the sample, security
    # advisories carry a CVSS vector, a CWE and a remediation more often
    # than VEX documents do." Read from the pooled sample rows the chart
    # shows. A 10-point floor on each gap absorbs sampling noise (about
    # 94 VEX and 176 advisories sampled): a narrower gap is no longer a
    # difference the sample can carry. (2026-11-05: CVSS 97.7 vs 64.9,
    # CWE 93.8 vs 57.4, remediation 96.6 vs 60.6.)
    g = d["totals"]["by_group"]
    assert "advisory" in g and "vex" in g, (
        f"pooled rows missing: {sorted(g)}")
    for field in ("cvss", "cwe", "remediation"):
        adv, vex = g["advisory"][field], g["vex"][field]
        assert adv - vex >= 10.0, (
            f"'advisories carry {field} more often than VEX documents' vs "
            f"{adv}% against {vex}%")


def check_counts_not_documents(d: dict) -> None:
    # editorial.js (csaf.html fields methodology): "Only the presence of
    # fields is read; no document text is republished." Structural: the
    # emitted file carries no document URL, title or note — the only URL in
    # it is the lister's own.
    lister = d["lister"]["url"]

    def walk(node, path="csaf_adoption"):
        if isinstance(node, dict):
            for k, v in node.items():
                assert k not in ("title", "notes", "summary", "url_list"), (
                    f"{path}.{k}: document content in the emitted file")
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str) and "://" in node:
            assert node == lister, f"{path}: URL {node!r} in the emitted file"

    walk(d)


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "Most documents in the listed CSAF feeds are VEX documents, and Red "
        "Hat publishes nearly all of them.",
        "csaf_adoption.json",
        check_most_documents_are_vex,
    ),
    (
        "More documents in the listed feeds were first released in 2026 than "
        "in 2024 and 2025 combined.",
        "csaf_adoption.json",
        check_2026_beats_2024_and_2025,
    ),
    (
        "It can predate the CSAF file, because providers have converted older "
        "advisories to CSAF.",
        "csaf_adoption.json",
        check_converted_older_advisories,
    ),
    (
        "In the sample, security advisories carry a CVSS vector, a CWE and a "
        "remediation more often than VEX documents do.",
        "csaf_adoption.json",
        check_advisories_more_complete_than_vex,
    ),
    (
        "Only the presence of fields is read; no document text is "
        "republished.",
        "csaf_adoption.json",
        check_counts_not_documents,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
