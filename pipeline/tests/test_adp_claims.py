"""Claims audit for the Vulnrichment / ADP handoff module (pattern:
test_claims_naming.py).

The adp.html copy (site/js/editorial.js) makes verbal claims about numbers in
site/data/adp_coverage.json, which refreshes nightly from the cvelistV5
corpus. Each CLAIMS entry quotes the copy verbatim (grep for it in
editorial.js) and asserts the underlying number still sits in a range where
the sentence stays true. Ranges are tolerant — normal night-to-night drift
must not trip them; only a claim becoming untrue should.

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim + range, in the same
commit) or the pipeline broke (fix the pipeline). NEVER silence a failing
claim check without doing one of the two.

Skips itself when site/data/ holds sample data or the files are missing —
this audit only ever judges the committed real data. (It skips until the
first real adp_coverage.json is committed, exactly as intended.)
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from . import claims_support

DATA_DIR = claims_support.DATA_DIR

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
    return claims_support.read_json(path)


def check_ssvc_rides_nearly_every_record(d: dict) -> None:
    # editorial.js (adp_adds caption): "An SSVC assessment ... rides on
    # nearly every one"
    pct = d["adds"]["pct_ssvc"]
    assert pct >= 85.0, (
        f"'an SSVC decision rides on nearly every one' needs SSVC on at least "
        f"85% of CISA-ADP records; it is on {pct:.1f}%"
    )


def check_cisa_is_the_sole_substantive_enricher(d: dict) -> None:
    # editorial.js (adp_providers headline): "CISA adds almost all of the
    # substantive ADP enrichment on CVE records." — CISA-ADP's share of all
    # credited publisher-records. (2026-10-03: 193,982 of 195,151, 99.4%.)
    providers = d["providers"]
    assert providers, "provider board is empty — no ADP data to judge"
    top = providers[0]
    total = sum(p["n"] for p in providers)
    assert top["provider"] == "CISA-ADP", (
        f"'CISA adds almost all of it' needs CISA-ADP atop the board; "
        f"it is {top['provider']!r}"
    )
    share = 100.0 * top["n"] / total
    assert share >= 90.0, (
        f"'CISA adds almost all of the substantive ADP enrichment' needs "
        f"CISA-ADP at 90% or more of credited records; it is {share:.1f}% "
        f"({top['n']} of {total})"
    )


def check_one_other_publisher(d: dict) -> None:
    # editorial.js (adp_providers caption and methodology): "One other
    # publisher clears the bar: Red Hat's supplier ADP ... on well under 1%
    # of records". The board has held exactly CISA-ADP and redhat-SADP in
    # every edition since 2026-07-19 (redhat-SADP 1,168-1,169 records,
    # 0.3%); a new publisher, or Red Hat leaving, changes the sentence.
    names = {p["provider"] for p in d["providers"]}
    assert names == {"CISA-ADP", "redhat-SADP"}, (
        f"'One other publisher clears the bar: Red Hat's supplier ADP' vs "
        f"the board {sorted(names)}"
    )
    redhat = next(p for p in d["providers"] if p["provider"] == "redhat-SADP")
    pct = 100.0 * redhat["n"] / d["headline"]["total_published"]
    assert pct < 0.5, (
        f"'on well under 1% of records' vs redhat-SADP on {pct:.2f}%"
    )


def check_vulnrichment_card_adds(d: dict) -> None:
    # editorial.js (home card 16): "adds SSVC decision points to nearly
    # every record it covers, and a CVSS score or a CWE id to about a fifth
    # each". (2026-10-03: SSVC 100.0%, CVSS 22.2%, CWE 20.3%; since July
    # CVSS has run 22.2-22.8% and CWE 19.7-20.4%.)
    adds = d["adds"]
    assert adds["pct_ssvc"] >= 85.0, adds
    for key in ("pct_cvss", "pct_cwe"):
        assert 16.0 <= adds[key] <= 24.0, (
            f"'a CVSS score or a CWE id to about a fifth each' vs {key} "
            f"{adds[key]}%"
        )


def check_handoff_begins_in_the_vulnrichment_era(d: dict) -> None:
    # editorial.js (adp_handoff caption): "climbs from Vulnrichment's 2024
    # launch". This directly guards the module's core landmine: bucketing by
    # the CISA-ADP container's dateUpdated (not the CVE's datePublished). A
    # datePublished axis would push first_month back to the 1999–2015 era.
    first = d["headline"]["first_month"]
    assert first is not None and "2023-06" <= first <= "2025-12", (
        f"'climbs from Vulnrichment's 2024 launch' needs the handoff curve to "
        f"begin in the Vulnrichment era (2023-06..2025-12); first_month is "
        f"{first!r} — a value outside it means the curve is bucketed by the "
        f"CVE's publish date, not the CISA-ADP container's dateUpdated"
    )


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "SSVC decision points, CISA's assessment of exploitation, automatability and technical impact, appear on nearly every one",
        "adp_coverage.json",
        check_ssvc_rides_nearly_every_record,
    ),
    (
        "CISA adds almost all of the substantive ADP enrichment on CVE records.",
        "adp_coverage.json",
        check_cisa_is_the_sole_substantive_enricher,
    ),
    (
        "One other publisher clears the bar: Red Hat's supplier ADP, which adds "
        "data about products Red Hat ships, on well under 1% of records.",
        "adp_coverage.json",
        check_one_other_publisher,
    ),
    (
        "the one other publisher that clears the bar is Red Hat's supplier ADP "
        "(redhat-SADP), on well under 1% of published records.",
        "adp_coverage.json",
        check_one_other_publisher,
    ),
    (
        "adds SSVC decision points to nearly every record it covers, and a CVSS "
        "score or a CWE id to about a fifth each",
        "adp_coverage.json",
        check_vulnrichment_card_adds,
    ),
    (
        "The series starts at Vulnrichment's 2024 launch",
        "adp_coverage.json",
        check_handoff_begins_in_the_vulnrichment_era,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
