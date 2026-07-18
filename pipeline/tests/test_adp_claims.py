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


def check_ssvc_rides_nearly_every_record(d: dict) -> None:
    # editorial.js (adp_adds caption): "an SSVC decision ... rides on nearly
    # every one"
    pct = d["adds"]["pct_ssvc"]
    assert pct >= 85.0, (
        f"'an SSVC decision rides on nearly every one' needs SSVC on at least "
        f"85% of CISA-ADP records; it is on {pct:.1f}%"
    )


def check_cisa_is_the_sole_substantive_enricher(d: dict) -> None:
    # editorial.js (adp_providers headline): "One agency does almost all of it."
    providers = d["providers"]
    assert providers, "provider board is empty — no ADP data to judge"
    top = providers[0]
    runner_up = providers[1]["n"] if len(providers) > 1 else 0
    assert top["provider"] == "CISA-ADP", (
        f"'one agency does almost all of it' needs CISA-ADP atop the board; "
        f"it is {top['provider']!r}"
    )
    assert top["n"] >= 3 * runner_up, (
        f"'one agency does almost all of it' needs CISA-ADP to dwarf the next "
        f"publisher (>=3x); CISA-ADP={top['n']} vs runner-up={runner_up}"
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
        "an SSVC decision ... rides on nearly every one",
        "adp_coverage.json",
        check_ssvc_rides_nearly_every_record,
    ),
    (
        "One agency does almost all of it",
        "adp_coverage.json",
        check_cisa_is_the_sole_substantive_enricher,
    ),
    (
        "climbs from Vulnrichment's 2024 launch",
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
