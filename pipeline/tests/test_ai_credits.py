"""AI-credited CVEs: registry matching, the collector and the builder."""
from __future__ import annotations

from datetime import date

import pytest

# contracts must load before ai_credits_contracts: the coordinator registers
# module contracts from its own module bottom, so importing a module-
# contract file first would hit the registration mid-initialization.
from pipeline import contracts  # noqa: F401
from pipeline import ai_credits_contracts as contract  # noqa: E402
from pipeline import ai_credits_metrics as acm
from pipeline.ai_credits_data import (CLAIM_MAX_AGE_DAYS, CLAIM_QUALIFIERS,
                                      CLAIM_UNIT_KINDS, CLAIMS, FINDERS, GROUPS, classify,
                                      counts_toward_headline)
from pipeline.contracts import ContractViolation
from pipeline.metrics import CveFacts

GENERATED_AT = "2026-07-09T13:00:00Z"


def _record(*credits: str) -> dict:
    return {"containers": {"cna": {
        "credits": [{"lang": "en", "value": c} for c in credits]}}}


def _facts(cve_id: str, published: str | None, cna: str = "VendorX",
           state: str = "PUBLISHED", score: float | None = None) -> CveFacts:
    return CveFacts(cve_id=cve_id, state=state, year=int(cve_id[4:8]),
                    cna=cna, date_published=published,
                    cna_scores={} if score is None else {"v3": score})


# ---------------------------------------------------------------- registry

def test_headline_rule_is_split_by_kind():
    # labs: the credit must name the model; vendors: AI is the product
    assert counts_toward_headline("anthropic", "system")
    assert not counts_toward_headline("anthropic", "org")
    assert not counts_toward_headline("other_llm", "org")
    assert counts_toward_headline("vendor", "org")


def test_registry_is_well_formed():
    keys = [f.key for f in FINDERS]
    assert len(set(keys)) == len(keys)
    assert all(f.group in GROUPS for f in FINDERS)
    assert all(f.system or f.org for f in FINDERS)


@pytest.mark.parametrize("text, expected", [
    ("Nicholas Carlini using Claude, Anthropic", {"anthropic": "system"}),
    ("Alex Gaynor (Anthropic)", {"anthropic": "org"}),
    ("Andrew Nesbitt (powered by Mythos)", {"anthropic": "system"}),
    ("Codex (GPT-5.5)", {"openai": "system"}),
    (", OpenAI Security Research", {"openai": "org"}),
    ("Red Hat would like to thank Google Big Sleep for reporting this "
     "issue.", {"google": "system"}),
    ("Jane Doe using Gemini 2.5 Pro", {"google": "system"}),
    ("Stanislav Fort (Aisle Research)", {"aisle": "org"}),
    ("This issue was discovered by AISLE in partnership with Red Hat.",
     {"aisle": "system"}),
    ("@johnatzeropath", {"zeropath": "org"}),
    ("Quang Luong of Calif.IO in collaboration with OpenAI Codex",
     {"openai": "system"}),
    ("Thai Duong (Calif.io in collaboration with Claude and Anthropic "
     "Research)", {"anthropic": "system"}),
])
def test_classify_positives(text, expected):
    assert classify(text) == expected


@pytest.mark.parametrize("text", [
    # every one of these was caught by a broad \bai\b|gemini|agent probe
    # of the July 2026 corpus — the reason the registry is narrow
    "Nathanael ROTA (Capgemini)",
    "Gui-Dong Han <2045gemini@gmail.com>",
    "Ai Ho (@j3ssiejjj)",
    "A.I. hernandez",
    "Naveen Sunkavally (Horizon3.ai)",
    "Marc Olivier Bergeron (GoSecure.ai)",
    "claudefans (VulDB User)",
    "Jean-Claude Dupont",
    "Eunsoo Kim (Autonomous Code Security team at Microsoft)",
    "vegagent on hackerone",
])
def test_classify_known_negatives(text):
    assert classify(text) == {}


# --------------------------------------------------------------- collector

def test_collector_skips_rejected_undated_and_uncredited():
    col = acm.CreditCollector()
    col(_facts("CVE-2026-0001", "2026-02-03", state="REJECTED"),
        _record("Claude"))
    col(_facts("CVE-2026-0002", None), _record("Claude"))
    col(_facts("CVE-2026-0003", "2026-02-03"), _record())
    col(_facts("CVE-2026-0004", "2026-02-03"), _record("Jane Doe"))
    assert col.rows == []
    assert col.published_by_year[2026] == 2
    assert col.credited_by_year[2026] == 1


def test_collector_strongest_tier_wins_across_credit_lines():
    col = acm.CreditCollector()
    col(_facts("CVE-2026-0005", "2026-03-01", cna="mozilla"),
        _record("Alex Gaynor (Anthropic)", "found using Claude"))
    assert col.rows == [acm.CreditRow("CVE-2026-0005", "2026-03", "mozilla",
                                      {"anthropic": "system"}, "unscored",
                                      False)]


def test_collector_never_keeps_the_raw_credit_string():
    col = acm.CreditCollector()
    col(_facts("CVE-2026-0006", "2026-03-01"),
        _record("Feng Ning (feng@example.ai) using Claude"))
    assert "feng" not in repr(col.rows)


# ----------------------------------------------------------------- builder

def _collector() -> acm.CreditCollector:
    col = acm.CreditCollector(kev_ids=["CVE-2026-0012"])
    col(_facts("CVE-2026-0010", "2026-02-10", cna="mozilla", score=9.8),
        _record("Anthropic (automated discovery using Claude)"))
    col(_facts("CVE-2026-0011", "2026-04-02", cna="openssl", score=5.3),
        _record("Stanislav Fort (Aisle Research)"))
    col(_facts("CVE-2026-0012", "2026-04-20", cna="apache", score=7.5),
        _record("XBOW", "Quang Luong in collaboration with OpenAI Codex"))
    col(_facts("CVE-2026-0013", "2026-04-21"), _record("Jane Doe"))
    col(_facts("CVE-2026-0014", "2026-05-01", score=8.1),
        _record("Alex Gaynor (Anthropic)"))     # lab org tier: board only
    return col


def test_build_empty_has_null_headlines():
    obj = acm.build_ai_credits(acm.CreditCollector(), GENERATED_AT)
    assert obj["board"] == [] and obj["baseline"] is None
    for kind in obj["kinds"].values():
        assert kind["headline"] is None and kind["months"] == []


def test_kinds_are_separate_and_a_dual_credit_lands_in_both():
    kinds = acm.build_ai_credits(_collector(), GENERATED_AT)["kinds"]
    llm, vendor = kinds["llm"], kinds["vendor"]
    assert llm["lanes"] == ["anthropic", "openai", "google", "other_llm"]
    assert vendor["lanes"] == ["vendor"]
    # CVE-0012 credits XBOW and Codex: once in each kind, never summed
    assert llm["headline"]["cves"] == 2 and vendor["headline"]["cves"] == 2
    assert [r["month"] for r in llm["months"]] == [
        "2026-02", "2026-03", "2026-04", "2026-05", "2026-06", "2026-07"]
    assert llm["months"][2] == {"month": "2026-04", "anthropic": 0,
                                "openai": 1, "google": 0, "other_llm": 0,
                                "total": 1}


def test_severity_and_funnel_describe_counted_cves_only():
    obj = acm.build_ai_credits(_collector(), GENERATED_AT)
    llm = obj["kinds"]["llm"]
    # the 8.1 lab-affiliation credit is recorded on the board, not here
    assert llm["severity"] == {"critical": 1, "high": 1, "medium": 0,
                               "low": 0, "unscored": 0}
    assert llm["funnel"] == {"credited": 2, "scored": 2,
                             "high_or_critical": 2,
                             "high_or_critical_pct": 100.0,
                             "kev": 1, "kev_pct": 50.0}
    assert llm["kev_cves"] == ["CVE-2026-0012"]
    anthropic = next(r for r in obj["board"] if r["key"] == "anthropic")
    assert (anthropic["cves"], anthropic["counted"]) == (2, 1)
    assert anthropic["org"] == 1
    assert sum(anthropic["severity"].values()) == anthropic["counted"]


def test_a_post_dated_record_is_dropped_whole():
    col = _collector()
    col(_facts("CVE-2026-0099", "2027-01-05", score=9.9), _record("XBOW"))
    obj = acm.build_ai_credits(col, GENERATED_AT)
    assert obj["kinds"]["vendor"]["headline"]["cves"] == 2
    assert obj["kinds"]["vendor"]["months"][-1]["month"] == "2026-07"
    assert next(r for r in obj["board"] if r["key"] == "xbow")["cves"] == 1
    assert obj["baseline"]["credited"] == 5


def test_baseline_covers_every_credited_cve_in_the_window():
    obj = acm.build_ai_credits(_collector(), GENERATED_AT)
    base = obj["baseline"]
    assert base["from_month"] == "2026-02"
    assert base["credited"] == 5 and base["severity"]["unscored"] == 1
    assert base["kev"] == 1
    assert obj["coverage"] == [{"year": 2026, "published": 5,
                                "with_credits": 5, "pct": 100.0}]


# ------------------------------------------------------------------ claims

def test_claims_registry_is_sourced_and_tied_to_finders():
    keys = {f.key for f in FINDERS}
    for c in CLAIMS:
        assert c.finder in keys
        assert c.unit_kind in CLAIM_UNIT_KINDS
        assert c.qualifier in CLAIM_QUALIFIERS
        assert c.source.startswith("https://") and c.value > 0
        assert c.date <= c.checked          # read on or after it was made
        assert c.checked <= date.today().isoformat()
        if c.live:                          # a running counter is dated
            assert c.date == c.checked      # by the day it was read


@pytest.mark.parametrize("claim", CLAIMS,
                         ids=[f"{c.finder}-{c.value}" for c in CLAIMS])
def test_claim_reading_is_fresh(claim):
    """Fails ON PURPOSE as a reading ages: a quoted number nobody has
    re-opened is a number the page can no longer vouch for. A running
    counter moves, so it gets 45 days; a dated post only needs proof it
    still exists and still says what is quoted. The fix is to open
    ``source``, update the entry and bump ``checked`` — never to raise
    the limit or bump the date unread."""
    limit = CLAIM_MAX_AGE_DAYS["live" if claim.live else "dated"]
    age = (date.today() - date.fromisoformat(claim.checked)).days
    assert age <= limit, (
        f"{claim.finder}: '{claim.value} {claim.unit}' was last read "
        f"{age} days ago (limit {limit}). Re-open {claim.source}, update "
        f"ai_credits_data.CLAIMS and bump `checked`."
    )


def test_claims_carry_the_measured_count_beside_them():
    obj = acm.build_ai_credits(_collector(), GENERATED_AT)
    by_finder = {c["finder"]: c for c in obj["claims"]}
    assert by_finder["xbow"]["credited"] == 1
    assert by_finder["zeropath"]["credited"] == 0   # claimed, never credited
    assert by_finder["anthropic"]["kind"] == "llm"


# ---------------------------------------------------------------- contract

def _valid() -> dict:
    # every committed claim predates this edition
    return acm.build_ai_credits(_collector(), "2026-09-20T03:00:00Z")


def test_contract_accepts_the_builder_output_and_the_empty_case():
    contract.validate("ai_credits.json", _valid())
    contract.validate("ai_credits.json", acm.build_ai_credits(
        acm.CreditCollector(), "2026-09-20T03:00:00Z"))


@pytest.mark.parametrize("mutate", [
    lambda o: o["kinds"]["llm"]["funnel"].update(credited=99),
    lambda o: o["kinds"]["llm"]["severity"].update(high=5),
    lambda o: o["kinds"]["vendor"]["kev_cves"].append("CVE-2026-9999"),
    lambda o: o["kinds"]["llm"]["months"].pop(1),            # a gap
    lambda o: o["board"][0].update(label="Somebody Else"),
    lambda o: o["board"][0].update(counted=o["board"][0]["cves"] + 1),
    lambda o: o["claims"][0].update(source="http://insecure.example"),
    lambda o: o["claims"][0].update(unit_kind="vibes"),
    lambda o: o["claims"][0].update(credited=12345),
    lambda o: o["claims"][0].update(date="last Tuesday"),
    lambda o: o.update(baseline=None),
])
def test_contract_rejects_inconsistent_output(mutate):
    obj = _valid()
    mutate(obj)
    with pytest.raises(ContractViolation):
        contract.validate("ai_credits.json", obj)
