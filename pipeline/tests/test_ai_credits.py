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
                                      CLAIM_UNIT_KINDS, CLAIMS,
                                      WEAKNESS_FAMILIES, WEAKNESS_KEYS,
                                      weakness_family, FINDERS, GROUPS, classify,
                                      counts_toward_headline)
from pipeline.contracts import ContractViolation
from pipeline.metrics import CveFacts

GENERATED_AT = "2026-07-09T13:00:00Z"


def _record(*credits, vendor: str | None = None,
            product: str | None = None) -> dict:
    """``credits`` are strings, or ``(value, schema role)`` pairs."""
    cna: dict = {"credits": [
        {"lang": "en", "value": c} if isinstance(c, str)
        else {"lang": "en", "value": c[0], "type": c[1]} for c in credits]}
    if vendor is not None or product is not None:
        cna["affected"] = [{"vendor": vendor, "product": product}]
    return {"containers": {"cna": cna}}


def _facts(cve_id: str, published: str | None, cna: str = "VendorX",
           state: str = "PUBLISHED", score: float | None = None,
           cwe: str | None = None, adp_score: float | None = None
           ) -> CveFacts:
    return CveFacts(cve_id=cve_id, state=state, year=int(cve_id[4:8]),
                    cna=cna, date_published=published, cwe=cwe,
                    cna_scores={} if score is None else {"v3": score},
                    adp_scores={} if adp_score is None else {"v3": adp_score})


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
    (row,) = col.rows
    assert (row.cve_id, row.cna, row.found, row.target) == (
        "CVE-2026-0005", "mozilla", {"anthropic": "system"}, "")
    assert row.roles == {"anthropic": ("unspecified",)}
    assert row.traits == acm.Traits(
        month="2026-03", published="2026-03-01", severity="unscored",
        score=None, cna_scored=False, cwe=None, epss_pctile=None,
        in_kev=False, has_poc=False)
    assert col.credited == [row.traits]     # the baseline keeps it too


def test_a_remediation_credit_is_a_fix_not_a_find():
    # CVE schema roles matter: "Claude" as remediation developer wrote the
    # patch. It is recorded (tier fix) and never counted. Regression for
    # the 2026-09-20 review: 31 Anthropic CVEs were counted this way.
    col = acm.CreditCollector()
    col(_facts("CVE-2026-0007", "2026-03-02", cna="misp", score=7.0),
        _record(("Jane Doe", "finder"), ("Claude", "remediation developer")))
    col(_facts("CVE-2026-0008", "2026-03-03", score=7.0),
        _record(("Claude", "remediation reviewer"), ("Claude", "finder")))
    fix, find = col.rows
    assert fix.found == {"anthropic": "fix"}
    assert find.found == {"anthropic": "system"}      # the find outranks it
    assert find.roles == {"anthropic": ("finder", "remediation reviewer")}
    obj = acm.build_ai_credits(col, GENERATED_AT)
    row = obj["board"][0]
    assert (row["cves"], row["counted"], row["fix"]) == (2, 1, 1)
    assert obj["kinds"]["llm"]["headline"]["cves"] == 1


def test_oss_fuzz_gen_is_matched_and_plain_oss_fuzz_is_not():
    # CVE-2024-9143 (2024-10-16) credits "Google OSS-Fuzz-Gen" as finder —
    # the counterexample to the page's first "no AI finder before 2025"
    # headline. Classic OSS-Fuzz has been credited since 2017 and is not AI.
    assert classify("Google OSS-Fuzz-Gen", "finder") == {"google": "system"}
    assert classify("OSS-Fuzz", "finder") == {}
    assert classify("Found by OSS-Fuzz in https://bugs.chromium.org/x") == {}


def test_collector_never_keeps_the_raw_credit_string():
    col = acm.CreditCollector()
    col(_facts("CVE-2026-0006", "2026-03-01"),
        _record("Feng Ning (feng@example.ai) using Claude"))
    assert "feng" not in repr(col.rows)


# ----------------------------------------------------------------- builder

def _collector() -> acm.CreditCollector:
    col = acm.CreditCollector(
        kev_ids=["CVE-2026-0012"], poc_ids=["CVE-2026-0011", "CVE-2026-0013"],
        epss_percentiles={"CVE-2026-0010": 0.20, "CVE-2026-0012": 0.90,
                          "CVE-2026-0011": 0.40})
    col(_facts("CVE-2026-0010", "2026-02-10", cna="mozilla", score=9.8,
               cwe="CWE-416"),
        _record("Anthropic (automated discovery using Claude)",
                vendor="Mozilla", product="Firefox"))
    col(_facts("CVE-2026-0011", "2026-04-02", cna="openssl", score=5.3,
               cwe="CWE-125"),
        _record("Stanislav Fort (Aisle Research)",
                vendor="OpenSSL", product="openssl"))
    col(_facts("CVE-2026-0012", "2026-04-20", cna="apache", adp_score=7.5,
               cwe="CWE-79"),
        _record("XBOW", "Quang Luong in collaboration with OpenAI Codex",
                vendor="n/a", product="OpenSSL"))
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
                             "poc": 0, "poc_pct": 0.0,
                             "kev": 1, "kev_pct": 50.0}
    # the AISLE CVE has public exploit code; the stage is a share of
    # credited, not nested under high-or-critical (it is a 5.3)
    assert obj["kinds"]["vendor"]["funnel"]["poc"] == 1
    assert obj["baseline"]["poc"] == 2
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


# ---------------------------------------------- profile, weaknesses, targets

def test_weakness_family_membership():
    assert weakness_family("CWE-416") == "memory"
    assert weakness_family("CWE-79") == "injection"
    assert weakness_family("CWE-862") == "access"
    assert weakness_family("CWE-9999") == "other"
    assert weakness_family("NVD-CWE-noinfo") == "other"
    assert weakness_family(None) == "none"
    ids = [i for _, _, members in WEAKNESS_FAMILIES for i in members]
    assert len(ids) == len(set(ids))        # a CWE lives in one family


def test_profile_columns_describe_each_population():
    profile = acm.build_ai_credits(_collector(), GENERATED_AT)["profile"]
    assert list(profile) == ["llm", "vendor", "baseline"]
    llm = profile["llm"]            # CVE-0010 (9.8, p20) + CVE-0012 (7.5, p90)
    assert (llm["n"], llm["median_cvss"], llm["median_epss_pctile"]) == \
        (2, 8.7, 55.0)
    assert llm["memory_pct"] == 50.0
    assert llm["cna_scored_pct"] == 50.0    # 0012 was scored by an ADP only
    assert llm["top_cwe"] == {"cwe": "CWE-416", "n": 1, "pct": 50.0}
    base = profile["baseline"]
    assert (base["n"], base["epss_scored"]) == (5, 3)
    assert base["poc_pct"] == 40.0
    # cohort age: everything in the fixture predates 2026-07-09 by < 90 days
    # except the February lab CVE
    assert (llm["recent_days"], llm["recent_pct"]) == (90, 50.0)


def test_weakness_families_add_back_up_to_each_population():
    obj = acm.build_ai_credits(_collector(), GENERATED_AT)
    families = obj["weaknesses"]["families"]
    assert [f["key"] for f in families] == list(WEAKNESS_KEYS)
    for name, size in (("llm", 2), ("vendor", 2), ("baseline", 5)):
        assert sum(f[name]["n"] for f in families) == size
    memory = families[0]
    assert (memory["llm"]["n"], memory["vendor"]["n"]) == (1, 1)
    none = families[-1]
    assert none["baseline"] == {"n": 2, "pct": 40.0}


def test_targets_fold_spelling_and_drop_placeholder_vendors():
    targets = acm.build_ai_credits(_collector(), GENERATED_AT)["targets"]
    # "OpenSSL / openssl" folds to the product; "n/a" is not a vendor —
    # so AISLE's and XBOW's records name the same target
    assert targets["vendor"]["projects"] == [
        {"label": "OpenSSL", "n": 2, "pct": 100.0}]
    assert targets["vendor"]["top_share_pct"] == 100.0
    assert targets["llm"]["projects"][0]["label"] in (
        "Mozilla / Firefox", "OpenSSL")
    assert targets["llm"]["distinct"] == 2


def test_target_never_returns_a_bare_placeholder():
    assert acm._target(_record("x", vendor="n/a", product="unknown")) == ""
    assert acm._target(_record("x")) == ""
    assert acm._target(_record("x", vendor="Acme", product=None)) == "Acme"
    rhel = _record("x", vendor="Red Hat",
                   product="Red Hat Enterprise Linux 10")
    assert acm._target(rhel) == "Red Hat Enterprise Linux 10"


# ------------------------------------------------------------------ ledger

def test_ledger_lists_every_match_without_credit_text():
    col = _collector()
    ledger = acm.build_ai_credits_ledger(col, GENERATED_AT)
    assert [r["cve"] for r in ledger["rows"]] == [
        "CVE-2026-0010", "CVE-2026-0011", "CVE-2026-0012", "CVE-2026-0014"]
    dual = ledger["rows"][2]
    assert dual["counts_for"] == ["llm", "vendor"]
    assert dual["matches"] == [
        {"finder": "openai", "tier": "system", "roles": ["unspecified"]},
        {"finder": "xbow", "tier": "system", "roles": ["unspecified"]}]
    assert ledger["rows"][3]["counts_for"] == []    # lab named, not counted
    assert "Gaynor" not in repr(ledger) and "Fort" not in repr(ledger)
    contract.validate("ai_credits_ledger.json", ledger)


@pytest.mark.parametrize("mutate", [
    lambda o: o["rows"][0].update(credit="Jane Doe <jane@example.org>"),
    lambda o: o["rows"][0]["matches"][0].update(tier="vibes"),
    lambda o: o["rows"][0]["matches"][0].update(finder="somebody"),
    lambda o: o["rows"][3].update(counts_for=["llm"]),
    lambda o: o["rows"].reverse(),
])
def test_ledger_contract_rejects_tampering(mutate):
    ledger = acm.build_ai_credits_ledger(_collector(), GENERATED_AT)
    mutate(ledger)
    with pytest.raises(ContractViolation):
        contract.validate("ai_credits_ledger.json", ledger)


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
    lambda o: o.update(profile=None),
    lambda o: o["kinds"]["vendor"]["funnel"].update(poc=99),
    lambda o: o["profile"]["llm"].update(n=7),
    lambda o: o["profile"]["vendor"].update(poc_pct=12.3),
    lambda o: o["weaknesses"]["families"].pop(0),
    lambda o: o["weaknesses"]["families"][0]["llm"].update(n=5),
    lambda o: o["targets"]["llm"]["projects"][0].update(
        label="jane@example.org"),
    lambda o: o["targets"]["vendor"].update(cves=99),
])
def test_contract_rejects_inconsistent_output(mutate):
    obj = _valid()
    mutate(obj)
    with pytest.raises(ContractViolation):
        contract.validate("ai_credits.json", obj)
