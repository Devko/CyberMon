"""adp_metrics tests: CISA-ADP detection in extract_facts, aggregator
accumulation, the coverage builder's monthly gap-fill / min_n / back-fill
flag / adds / provider board / headline math, and the offline end-to-end run
emitting a valid adp_coverage.json."""
from __future__ import annotations

import json

from pipeline import contracts, metrics
from pipeline import adp_contracts  # noqa: E402  (registration order — see below)
from pipeline.__main__ import main
from pipeline.adp_metrics import build_adp_coverage
from pipeline.metrics import Aggregator, CveFacts, extract_facts

GENERATED_AT = "2026-07-09T00:00:00Z"


# ------------------------------------------------------------- extraction

def _record(**adp) -> dict:
    """A minimal published CVE record carrying one ADP container. The CVE ID
    is a 2019 vintage so a 2025 enrichment reads as a legacy back-fill."""
    return {
        "cveMetadata": {"cveId": "CVE-2019-1234", "state": "PUBLISHED",
                        "assignerShortName": "acme"},
        "containers": {"cna": {}, "adp": [adp]},
    }


def test_extract_detects_cisa_adp_by_shortname_and_captures_month():
    facts = extract_facts(_record(
        providerMetadata={"shortName": "CISA-ADP",
                          "dateUpdated": "2025-06-15T00:00:00.000Z"},
        metrics=[{"other": {"type": "ssvc"}},
                 {"cvssV3_1": {"baseScore": 7.5}}],
        problemTypes=[{"descriptions": [{"cweId": "CWE-79"}]}]))
    assert facts.adp_cisa is True
    assert facts.adp_cisa_month == "2025-06"
    assert facts.adp_added == frozenset({"ssvc", "cvss", "cwe"})
    assert facts.adp_providers == ("CISA-ADP",)
    # CVE-2019 enriched in 2025 -> legacy back-fill (gap >= 2 years).
    assert facts.adp_cisa_legacy is True


def test_extract_detects_cisa_adp_by_orgid_when_shortname_differs():
    facts = extract_facts(_record(
        providerMetadata={"shortName": "Zzz",
                          "orgId": metrics.ADP_CISA_ORGID,
                          "dateUpdated": "2024-05-01T00:00:00Z"}))
    assert facts.adp_cisa is True
    # No metrics/problemTypes -> adds nothing, but still a carrier.
    assert facts.adp_added == frozenset()
    assert facts.adp_providers == ("Zzz",)


def test_extract_non_cisa_adp_is_a_provider_but_not_cisa():
    facts = extract_facts(_record(
        providerMetadata={"shortName": "CVE Program Container"},
        references=[{"url": "https://example"}]))
    assert facts.adp_cisa is False
    assert facts.adp_cisa_month is None
    assert facts.adp_added == frozenset()
    assert facts.adp_providers == ("CVE Program Container",)


def test_extract_cisa_adp_without_dateupdated_has_no_month():
    facts = extract_facts(_record(
        providerMetadata={"shortName": "CISA-ADP"},
        metrics=[{"other": {"type": "ssvc"}}]))
    assert facts.adp_cisa is True and facts.adp_added == frozenset({"ssvc"})
    assert facts.adp_cisa_month is None and facts.adp_cisa_legacy is False


def test_extract_recent_cve_enrichment_is_not_legacy():
    rec = _record(providerMetadata={"shortName": "CISA-ADP",
                                    "dateUpdated": "2025-02-01T00:00:00Z"})
    rec["cveMetadata"]["cveId"] = "CVE-2025-0009"  # same-year vintage
    facts = extract_facts(rec)
    assert facts.adp_cisa_month == "2025-02" and facts.adp_cisa_legacy is False


def test_extract_multiple_providers_deduped_in_order():
    rec = {
        "cveMetadata": {"cveId": "CVE-2024-0001", "state": "PUBLISHED"},
        "containers": {"cna": {}, "adp": [
            {"providerMetadata": {"shortName": "CVE Program Container"}},
            {"providerMetadata": {"shortName": "CISA-ADP",
                                  "dateUpdated": "2024-07-01T00:00:00Z"}},
            {"providerMetadata": {"shortName": "CVE Program Container"}},
        ]},
    }
    facts = extract_facts(rec)
    assert facts.adp_providers == ("CVE Program Container", "CISA-ADP")
    assert facts.adp_cisa is True and facts.adp_cisa_month == "2024-07"


def test_reference_only_provider_excluded_from_substantive_board():
    # The CVE-program root rides on the record but adds only reference tags;
    # only CISA-ADP (an SSVC decision here) is a substantive enricher.
    rec = {
        "cveMetadata": {"cveId": "CVE-2024-0002", "state": "PUBLISHED"},
        "containers": {"cna": {}, "adp": [
            {"providerMetadata": {"shortName": "CVE"}},
            {"providerMetadata": {"shortName": "CISA-ADP",
                                  "dateUpdated": "2024-07-01T00:00:00Z"},
             "metrics": [{"other": {"type": "ssvc", "content": {"id": "x"}}}]},
        ]},
    }
    facts = extract_facts(rec)
    assert facts.adp_providers == ("CVE", "CISA-ADP")
    assert facts.adp_substantive == ("CISA-ADP",)


# ------------------------------------------------------------ aggregation

def test_aggregator_accumulates_published_only():
    agg = Aggregator()
    agg.add(CveFacts("CVE-2019-1", "PUBLISHED", 2019, "acme",
                     adp_cisa=True, adp_cisa_month="2025-03",
                     adp_cisa_legacy=True,
                     adp_added=frozenset({"ssvc", "cvss"}),
                     adp_providers=("CISA-ADP", "CVE Program Container"),
                     adp_substantive=("CISA-ADP",)))
    # REJECTED records return early and never reach the ADP tallies.
    agg.add(CveFacts("CVE-2025-2", "REJECTED", 2025, "acme",
                     adp_cisa=True, adp_cisa_month="2025-03",
                     adp_providers=("CISA-ADP",)))
    assert agg.adp_published_total == 1
    assert agg.adp_cisa_total == 1
    assert dict(agg.adp_add_counts) == {"ssvc": 1, "cvss": 1}
    assert dict(agg.adp_month_enriched) == {"2025-03": 1}
    assert dict(agg.adp_month_legacy) == {"2025-03": 1}
    assert dict(agg.adp_provider_counts) == {"CISA-ADP": 1,
                                             "CVE Program Container": 1}
    # Only the substantive enricher (not the reference-only root) is boarded.
    assert dict(agg.adp_provider_substantive) == {"CISA-ADP": 1}


# ---------------------------------------------------------------- builder

def _agg(months_enriched, *, months_legacy=None, adds=None, providers=None,
         published=0, cisa=0) -> Aggregator:
    """A bare aggregator with its ADP tallies poked directly (the metrics.py
    pattern for builder-math tests)."""
    agg = Aggregator()
    agg.adp_published_total = published
    agg.adp_cisa_total = cisa
    agg.adp_month_enriched.update(months_enriched)
    agg.adp_month_legacy.update(months_legacy or {})
    agg.adp_add_counts.update(adds or {})
    agg.adp_provider_substantive.update(providers or {})
    return agg


def test_build_gap_fills_months_and_respects_min_n_start():
    agg = _agg({"2024-05": 5, "2024-08": 40, "2024-11": 3},
               published=100, cisa=48)
    out = build_adp_coverage(agg, GENERATED_AT, min_n=10)
    # min_n=10 -> series starts at the first month clearing 10 (2024-08),
    # gap-filled through the last observed month (2024-11); 2024-05 (below
    # the floor and before the start) drops out entirely.
    assert [m["month"] for m in out["months"]] == [
        "2024-08", "2024-09", "2024-10", "2024-11"]
    by = {m["month"]: m for m in out["months"]}
    assert by["2024-08"]["enriched"] == 40
    assert by["2024-09"]["enriched"] == 0   # gap-filled
    assert by["2024-11"]["enriched"] == 3   # within range, kept honestly
    contracts.validate("adp_coverage.json", out)


def test_build_flags_backfill_sweep_month():
    agg = _agg({"2025-01": 100, "2025-02": 100},
               months_legacy={"2025-01": 80, "2025-02": 10},
               published=500, cisa=200)
    out = build_adp_coverage(agg, GENERATED_AT, min_n=50)
    by = {m["month"]: m for m in out["months"]}
    assert by["2025-01"]["backfill"] is True    # legacy majority, real volume
    assert by["2025-02"]["backfill"] is False
    assert out["headline"]["backfill_month_count"] == 1
    contracts.validate("adp_coverage.json", out)


def test_build_within_range_below_min_n_month_not_flagged():
    agg = _agg({"2025-01": 100, "2025-03": 20},
               months_legacy={"2025-01": 10, "2025-03": 20},
               published=500, cisa=120)
    out = build_adp_coverage(agg, GENERATED_AT, min_n=50)
    by = {m["month"]: m for m in out["months"]}
    # 2025-03 is all-legacy but below min_n=50 -> not a sweep (one stray old
    # stamp in a quiet month is not a bulk pass).
    assert by["2025-03"]["enriched"] == 20 and by["2025-03"]["backfill"] is False
    assert [m["month"] for m in out["months"]] == [
        "2025-01", "2025-02", "2025-03"]


def test_build_empty_series_when_no_month_clears_min_n():
    agg = _agg({"2025-01": 5}, months_legacy={"2025-01": 5},
               published=10, cisa=5)
    out = build_adp_coverage(agg, GENERATED_AT, min_n=50)
    assert out["months"] == []
    contracts.validate("adp_coverage.json", out)


def test_build_adds_shares_provider_board_and_headline():
    agg = _agg({"2024-06": 50, "2024-07": 150},
               adds={"ssvc": 190, "cvss": 60, "cwe": 100},
               providers={"CISA-ADP": 200, "redhat-SADP": 40},
               published=1000, cisa=200)
    out = build_adp_coverage(agg, GENERATED_AT, min_n=10)
    assert out["adds"]["total"] == 200
    assert out["adds"]["pct_ssvc"] == 95.0 and out["adds"]["pct_cvss"] == 30.0
    assert out["providers"][0] == {"provider": "CISA-ADP", "n": 200,
                                   "pct": 20.0}
    assert out["providers"][1]["provider"] == "redhat-SADP"
    h = out["headline"]
    assert h["total_published"] == 1000 and h["total_cisa"] == 200
    assert h["pct_cisa"] == 20.0
    assert h["first_month"] == "2024-06" and h["last_month"] == "2024-07"
    assert h["peak_month"] == "2024-07" and h["peak_enriched"] == 150
    assert h["sole_enricher"] == "CISA-ADP"
    contracts.validate("adp_coverage.json", out)


def test_build_peak_ties_keep_earliest_month():
    agg = _agg({"2024-06": 100, "2024-07": 100}, published=500, cisa=200)
    out = build_adp_coverage(agg, GENERATED_AT, min_n=10)
    assert out["headline"]["peak_month"] == "2024-06"


def test_build_empty_when_no_cisa_adp():
    agg = _agg({}, published=500, cisa=0)
    out = build_adp_coverage(agg, GENERATED_AT, min_n=50)
    assert out["months"] == []
    assert out["adds"] == {"total": 0, "ssvc": 0, "pct_ssvc": 0.0,
                           "cvss": 0, "pct_cvss": 0.0, "cwe": 0,
                           "pct_cwe": 0.0}
    assert out["providers"] == []
    h = out["headline"]
    assert h["total_cisa"] == 0 and h["pct_cisa"] == 0.0
    assert h["first_month"] is None and h["last_month"] is None
    assert h["peak_month"] is None and h["sole_enricher"] is None
    assert h["backfill_month_count"] == 0
    contracts.validate("adp_coverage.json", out)


# ---------------------------------------------------------------------- e2e

def test_offline_pipeline_run_emits_valid_adp_coverage(tmp_path):
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    obj = json.loads((tmp_path / "adp_coverage.json").read_text("utf-8"))
    contracts.validate("adp_coverage.json", obj)
    # The fixture corpus carries exactly one CISA-ADP record (CVE-2025-0001),
    # enriched 2025-03 with SSVC + CVSS + CWE, same-year so not a back-fill.
    assert obj["months"] == [{"month": "2025-03", "enriched": 1, "ssvc": 1,
                              "cvss": 1, "cwe": 1, "legacy": 0,
                              "backfill": False}]
    assert obj["adds"]["total"] == 1 and obj["adds"]["pct_ssvc"] == 100.0
    assert obj["providers"] == [{"provider": "CISA-ADP", "n": 1, "pct": 10.0}]
    h = obj["headline"]
    assert h["total_published"] == 10 and h["total_cisa"] == 1
    assert h["pct_cisa"] == 10.0 and h["sole_enricher"] == "CISA-ADP"
    assert h["peak_month"] == "2025-03" and h["backfill_month_count"] == 0

    meta = json.loads((tmp_path / "meta.json").read_text("utf-8"))
    contracts.validate("meta.json", meta)
    assert meta["sources"]["adp"] == {"fetched_at": meta["generated_at"],
                                      "cisa_records": 1}
