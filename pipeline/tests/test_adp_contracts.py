"""adp_contracts tests: the valid shape passes through the core dispatch;
each deviation that would break the site fails loudly."""
from __future__ import annotations

import copy

import pytest

# contracts must load before adp_contracts: the coordinator registers module
# contracts from its own module bottom, so importing a module-contract file
# first would hit the registration mid-initialization.
from pipeline import contracts
from pipeline import adp_contracts  # noqa: E402  (see above)
from pipeline.contracts import ContractViolation


def valid_obj() -> dict:
    return {
        "generated_at": "2026-07-09T00:00:00Z",
        "min_n": 50,
        "months": [
            {"month": "2024-05", "enriched": 800, "ssvc": 790, "cvss": 120,
             "cwe": 300, "legacy": 40, "backfill": False},
            {"month": "2024-06", "enriched": 1200, "ssvc": 1190, "cvss": 200,
             "cwe": 700, "legacy": 900, "backfill": True},
        ],
        "adds": {"total": 2000, "ssvc": 1980, "pct_ssvc": 99.0,
                 "cvss": 320, "pct_cvss": 16.0, "cwe": 1000, "pct_cwe": 50.0},
        "providers": [
            {"provider": "CISA-ADP", "n": 2000, "pct": 40.0},
            {"provider": "CVE Program Container", "n": 300, "pct": 6.0},
        ],
        "headline": {
            "total_published": 5000, "total_cisa": 2000, "pct_cisa": 40.0,
            "first_month": "2024-05", "last_month": "2024-06",
            "peak_month": "2024-06", "peak_enriched": 1200,
            "sole_enricher": "CISA-ADP", "backfill_month_count": 1,
        },
    }


def test_valid_object_passes_and_is_registered_in_core_dispatch():
    contracts.validate("adp_coverage.json", valid_obj())


def test_empty_data_shape_passes():
    contracts.validate("adp_coverage.json", {
        "generated_at": "2026-07-09T00:00:00Z", "min_n": 50, "months": [],
        "adds": {"total": 0, "ssvc": 0, "pct_ssvc": 0.0, "cvss": 0,
                 "pct_cvss": 0.0, "cwe": 0, "pct_cwe": 0.0},
        "providers": [],
        "headline": {"total_published": 0, "total_cisa": 0, "pct_cisa": 0.0,
                     "first_month": None, "last_month": None,
                     "peak_month": None, "peak_enriched": 0,
                     "sole_enricher": None, "backfill_month_count": 0}})


@pytest.mark.parametrize("mutate, match", [
    (lambda o: o["months"][0].update(month="2024-13"), "month"),     # bad month
    (lambda o: o["months"][0].update(month="2024-5"), "month"),      # unpadded
    (lambda o: o["months"].reverse(), "not sorted"),                 # asc order
    (lambda o: o["months"][0].update(ssvc=9999), "ssvc"),            # ssvc>enriched
    (lambda o: o["months"][0].update(legacy=9999), "legacy"),        # legacy>enriched
    (lambda o: o["months"][0].update(backfill="yes"), "backfill"),   # not bool
    (lambda o: o["months"].append(copy.deepcopy(o["months"][1])),
     "duplicate"),                                                   # dup month
    (lambda o: o["adds"].update(ssvc=999999), "ssvc"),               # ssvc>total
    (lambda o: o["adds"].update(pct_ssvc=250.0), "pct_ssvc"),        # out of range
    (lambda o: o["adds"].update(total=1980), "total"),               # != total_cisa
    (lambda o: o["providers"].reverse(), "not sorted"),              # desc order
    (lambda o: o["providers"][0].pop("provider"), "provider"),
    (lambda o: o["headline"].update(total_cisa=99999), "total_cisa"),  # >published
    (lambda o: o["headline"].update(sole_enricher="Nope"), "sole_enricher"),
    (lambda o: o["headline"].update(first_month="May 2024"), "first_month"),
    (lambda o: o.pop("months"), "months"),
])
def test_violations_fail_loudly(mutate, match):
    obj = copy.deepcopy(valid_obj())
    mutate(obj)
    with pytest.raises(ContractViolation, match=match):
        adp_contracts.validate("adp_coverage.json", obj)


# ---------------------------------------------------------- meta.sources.adp

def _meta_with_adp(adp: dict) -> dict:
    return {
        "generated_at": "2026-07-09T00:00:00Z",
        "sample": False,
        "sources": {
            "cvelist": {"release": "fixtures", "cve_count": 11},
            "epss": {"model_version": "v4", "score_date": "2026-07-08",
                     "row_count": 7},
            "kev": {"catalog_version": "2026.07.08", "count": 3},
            "adp": adp,
        },
    }


def test_meta_accepts_adp_source_block():
    contracts.validate("meta.json", _meta_with_adp(
        {"fetched_at": "2026-07-09T00:00:00Z", "cisa_records": 42000}))


def test_meta_adp_block_optional_but_checked_when_present():
    meta = _meta_with_adp({"fetched_at": "2026-07-09T00:00:00Z",
                           "cisa_records": 42000})
    del meta["sources"]["adp"]
    contracts.validate("meta.json", meta)  # optional: absent is fine
    with pytest.raises(ContractViolation, match="cisa_records"):
        contracts.validate("meta.json", _meta_with_adp(
            {"fetched_at": "2026-07-09T00:00:00Z", "cisa_records": "lots"}))
    with pytest.raises(ContractViolation, match="fetched_at"):
        contracts.validate("meta.json", _meta_with_adp(
            {"fetched_at": "yesterday", "cisa_records": 1}))
