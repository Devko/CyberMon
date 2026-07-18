"""top25_contracts tests: the valid shape passes through the core dispatch;
each deviation that would break the site fails loudly."""
from __future__ import annotations

import copy

import pytest

# contracts must load before top25_contracts: the coordinator registers
# module contracts from its own module bottom, so importing a module-
# contract file first would hit the registration mid-initialization.
from pipeline import contracts
from pipeline import top25_contracts  # noqa: E402  (see above)
from pipeline.contracts import ContractViolation


def valid_obj() -> dict:
    return {
        "generated_at": "2026-07-09T00:00:00Z",
        "official_year": 2024,
        "official_years": [2023, 2024],
        "window": {"start": 2021, "end": 2025},
        "window_years": 5,
        "min_n": 2000,
        "measured_total": 100000,
        "kev_total": 500,
        "ranks": [
            {"cwe": "CWE-79", "name": "Cross-site scripting",
             "official_rank": 1, "measured_rank": 1, "measured_n": 5000,
             "measured_share": 5.0, "kev_n": 100},
            {"cwe": "CWE-787", "name": "Out-of-bounds write",
             "official_rank": 2, "measured_rank": 3, "measured_n": 4000,
             "measured_share": 4.0, "kev_n": 80},
            {"cwe": "CWE-89", "name": "SQL injection",
             "official_rank": 3, "measured_rank": None, "measured_n": 0,
             "measured_share": 0.0, "kev_n": 0},
        ],
        "headline": {
            "official_year": 2024, "window_start": 2021, "window_end": 2025,
            "official_top_cwe": "CWE-79", "measured_top_cwe": "CWE-79",
            "in_measured_top25": 2, "outside_measured_top25": 1,
            "in_kev": 2, "kev_coverage_pct": 36.0,
        },
    }


def test_valid_object_passes_and_is_registered_in_core_dispatch():
    contracts.validate("cwe_top25.json", valid_obj())


def test_below_min_n_requires_null_headline():
    obj = valid_obj()
    obj["measured_total"] = 10          # below min_n
    obj["headline"] = None
    contracts.validate("cwe_top25.json", obj)   # null headline is fine
    obj["headline"] = valid_obj()["headline"]
    with pytest.raises(ContractViolation, match="headline"):
        contracts.validate("cwe_top25.json", obj)


def test_at_min_n_requires_headline():
    obj = valid_obj()
    obj["headline"] = None
    with pytest.raises(ContractViolation, match="headline"):
        contracts.validate("cwe_top25.json", obj)


@pytest.mark.parametrize("mutate, match", [
    # measured_rank must be null exactly when measured_n is 0
    (lambda o: o["ranks"][0].update(measured_n=0), "measured_rank"),
    (lambda o: o["ranks"][2].update(measured_rank=5), "measured_rank"),
    (lambda o: o["ranks"].reverse(), "not sorted"),            # official_rank order
    (lambda o: o["ranks"][2].update(official_rank=9), "contiguous"),
    (lambda o: o["ranks"][0].pop("cwe"), "cwe"),
    (lambda o: o["ranks"][1].update(cwe="CWE-79"), "duplicate"),
    (lambda o: o["ranks"][0].update(measured_share=5.55), "measured_share"),
    (lambda o: o["ranks"][0].update(cwe="79"), "cwe"),         # id format
    (lambda o: o.update(official_year=2023), "official_year"),  # not the newest
    (lambda o: o.update(official_year=2099), "official_year"),  # not committed
    (lambda o: o["window"].update(start=2025, end=2021), "window"),
    (lambda o: o.pop("ranks"), "ranks"),
    (lambda o: o["headline"].update(in_measured_top25=9), "in_measured_top25"),
    (lambda o: o["headline"].update(official_top_cwe="CWE-787"),
     "official_top_cwe"),
    (lambda o: o["headline"].update(official_year=2023), "official_year"),
    (lambda o: o["headline"].update(kev_coverage_pct=150.0),
     "kev_coverage_pct"),
])
def test_violations_fail_loudly(mutate, match):
    obj = copy.deepcopy(valid_obj())
    mutate(obj)
    with pytest.raises(ContractViolation, match=match):
        top25_contracts.validate("cwe_top25.json", obj)


# -------------------------------------------------------- meta.sources.top25

def _meta_with_top25(top25: dict) -> dict:
    return {
        "generated_at": "2026-07-09T00:00:00Z",
        "sample": False,
        "sources": {
            "cvelist": {"release": "fixtures", "cve_count": 11},
            "epss": {"model_version": "v4", "score_date": "2026-07-08",
                     "row_count": 7},
            "kev": {"catalog_version": "2026.07.08", "count": 3},
            "top25": top25,
        },
    }


def test_meta_accepts_top25_source_block():
    contracts.validate("meta.json", _meta_with_top25(
        {"fetched_at": "2026-07-09T00:00:00Z", "official_year": 2024,
         "list_count": 2}))


def test_meta_top25_block_is_optional_but_checked_when_present():
    meta = _meta_with_top25({"fetched_at": "2026-07-09T00:00:00Z",
                             "official_year": 2024, "list_count": 2})
    del meta["sources"]["top25"]
    contracts.validate("meta.json", meta)  # optional: absent is fine
    with pytest.raises(ContractViolation, match="official_year"):
        contracts.validate("meta.json", _meta_with_top25(
            {"fetched_at": "2026-07-09T00:00:00Z", "official_year": "twenty",
             "list_count": 2}))
    with pytest.raises(ContractViolation, match="list_count"):
        contracts.validate("meta.json", _meta_with_top25(
            {"fetched_at": "2026-07-09T00:00:00Z", "official_year": 2024,
             "list_count": 0}))
