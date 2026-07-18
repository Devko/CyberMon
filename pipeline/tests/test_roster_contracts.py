"""roster_contracts tests: the valid shape passes through the core dispatch;
each deviation that would break the site fails loudly."""
from __future__ import annotations

import copy

import pytest

# contracts must load before roster_contracts: the coordinator registers
# module contracts from its own module bottom, so importing the contract file
# first would hit the registration mid-initialization.
from pipeline import contracts
from pipeline import roster_contracts  # noqa: E402  (see above)
from pipeline.contracts import ContractViolation


def valid_obj() -> dict:
    return {
        "generated_at": "2026-07-09T00:00:00Z",
        "roster_size": {
            "min_n": 2, "current": 3, "net_change": 1,
            "first_observed": "2026-07-01",
            "series": [{"date": "2026-07-01", "size": 2},
                       {"date": "2026-07-08", "size": 3}],
        },
        "roster_flux": {
            "months": [{"month": "2026-07", "onboarded": 1, "departed": 0,
                        "scope_changed": 1}],
            "totals": {"onboarded": 1, "departed": 0, "scope_changed": 1},
            "events_total": 2, "first_observed": "2026-07-08",
        },
        "roster_mix": {
            "total": 3,
            "by_type": [{"label": "Vendor", "n": 2},
                        {"label": "Open Source", "n": 1}],
            "by_tlr": [{"label": "mitre", "n": 2}, {"label": "CISA", "n": 1}],
            "by_root": [{"label": "n/a", "n": 2}, {"label": "icscert", "n": 1}],
            "by_country": [{"label": "USA", "n": 2},
                           {"label": "Germany", "n": 1}],
        },
        "headline": {
            "roster_total": 3, "top_type": "Vendor", "top_type_n": 2,
            "country_count": 2, "root_count": 1, "mitre_n": 2, "cisa_n": 1,
        },
    }


def test_valid_object_passes_and_is_registered_in_core_dispatch():
    contracts.validate("cna_roster.json", valid_obj())


def test_empty_series_requires_null_size_scalars():
    obj = valid_obj()
    obj["roster_size"] = {"min_n": 2, "current": 0, "net_change": None,
                          "first_observed": None, "series": []}
    roster_contracts.validate("cna_roster.json", obj)  # honest empty is legal


@pytest.mark.parametrize("mutate, match", [
    (lambda o: o["roster_mix"]["by_type"].reverse(), "not sorted"),
    (lambda o: o["roster_mix"]["by_country"][0].update(n=1), "partition"),
    (lambda o: o["roster_mix"]["by_country"].append({"label": "X", "n": 9}),
     "exceeds roster total"),
    (lambda o: o["roster_mix"]["by_tlr"][0].update(n=0), "n"),   # below min 1
    (lambda o: o["roster_size"].update(net_change=99), "net_change"),
    (lambda o: (o["roster_size"].update(
        series=[{"date": "2026-07-01", "size": 2}], current=2)),
     "net_change"),  # 1 point < min_n but net_change still set -> gate
    (lambda o: o["roster_size"]["series"].append(
        {"date": "2026-07-08", "size": 3}), "duplicate"),
    (lambda o: o["roster_flux"].update(events_total=9), "events_total"),
    (lambda o: o["roster_flux"]["months"].append(
        {"month": "2026-07", "onboarded": 0, "departed": 0,
         "scope_changed": 0}), "duplicate"),
    (lambda o: o["roster_flux"].update(first_observed=None),
     "first_observed"),  # non-empty log needs a date
    (lambda o: o["roster_flux"]["totals"].pop("departed"), "totals"),
    (lambda o: o["headline"].update(top_type="Open Source"), "top_type"),
    (lambda o: o["headline"].update(country_count=9), "country_count"),
    (lambda o: o["headline"].update(roster_total=9), "roster_total"),
    (lambda o: o["roster_mix"].update(total=0), "total"),   # below min 1
])
def test_violations_fail_loudly(mutate, match):
    obj = copy.deepcopy(valid_obj())
    mutate(obj)
    with pytest.raises(ContractViolation, match=match):
        roster_contracts.validate("cna_roster.json", obj)


# --------------------------------------------------------- meta.sources.roster

def _meta_with_roster(roster: dict) -> dict:
    return {
        "generated_at": "2026-07-09T00:00:00Z",
        "sample": False,
        "sources": {
            "cvelist": {"release": "fixtures", "cve_count": 11},
            "epss": {"model_version": "v4", "score_date": "2026-07-08",
                     "row_count": 7},
            "kev": {"catalog_version": "2026.07.08", "count": 3},
            "roster": roster,
        },
    }


def test_meta_accepts_roster_source_block():
    contracts.validate("meta.json", _meta_with_roster(
        {"fetched_at": "2026-07-09T00:00:00Z", "org_count": 530,
         "events_total": 0}))


def test_meta_roster_block_is_optional_but_checked_when_present():
    meta = _meta_with_roster({"fetched_at": "2026-07-09T00:00:00Z",
                              "org_count": 530, "events_total": 0})
    del meta["sources"]["roster"]
    contracts.validate("meta.json", meta)  # optional: absent is fine
    with pytest.raises(ContractViolation, match="org_count"):
        contracts.validate("meta.json", _meta_with_roster(
            {"fetched_at": "2026-07-09T00:00:00Z", "org_count": 0,
             "events_total": 0}))
    with pytest.raises(ContractViolation, match="events_total"):
        contracts.validate("meta.json", _meta_with_roster(
            {"fetched_at": "2026-07-09T00:00:00Z", "org_count": 530,
             "events_total": "lots"}))
