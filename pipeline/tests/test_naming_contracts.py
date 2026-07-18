"""naming_contracts tests: the valid shape passes through the core dispatch;
each deviation that would break the site fails loudly."""
from __future__ import annotations

import copy

import pytest

# contracts must load before naming_contracts: the coordinator registers
# module contracts from its own module bottom, so importing a module-
# contract file first would hit the registration mid-initialization.
from pipeline import contracts
from pipeline import naming_contracts  # noqa: E402  (see above)
from pipeline.contracts import ContractViolation


def valid_obj() -> dict:
    return {
        "generated_at": "2026-07-09T00:00:00Z",
        "version": "19.1",
        "released": "2026-05-12",
        "groups": [
            {"name": "APT28", "alt_count": 3,
             "aliases": ["Fancy Bear", "Forest Blizzard", "Sofacy"]},
            {"name": "APT29", "alt_count": 2,
             "aliases": ["Cozy Bear", "Midnight Blizzard"]},
        ],
        "distribution": [
            {"alt_count": 0, "n": 5},
            {"alt_count": 1, "n": 0},
            {"alt_count": 2, "n": 1},
            {"alt_count": 3, "n": 1},
        ],
        "headline": {
            "total_groups": 7, "groups_with_aliases": 2,
            "total_alias_strings": 5, "distinct_alias_strings": 5,
            "most_renamed": "APT28", "most_renamed_alt_count": 3,
        },
    }


def test_valid_object_passes_and_is_registered_in_core_dispatch():
    contracts.validate("naming.json", valid_obj())


def test_empty_groups_requires_null_headline():
    naming_contracts.validate(
        "naming.json",
        {"generated_at": "2026-07-09T00:00:00Z", "version": "19.1",
         "released": "2026-05-12", "groups": [],
         "distribution": [{"alt_count": 0, "n": 4}], "headline": None})
    with pytest.raises(ContractViolation, match="headline"):
        naming_contracts.validate(
            "naming.json",
            {"generated_at": "2026-07-09T00:00:00Z", "version": "19.1",
             "released": "2026-05-12", "groups": [],
             "distribution": [{"alt_count": 0, "n": 4}],
             "headline": valid_obj()["headline"]})


def test_nonempty_groups_requires_headline():
    obj = valid_obj()
    obj["headline"] = None
    with pytest.raises(ContractViolation, match="headline"):
        naming_contracts.validate("naming.json", obj)


@pytest.mark.parametrize("mutate, match", [
    (lambda o: o["groups"][0].update(alt_count=2), "aliases"),      # len != count
    (lambda o: o["groups"][0].update(alt_count=0,
                                     aliases=[]), "alt_count"),     # board >= 1
    (lambda o: o["groups"].reverse(), "not sorted"),                # desc order
    (lambda o: o["groups"][0].pop("name"), "name"),
    (lambda o: o["distribution"].reverse(), "not sorted"),          # asc order
    (lambda o: o["distribution"].append({"alt_count": 3, "n": 1}), "duplicate"),
    (lambda o: o.update(version="nineteen"), "version"),
    (lambda o: o.update(released="12 May 2026"), "released"),
    (lambda o: o.pop("groups"), "groups"),
    (lambda o: o["headline"].update(most_renamed="APT29"), "most_renamed"),
    (lambda o: o["headline"].update(groups_with_aliases=9),
     "groups_with_aliases"),
    (lambda o: o["headline"].update(total_groups=99), "total_groups"),
])
def test_violations_fail_loudly(mutate, match):
    obj = copy.deepcopy(valid_obj())
    mutate(obj)
    with pytest.raises(ContractViolation, match=match):
        naming_contracts.validate("naming.json", obj)


# ------------------------------------------------------- meta.sources.naming

def _meta_with_naming(naming: dict) -> dict:
    return {
        "generated_at": "2026-07-09T00:00:00Z",
        "sample": False,
        "sources": {
            "cvelist": {"release": "fixtures", "cve_count": 11},
            "epss": {"model_version": "v4", "score_date": "2026-07-08",
                     "row_count": 7},
            "kev": {"catalog_version": "2026.07.08", "count": 3},
            "naming": naming,
        },
    }


def test_meta_accepts_naming_source_block():
    contracts.validate("meta.json", _meta_with_naming(
        {"fetched_at": "2026-07-09T00:00:00Z", "version": "19.1",
         "group_count": 174}))


def test_meta_naming_block_is_optional_but_checked_when_present():
    meta = _meta_with_naming({"fetched_at": "2026-07-09T00:00:00Z",
                              "version": "19.1", "group_count": 174})
    del meta["sources"]["naming"]
    contracts.validate("meta.json", meta)  # optional: absent is fine
    with pytest.raises(ContractViolation, match="version"):
        contracts.validate("meta.json", _meta_with_naming(
            {"fetched_at": "2026-07-09T00:00:00Z", "version": "",
             "group_count": 174}))
    with pytest.raises(ContractViolation, match="group_count"):
        contracts.validate("meta.json", _meta_with_naming(
            {"fetched_at": "2026-07-09T00:00:00Z", "version": "19.1",
             "group_count": "many"}))
