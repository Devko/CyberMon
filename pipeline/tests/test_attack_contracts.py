"""attack_contracts tests: the valid shape passes; each deviation that
would break the site (or the lossless state reconstruction) fails loudly."""
from __future__ import annotations

import copy

import pytest

# contracts must load before attack_contracts: the coordinator registers
# module contracts from its own module bottom, so importing a module-
# contract file first would hit the registration mid-initialization.
from pipeline import contracts
from pipeline import attack_contracts  # noqa: E402  (see above)
from pipeline.contracts import ContractViolation


def valid_obj() -> dict:
    return {
        "generated_at": "2026-07-09T00:00:00Z",
        "versions": [
            {"version": "1.0", "released": "2018-01-17",
             "techniques": 187, "subtechniques": 0, "groups": 68,
             "software": 328, "churn": None},
            {"version": "2.0", "released": "2018-10-17",
             "techniques": 219, "subtechniques": 0, "groups": 78,
             "software": 380,
             "churn": {"added": 32, "deprecated": 0, "revoked": 0}},
        ],
        "headline": {
            "latest_version": "2.0", "released_latest": "2018-10-17",
            "techniques_latest": 219, "subtechniques_latest": 0,
            "first_version": "1.0", "released_first": "2018-01-17",
            "techniques_first": 187, "subtechniques_first": 0,
        },
    }


def test_valid_object_passes_and_is_registered_in_core_dispatch():
    contracts.validate("attack_churn.json", valid_obj())


def test_stale_flag_is_tolerated_but_must_be_boolean():
    obj = valid_obj()
    obj["stale"] = True
    attack_contracts.validate("attack_churn.json", obj)
    obj["stale"] = "yes"
    with pytest.raises(ContractViolation, match="stale"):
        attack_contracts.validate("attack_churn.json", obj)


def test_empty_versions_requires_null_headline():
    attack_contracts.validate(
        "attack_churn.json",
        {"generated_at": "2026-07-09T00:00:00Z", "versions": [],
         "headline": None})
    with pytest.raises(ContractViolation, match="headline"):
        attack_contracts.validate(
            "attack_churn.json",
            {"generated_at": "2026-07-09T00:00:00Z", "versions": [],
             "headline": valid_obj()["headline"]})


def test_nonempty_versions_requires_headline():
    obj = valid_obj()
    obj["headline"] = None
    with pytest.raises(ContractViolation, match="headline"):
        attack_contracts.validate("attack_churn.json", obj)


@pytest.mark.parametrize("mutate, match", [
    (lambda o: o["versions"][0].pop("techniques"), "techniques"),
    (lambda o: o["versions"][0].update(subtechniques=-1), "subtechniques"),
    (lambda o: o["versions"][0].update(released="17 Jan 2018"), "released"),
    (lambda o: o["versions"][0].update(version="one-dot-oh"), "version"),
    (lambda o: o["versions"][1]["churn"].pop("revoked"), "revoked"),
    (lambda o: o["versions"][1]["churn"].update(added=-3), "added"),
    (lambda o: o["versions"][1].update(churn="lots"), "churn"),
    (lambda o: o["headline"].update(latest_version="9.9"), "latest_version"),
    (lambda o: o["headline"].update(first_version="9.9"), "first_version"),
    (lambda o: o["headline"].pop("techniques_latest"), "techniques_latest"),
    (lambda o: o.pop("versions"), "versions"),
])
def test_violations_fail_loudly(mutate, match):
    obj = copy.deepcopy(valid_obj())
    mutate(obj)
    with pytest.raises(ContractViolation, match=match):
        attack_contracts.validate("attack_churn.json", obj)


def test_versions_must_ascend_numerically_and_be_unique():
    obj = valid_obj()
    obj["versions"].reverse()  # 2.0 before 1.0
    obj["headline"]["latest_version"] = "1.0"
    obj["headline"]["first_version"] = "2.0"
    with pytest.raises(ContractViolation, match="not sorted"):
        attack_contracts.validate("attack_churn.json", obj)

    obj = valid_obj()
    obj["versions"][1] = dict(obj["versions"][0])
    obj["headline"]["latest_version"] = "1.0"
    obj["headline"]["first_version"] = "1.0"
    with pytest.raises(ContractViolation, match="duplicate"):
        attack_contracts.validate("attack_churn.json", obj)


def test_release_dates_must_never_go_backwards():
    obj = valid_obj()
    obj["versions"][1]["released"] = "2017-12-31"
    obj["headline"]["released_latest"] = "2017-12-31"
    with pytest.raises(ContractViolation, match="release date"):
        attack_contracts.validate("attack_churn.json", obj)


# ------------------------------------------------------- meta.sources.attack

def _meta_with_attack(attack: dict) -> dict:
    return {
        "generated_at": "2026-07-09T00:00:00Z",
        "sample": False,
        "sources": {
            "cvelist": {"release": "fixtures", "cve_count": 11},
            "epss": {"model_version": "v4", "score_date": "2026-07-08",
                     "row_count": 7},
            "kev": {"catalog_version": "2026.07.08", "count": 3},
            "attack": attack,
        },
    }


def test_meta_accepts_attack_source_block():
    contracts.validate("meta.json", _meta_with_attack(
        {"fetched_at": "2026-07-09T00:00:00Z", "latest_version": "19.1",
         "version_count": 40}))


def test_meta_attack_block_is_optional_but_checked_when_present():
    meta = _meta_with_attack({"fetched_at": "2026-07-09T00:00:00Z",
                              "latest_version": "19.1", "version_count": 40})
    del meta["sources"]["attack"]
    contracts.validate("meta.json", meta)  # optional: absent is fine
    with pytest.raises(ContractViolation, match="version_count"):
        contracts.validate("meta.json", _meta_with_attack(
            {"fetched_at": "2026-07-09T00:00:00Z", "latest_version": "19.1",
             "version_count": 0}))
    with pytest.raises(ContractViolation, match="latest_version"):
        contracts.validate("meta.json", _meta_with_attack(
            {"fetched_at": "2026-07-09T00:00:00Z", "latest_version": "",
             "version_count": 40}))
