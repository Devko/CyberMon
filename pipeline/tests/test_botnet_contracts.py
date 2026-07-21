"""botnet_contracts tests: the valid shape passes through the core dispatch;
each deviation that would break the site — or cross the aggregates-only red
line — fails loudly."""
from __future__ import annotations

import copy

import pytest

# contracts must load before botnet_contracts: the coordinator registers
# module contracts from its own module bottom, so importing the contract file
# first would hit the registration mid-initialization.
from pipeline import contracts
from pipeline import botnet_contracts  # noqa: E402  (see above)
from pipeline.contracts import ContractViolation


def valid_obj() -> dict:
    return {
        "generated_at": "2026-07-21T00:00:00Z",
        "c2_weather": {
            "first_observed": "2026-07-20",
            "families": ["Emotet", "QakBot"],
            "series": [
                {"date": "2026-07-20",
                 "online": {"Emotet": 1, "QakBot": 2},
                 "listed": {"Emotet": 2, "QakBot": 3},
                 "online_total": 3, "listed_total": 5},
                {"date": "2026-07-21",
                 "online": {"QakBot": 1},
                 "listed": {"QakBot": 3},
                 "online_total": 1, "listed_total": 3},
            ],
            "current_online": 1,
            "current_listed": 3,
        },
        "c2_today": {
            "snapshot_date": "2026-07-21",
            "listed_total": 3,
            "online_total": 1,
            "families": [{"label": "QakBot", "listed": 3, "online": 1}],
            "countries": [{"label": "US", "n": 2}, {"label": "GB", "n": 1}],
            "asns": [{"label": "CLOUD-A", "n": 2},
                     {"label": "EXAMPLE-BACKBONE", "n": 1}],
        },
        "c2_age": {
            "snapshot_date": "2026-07-21",
            "n": 3,
            "median_age_days": 120,
            "oldest_age_days": 500,
            "buckets": [
                {"label": "under 30 days", "n": 0},
                {"label": "30–90 days", "n": 1},
                {"label": "90 days – 1 year", "n": 1},
                {"label": "1–2 years", "n": 1},
                {"label": "over 2 years", "n": 0},
            ],
        },
        "catalog": {
            "snapshot_size": 3,
            "online_now": 1,
            "families": ["QakBot"],
            "family_count": 1,
            "first_date": "2026-07-20",
            "last_date": "2026-07-21",
            "days_observed": 2,
        },
    }


def test_valid_object_passes_and_is_registered_in_core_dispatch():
    contracts.validate("botnet_weather.json", valid_obj())


def test_honest_empty_snapshot_is_legal():
    obj = valid_obj()
    obj["c2_weather"]["series"].append(
        {"date": "2026-07-22", "online": {}, "listed": {},
         "online_total": 0, "listed_total": 0})
    obj["c2_weather"]["current_online"] = 0
    obj["c2_weather"]["current_listed"] = 0
    obj["c2_today"] = {"snapshot_date": "2026-07-22", "listed_total": 0,
                       "online_total": 0, "families": [], "countries": [],
                       "asns": []}
    obj["c2_age"] = {"snapshot_date": "2026-07-22", "n": 0,
                     "median_age_days": None, "oldest_age_days": None,
                     "buckets": [{"label": l, "n": 0}
                                 for l in ("under 30 days", "30–90 days",
                                           "90 days – 1 year", "1–2 years",
                                           "over 2 years")]}
    obj["catalog"].update(snapshot_size=0, online_now=0, families=[],
                          family_count=0, last_date="2026-07-22",
                          days_observed=3)
    botnet_contracts.validate("botnet_weather.json", obj)


@pytest.mark.parametrize("mutate, match", [
    (lambda o: o["c2_weather"].update(series=[]), "tonight"),
    (lambda o: o["c2_weather"]["series"].reverse(), "not sorted"),
    (lambda o: o["c2_weather"]["series"].append(
        dict(o["c2_weather"]["series"][-1])), "duplicate"),
    (lambda o: o["c2_weather"]["series"][0]["online"].update(Emotet=9),
     "online_total|exceeds listed"),
    (lambda o: o["c2_weather"]["series"][1].update(listed_total=9),
     "listed_total"),
    (lambda o: o["c2_weather"]["series"][1]["online"].pop("QakBot"),
     "same families|online_total"),
    (lambda o: o["c2_weather"]["series"][1]["listed"].update(Zeus=1),
     "missing from"),
    (lambda o: o["c2_weather"].update(families=["QakBot", "Emotet"]),
     "not sorted"),
    (lambda o: o["c2_weather"].update(families=["Emotet", "QakBot",
                                                "_total"]), "sentinel"),
    (lambda o: o["c2_weather"].update(current_listed=9), "current_listed"),
    (lambda o: o["c2_weather"].update(first_observed="2026-07-19"),
     "first_observed"),
    (lambda o: o["c2_today"].update(snapshot_date="2026-07-20"),
     "snapshot_date"),
    (lambda o: o["c2_today"].update(online_total=9), "online_total|exceeds"),
    (lambda o: o["c2_today"]["families"][0].update(online=9), "exceeds"),
    (lambda o: o["c2_today"]["families"].append(
        {"label": "Emotet", "listed": 1, "online": 0}), "sum to"),
    (lambda o: o["c2_today"]["countries"].reverse(), "not sorted"),
    (lambda o: o["c2_today"]["countries"][0].update(n=3), "partition"),
    (lambda o: o["c2_today"]["asns"].pop(), "partition"),
    (lambda o: o["c2_age"].update(n=9), "listed_total"),
    (lambda o: o["c2_age"].update(median_age_days=None), "null exactly"),
    (lambda o: o["c2_age"].update(median_age_days=900), "median"),
    (lambda o: o["c2_age"]["buckets"][0].update(label="fresh"), "fixed"),
    (lambda o: o["c2_age"]["buckets"][1].update(n=5), "sum to"),
    (lambda o: o["catalog"].update(snapshot_size=9), "snapshot_size"),
    (lambda o: o["catalog"].update(families=["Emotet"]), "tonight's"),
    (lambda o: o["catalog"].update(family_count=5), "family_count"),
    (lambda o: o["catalog"].update(days_observed=9), "days_observed"),
])
def test_violations_fail_loudly(mutate, match):
    obj = copy.deepcopy(valid_obj())
    mutate(obj)
    with pytest.raises(ContractViolation, match=match):
        botnet_contracts.validate("botnet_weather.json", obj)


# ----------------------------------------------------- the aggregates red line

@pytest.mark.parametrize("mutate", [
    # a per-server field name anywhere in the object
    lambda o: o["c2_today"].update(ip_address="203.0.113.7"),
    lambda o: o["catalog"].update(hostname="c2.example.net"),
    # a label that smuggles an address out as a string
    lambda o: o["c2_today"]["asns"].__setitem__(
        0, {"label": "203.0.113.7", "n": 2}),
])
def test_no_per_server_data_ever_leaves_the_pipeline(mutate):
    obj = copy.deepcopy(valid_obj())
    mutate(obj)
    with pytest.raises(ContractViolation,
                       match="aggregates only|weather, not the blocklist"):
        botnet_contracts.validate("botnet_weather.json", obj)


# --------------------------------------------------------- meta.sources.feodo

def _meta_with_feodo(feodo: dict) -> dict:
    return {
        "generated_at": "2026-07-21T00:00:00Z",
        "sample": False,
        "sources": {
            "cvelist": {"release": "fixtures", "cve_count": 11},
            "epss": {"model_version": "v4", "score_date": "2026-07-08",
                     "row_count": 7},
            "kev": {"catalog_version": "2026.07.08", "count": 3},
            "feodo": feodo,
        },
    }


def test_meta_accepts_feodo_source_block_including_zero_listed():
    contracts.validate("meta.json", _meta_with_feodo(
        {"fetched_at": "2026-07-21T00:00:00Z", "listed": 5, "online": 1}))
    # zero listed is a valid reading for this source (post-takedown state)
    contracts.validate("meta.json", _meta_with_feodo(
        {"fetched_at": "2026-07-21T00:00:00Z", "listed": 0, "online": 0}))


def test_meta_feodo_block_is_optional_but_checked_when_present():
    meta = _meta_with_feodo({"fetched_at": "2026-07-21T00:00:00Z",
                             "listed": 5, "online": 1})
    del meta["sources"]["feodo"]
    contracts.validate("meta.json", meta)  # optional: absent is fine
    with pytest.raises(ContractViolation, match="online"):
        contracts.validate("meta.json", _meta_with_feodo(
            {"fetched_at": "2026-07-21T00:00:00Z", "listed": 1,
             "online": 2}))
    with pytest.raises(ContractViolation, match="listed"):
        contracts.validate("meta.json", _meta_with_feodo(
            {"fetched_at": "2026-07-21T00:00:00Z", "listed": "few",
             "online": 0}))
