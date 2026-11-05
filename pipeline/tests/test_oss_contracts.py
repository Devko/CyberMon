"""oss_contracts: the fixture edition passes through the core dispatch; each
deviation that would mislead a reader — a pooled or reordered registry, a
broken partition, an over-age observation, or a package, account or
repository name in the output — fails loudly."""
from __future__ import annotations

import copy

import pytest

# contracts first: it registers module contracts from its own bottom.
from pipeline import contracts
from pipeline import oss_metrics  # noqa: E402
from pipeline.contracts import ContractViolation

from .test_oss_metrics import GEN, full_state


def valid_obj() -> dict:
    u, state, _ = full_state()
    return oss_metrics.build_oss_maintainers(u, state, GEN)


def test_valid_passes():
    contracts.validate("oss_maintainers.json", valid_obj())


def test_stale_carried_edition_may_lag_its_stamp():
    obj = valid_obj()
    obj["generated_at"] = "2026-12-01T03:00:00Z"
    with pytest.raises(ContractViolation, match="publishing rule"):
        contracts.validate("oss_maintainers.json", obj)
    obj["stale"] = True
    contracts.validate("oss_maintainers.json", obj)


def _eco(obj, i=0):
    return obj["ecosystems"][i]


MUTATIONS = {
    "package name leaks": lambda o: _eco(o)["accounts"].update(
        top_package="left-pad"),
    "account name leaks": lambda o: o["universe"].update(note="alice"),
    "repository leaks": lambda o: _eco(o)["scorecard"].update(
        repo="git" + "hub.com/example/left-pad"),
    "registries reordered": lambda o: o["ecosystems"].reverse(),
    "registry pooled away": lambda o: o["ecosystems"].pop(),
    "buckets do not partition": lambda o: _eco(o)["accounts"]["buckets"][1]
    .update(n=99),
    "bucket label changed": lambda o: _eco(o)["accounts"]["buckets"][1]
    .update(label="one"),
    "pct disagrees with n": lambda o: _eco(o)["single_account"].update(
        pct=50.0),
    "single exceeds one-account bucket": lambda o: _eco(o)[
        "single_account"].update(n=3, pct=100.0),
    "reach shrinks with k": lambda o: _eco(o)["shared"]["top"][1].update(
        n=1, pct=33.3),
    "denominator changed": lambda o: _eco(o).update(packages=4),
    "scored above repos": lambda o: _eco(o)["scorecard"].update(scored=5),
    "check buckets do not sum": lambda o: _eco(o)["scorecard"]["checks"][
        "Maintained"][0].update(n=7),
    "median score without scores": lambda o: _eco(o, 1)["scorecard"].update(
        median_score=None),
    "observed after the edition": lambda o: o["observed"].update(
        last="2026-11-09"),
    "scorecard dates nulled": lambda o: o["scorecard_dates"].update(
        first=None),
    "old scorecard result scored": lambda o: o["scorecard_dates"].update(
        first="2026-08-01"),
    "sole account holds more than all": lambda o: _eco(o)[
        "single_account"].update(largest=3),
    "sole accounts without packages": lambda o: _eco(o, 2)[
        "single_account"].update(accounts=0),
    "old results exceed repos": lambda o: _eco(o)["scorecard"].update(
        old_results=2),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_mutation_fails(name):
    obj = copy.deepcopy(valid_obj())
    MUTATIONS[name](obj)
    with pytest.raises(ContractViolation):
        contracts.validate("oss_maintainers.json", obj)


def _meta(oss: dict) -> dict:
    return {
        "generated_at": GEN, "sample": False,
        "sources": {
            "cvelist": {"release": "r", "cve_count": 1},
            "epss": {"model_version": "v", "score_date": "2026-11-05",
                     "row_count": 1},
            "kev": {"catalog_version": "v", "count": 1},
            "oss": oss,
        },
    }


OSS_SOURCE = {"fetched_at": GEN, "edition": "2026-11", "packages": 1000,
              "lookups": 270, "failed": 0, "oldest_observation": "2026-10-30"}


def test_meta_source_block():
    contracts.validate("meta.json", _meta(dict(OSS_SOURCE)))
    contracts.validate("meta.json", _meta({**OSS_SOURCE, "stale": True}))
    for bad in ({**OSS_SOURCE, "failed": 300},
                {**OSS_SOURCE, "oldest_observation": "last week"},
                {k: v for k, v in OSS_SOURCE.items() if k != "lookups"}):
        with pytest.raises(ContractViolation):
            contracts.validate("meta.json", _meta(bad))
