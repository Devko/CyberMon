"""Contract for sigma_coverage.json and meta.sources.sigma: the fixture
edition validates, and each class of breakage is refused loudly."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from pipeline import contracts, sigma_metrics
from pipeline.contracts import ContractViolation

CHURN = {"versions": [{"version": "1.0", "released": "2018-01-17"},
                      {"version": "2.0", "released": "2018-10-17"}]}


@pytest.fixture(scope="module")
def edition() -> dict:
    obj, _src = sigma_metrics.run_stage(
        Path("."), Path("."), "2026-11-05T06:00:00Z", attack_churn=CHURN,
        offline_fixtures=True, log=lambda m: None)
    return obj


def _broken(edition: dict, mutate) -> dict:
    obj = copy.deepcopy(edition)
    mutate(obj)
    return obj


def test_fixture_edition_validates(edition):
    contracts.validate("sigma_coverage.json", edition)
    contracts.validate("sigma_coverage.json", {**edition, "stale": True})


def test_carried_edition_stays_valid_across_a_year_boundary(edition):
    # __main__._carry_forward restamps generated_at; the partial flags are
    # measured to as_of, so a December edition carried into January must
    # not abort the run the degrade path exists to save.
    carried = {**edition, "generated_at": "2027-01-03T06:00:00Z",
               "stale": True}
    contracts.validate("sigma_coverage.json", carried)
    with pytest.raises(ContractViolation, match="as_of"):
        contracts.validate("sigma_coverage.json",
                           {**edition, "as_of": "2027-01-01"})


@pytest.mark.parametrize("name,mutate,match", [
    ("rule id leaks", lambda o: o["techniques"][0].update(
        name="00000000-0000-4000-8000-000000000001"), "Sigma rule id"),
    ("rule title leaks", lambda o: o["catalog"].update(title="x"),
     "rule content"),
    ("pct off", lambda o: o["coverage"].update(pct=81.0), "pct"),
    ("pct unrounded", lambda o: o["quarters"][-1].update(pct=80.04),
     "1 decimal"),
    ("quarter gap", lambda o: o["quarters"].pop(3), "gap"),
    ("added mismatch", lambda o: o["quarters"][0].update(added=99),
     "added sums"),
    ("catalog split", lambda o: o["catalog"].update(active=1),
     "active \\+ deprecated"),
    ("covered mismatch", lambda o: o["techniques"][0].update(rules=0),
     "coverage.covered"),
    ("lag buckets", lambda o: o["lag"].update(none=3), "sum to n"),
    ("lag median both", lambda o: o["lag"].update(median_at_least_days=1),
     "must be null when exact"),
    ("cohort sum", lambda o: o["cohorts"][0].update(later=5),
     "do not sum"),
    ("unknown debut", lambda o: o["techniques"][0].update(debut="9.9"),
     "not a synced release"),
    ("retired before debut", lambda o: o["retired_techniques"][0].update(
        debut="2.0", retired="1.0"), "retired no later"),
    ("bad commit", lambda o: o["source"].update(commit="HEAD"), "commit"),
    ("partial mid-series", lambda o: o["quarters"][0].update(partial=True),
     "partial"),
    ("peak not max", lambda o: o["coverage"]["peak"].update(pct=10.0),
     "maximum"),
    ("tactic unknown", lambda o: o["tactics"][0].update(id="nope"),
     "unknown or repeated"),
])
def test_breakage_is_refused(edition, name, mutate, match):
    with pytest.raises(ContractViolation, match=match):
        contracts.validate("sigma_coverage.json", _broken(edition, mutate))


def _meta(sigma_block: dict) -> dict:
    return {"generated_at": "2026-11-05T06:00:00Z", "sample": False,
            "sources": {"cvelist": {"release": "r", "cve_count": 1},
                        "epss": {"model_version": "v", "score_date":
                                 "2026-11-05", "row_count": 1},
                        "kev": {"catalog_version": "v", "count": 1},
                        "sigma": sigma_block}}


GOOD_SOURCE = {"fetched_at": "2026-11-05T06:00:00Z", "commit": "a" * 40,
               "commit_date": "2026-11-05", "rules": 3980,
               "attack_version": "20.0"}


def test_meta_source_block():
    contracts.validate("meta.json", _meta(GOOD_SOURCE))
    contracts.validate("meta.json", _meta({**GOOD_SOURCE, "stale": True}))
    for bad in ({**GOOD_SOURCE, "commit": "abc"},
                {**GOOD_SOURCE, "rules": 0},
                {k: v for k, v in GOOD_SOURCE.items() if k != "fetched_at"}):
        with pytest.raises(ContractViolation):
            contracts.validate("meta.json", _meta(bad))
