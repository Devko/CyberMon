"""Detection Rules: the ATT&CK technique timeline (attack_techniques) and
the sigma_coverage.json builder (sigma_metrics), on hand-built inputs."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import attack_techniques as at
from pipeline import contracts, sigma_metrics
from pipeline.fetch_sigma import ACTIVE, DEPRECATED, Rule, RuleSet

FIXTURES = Path(__file__).parent / "fixtures" / "sigma"
GEN = "2026-11-05T06:00:00Z"


def _bundle(version: str) -> dict:
    return json.loads((FIXTURES / "attack" / f"enterprise-attack-{version}.json")
                      .read_text(encoding="utf-8"))


def _ap(ext: str, *, sub=False, revoked=False, deprecated=False,
        tactic="execution", stix=None):
    return {"type": "attack-pattern", "id": stix or f"attack-pattern--{ext}",
            "name": f"Name {ext}", "x_mitre_is_subtechnique": sub,
            "revoked": revoked, "x_mitre_deprecated": deprecated,
            "external_references": [{"source_name": "mitre-attack",
                                     "external_id": ext}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack",
                                   "phase_name": tactic}]}


# ------------------------------------------------------------ timeline

def test_read_bundle_keeps_active_parent_techniques_and_revocations():
    info = at.read_bundle(_bundle("2.0"))
    assert info["active"] == {"T1001", "T1003", "T1059", "T1200", "T1595"}
    assert info["revoked_to"] == {"T1086": "T1059.001"}
    assert info["tactic_order"][:2] == ["reconnaissance", "initial-access"]
    assert info["tactic_names"]["command-and-control"] == "Command and Control"
    assert info["tactics"]["T1595"] == ["reconnaissance"]


def test_resolve_follows_revocations_then_rolls_up():
    revoked = {"T1562.001": "T1685", "T1562": "T1685",
               "T1086": "T1059.001", "T1": "T2", "T2": "T1"}
    assert at.resolve("T1562.001", revoked) == "T1685"
    assert at.resolve("T1562.005", revoked) == "T1685"   # via the parent
    assert at.resolve("T1086", revoked) == "T1059"
    assert at.resolve("T1059.003", revoked) == "T1059"
    assert at.resolve("T1", revoked) in {"T1", "T2"}       # cycle-safe


def test_sync_records_debut_and_retirement_once_per_release():
    reads = []

    def fetch(version):
        reads.append(version)
        return _bundle(version)

    state, n = at.sync(None, ["1.0", "2.0"], fetch, log=lambda m: None)
    assert n == 2 and reads == ["1.0", "2.0"]
    assert state["techniques"]["T1003"] == {"debut": "1.0", "retired": None}
    assert state["techniques"]["T1059"] == {"debut": "2.0", "retired": None}
    assert state["techniques"]["T1086"] == {"debut": "1.0", "retired": "2.0"}
    assert state["latest"]["version"] == "2.0"
    # A normal night: nothing new, no bundle read.
    reads.clear()
    again, n = at.sync(state, ["1.0", "2.0"], fetch, log=lambda m: None)
    assert n == 0 and reads == [] and again == state


def test_sync_reads_only_the_new_release_and_reactivates():
    bundles = {
        "1.0": {"objects": [_ap("T1001"), _ap("T1002")]},
        "2.0": {"objects": [_ap("T1001")]},
        "3.0": {"objects": [_ap("T1001"), _ap("T1002"), _ap("T1003")]},
    }
    state, _ = at.sync(None, ["1.0", "2.0"], bundles.__getitem__,
                       log=lambda m: None)
    assert state["techniques"]["T1002"]["retired"] == "2.0"
    reads = []

    def fetch(v):
        reads.append(v)
        return bundles[v]

    state, n = at.sync(state, ["1.0", "2.0", "3.0"], fetch, log=lambda m: None)
    assert reads == ["3.0"] and n == 1
    assert state["techniques"]["T1002"] == {"debut": "1.0", "retired": None}
    assert state["techniques"]["T1003"]["debut"] == "3.0"


def test_sync_rebuilds_when_the_release_list_changed_underneath():
    bundles = {"1.0": {"objects": [_ap("T1001")]},
               "1.1": {"objects": [_ap("T1001")]},
               "2.0": {"objects": [_ap("T1001"), _ap("T1002")]}}
    state, _ = at.sync(None, ["1.0", "2.0"], bundles.__getitem__,
                       log=lambda m: None)
    rebuilt, n = at.sync(state, ["1.0", "1.1", "2.0"], bundles.__getitem__,
                         log=lambda m: None)
    assert n == 3 and rebuilt["synced"] == ["1.0", "1.1", "2.0"]


def test_sync_caps_bundle_reads():
    versions = [f"{i}.0" for i in range(1, at.MAX_BUNDLES_PER_RUN + 2)]
    with pytest.raises(ValueError, match="cap"):
        at.sync(None, versions, lambda v: {"objects": []}, log=lambda m: None)


def test_published_output_reconstructs_the_timeline():
    state, _ = at.sync(None, ["1.0", "2.0"], _bundle, log=lambda m: None)
    rules = [Rule(ACTIVE, "2019-01-01", None, ("T1003",))]
    obj = sigma_metrics.build_sigma_coverage(
        RuleSet("0" * 40, "2026-11-05", rules, 1, 0), state,
        {"1.0": "2018-01-17", "2.0": "2018-10-17"}, GEN)
    rebuilt = at.reconstruct(json.loads(json.dumps(obj)))
    assert rebuilt == state
    assert at.reconstruct({"attack": {}}) is None
    assert at.reconstruct(None) is None


# -------------------------------------------------------------- builder

def _timeline(debuts: dict[str, str], retired=(), revoked=None,
              tactics=None) -> dict:
    versions = sorted({v for v in debuts.values()},
                      key=lambda v: tuple(int(x) for x in v.split(".")))
    techniques = {t: {"debut": v, "retired": None} for t, v in debuts.items()}
    for t, v in retired:
        techniques[t]["retired"] = v
    active = [t for t, e in techniques.items() if e["retired"] is None]
    return {"synced": versions, "techniques": techniques,
            "latest": {"version": versions[-1],
                       "names": {t: t for t in active},
                       "tactics": tactics or {t: ["execution"] for t in active},
                       "tactic_order": ["execution", "discovery"],
                       "tactic_names": {"execution": "Execution",
                                        "discovery": "Discovery"},
                       "revoked_to": revoked or {}}}


def _build(rules, timeline, releases, gen=GEN):
    rs = RuleSet("0" * 40, gen[:10], rules, len(rules), 0)
    obj = sigma_metrics.build_sigma_coverage(rs, timeline, releases, gen)
    contracts.validate("sigma_coverage.json", obj)
    return obj


def test_quarters_count_added_deprecated_and_alive_coverage():
    tl = _timeline({"T1001": "1.0", "T1002": "2.0"})
    rules = [
        Rule(ACTIVE, "2018-02-01", None, ("T1001",)),
        Rule(DEPRECATED, "2018-05-01", "2019-08-15", ("T1002.001",)),
        Rule(ACTIVE, "2019-11-30", None, ()),
    ]
    obj = _build(rules, tl, {"1.0": "2018-01-17", "2.0": "2018-04-18"})
    q = {r["quarter"]: r for r in obj["quarters"]}
    assert obj["quarters"][0]["quarter"] == "2018Q1"
    assert (q["2018Q1"]["added"], q["2018Q1"]["techniques"],
            q["2018Q1"]["covered"]) == (1, 1, 1)
    assert (q["2018Q2"]["techniques"], q["2018Q2"]["covered"]) == (2, 2)
    # The deprecated rule stops counting at its last edit (2019-08-15).
    assert q["2019Q3"]["deprecated"] == 1 and q["2019Q3"]["covered"] == 1
    assert q["2019Q2"]["covered"] == 2
    assert obj["coverage"]["peak"]["quarter"] == "2018Q1"   # earliest of the 100% ties
    assert obj["quarters"][-1]["partial"] is True
    assert obj["coverage"] == {"techniques": 2, "covered": 1, "pct": 50.0,
                               "peak": obj["coverage"]["peak"]}
    assert obj["catalog"]["mapped"] == 2 and obj["catalog"]["technique_tagged"] == 2


def test_revoked_tags_follow_to_the_replacement():
    tl = _timeline({"T1059": "1.0"}, revoked={"T1086": "T1059.001"})
    obj = _build([Rule(ACTIVE, "2018-03-01", None, ("T1086",))], tl,
                 {"1.0": "2018-01-17"})
    assert obj["techniques"][0]["rules"] == 1
    assert obj["coverage"]["covered"] == 1


def test_lag_median_exact_and_lower_bound():
    debuts = {"T1000": "1.0", "T1101": "2.0", "T1102": "2.0", "T1103": "2.0",
              "T1104": "2.0", "T1105": "3.0"}
    tl = _timeline(debuts)
    releases = {"1.0": "2018-01-17", "2.0": "2020-01-01", "3.0": "2026-06-01"}
    rules = [
        Rule(ACTIVE, "2019-01-01", None, ("T1101",)),   # before debut -> 0
        Rule(ACTIVE, "2020-02-01", None, ("T1102",)),   # 31 days
        Rule(ACTIVE, "2022-01-01", None, ("T1103",)),   # 731 days
        Rule(ACTIVE, "2017-01-01", None, ("T1000",)),   # v1.0: left out
    ]                                                   # T1104: none yet
    obj = _build(rules, tl, releases)
    lag = obj["lag"]
    assert (lag["n"], lag["before_debut"], lag["within_year"], lag["later"],
            lag["none"]) == (4, 1, 1, 1, 1)
    # waits [0, 31, 731, inf] -> median 381; the open technique has waited
    # since 2020, far longer, so the median is exact.
    assert lag["median_exact"] and lag["median_days"] == 381
    cohorts = {c["year"]: c for c in obj["cohorts"]}
    assert cohorts[2020]["techniques"] == 4 and cohorts[2020]["full_year"]
    assert cohorts[2026]["none"] == 1 and not cohorts[2026]["full_year"]
    # Two open techniques: the middle pair is [731, inf] -> not exact; the
    # lower bound puts each open technique at the wait it has served.
    rules2 = rules[:2]
    obj2 = _build(rules2, tl, releases)
    assert not obj2["lag"]["median_exact"]
    assert obj2["lag"]["median_days"] is None
    assert obj2["lag"]["median_at_least_days"] > 31


def test_rules_dated_after_the_edition_are_left_out():
    tl = _timeline({"T1001": "1.0"})
    rules = [Rule(ACTIVE, "2019-01-01", None, ("T1001",)),
             Rule(ACTIVE, "2030-01-01", None, ("T1001",))]
    obj = _build(rules, tl, {"1.0": "2018-01-17"})
    assert obj["catalog"]["rules"] == 1
    assert obj["catalog"]["future_dated"] == 1
    assert obj["techniques"][0]["rules"] == 1


def test_tactics_follow_matrix_order_and_count_twice_listed_techniques():
    tl = _timeline({"T1001": "1.0", "T1002": "1.0"},
                   tactics={"T1001": ["discovery", "execution"],
                            "T1002": ["execution"]})
    obj = _build([Rule(ACTIVE, "2019-01-01", None, ("T1001",))], tl,
                 {"1.0": "2018-01-17"})
    assert [(t["id"], t["techniques"], t["covered"]) for t in obj["tactics"]] \
        == [("execution", 2, 1), ("discovery", 1, 1)]


def test_missing_release_date_is_refused():
    tl = _timeline({"T1001": "1.0", "T1002": "2.0"})
    with pytest.raises(ValueError, match="no release date"):
        _build([Rule(ACTIVE, "2019-01-01", None, ())], tl,
               {"1.0": "2018-01-17"})


def test_run_stage_needs_the_attack_release_list():
    with pytest.raises(ValueError, match="no ATT&CK"):
        sigma_metrics.run_stage(Path("."), Path("."), GEN, attack_churn=None,
                                offline_fixtures=True, log=lambda m: None)


def test_offline_stage_matches_the_fixture_story():
    churn = {"versions": [{"version": "1.0", "released": "2018-01-17"},
                          {"version": "2.0", "released": "2018-10-17"}]}
    obj, src = sigma_metrics.run_stage(Path("."), Path("."), GEN,
                                       attack_churn=churn,
                                       offline_fixtures=True,
                                       log=lambda m: None)
    contracts.validate("sigma_coverage.json", obj)
    assert src["rules"] == 8 and src["attack_version"] == "2.0"
    assert obj["lag"]["median_days"] == 45
    assert len(json.dumps(obj)) < 200_000


def test_live_stage_lost_cache_rebuilds_timeline_without_bundles(tmp_path):
    """A lost cache: the rules come from one shallow clone (a fake runner
    here) and the technique timeline from the published edition — no
    ATT&CK index or bundle is requested. A second night with the same
    head costs one ls-remote and nothing else."""
    from .test_fetch_sigma import FakeGit, _tree

    churn = {"versions": [{"version": "1.0", "released": "2018-01-17"},
                          {"version": "2.0", "released": "2018-10-17"}]}
    published, _ = sigma_metrics.run_stage(tmp_path, tmp_path, GEN,
                                           attack_churn=churn,
                                           offline_fixtures=True,
                                           log=lambda m: None)
    out = tmp_path / "out"
    out.mkdir()
    (out / "sigma_coverage.json").write_text(json.dumps(published))

    class NoNetwork:
        def get(self, *args, **kwargs):
            raise AssertionError("no ATT&CK fetch expected")

    runner = FakeGit(_tree())
    cache = tmp_path / "cache"
    obj, src = sigma_metrics.run_stage(out, cache, GEN, attack_churn=churn,
                                       offline_fixtures=False,
                                       session=NoNetwork(), git_run=runner,
                                       log=lambda m: None)
    contracts.validate("sigma_coverage.json", obj)
    assert src["rules"] == 1002 and src["commit"] == "a" * 40
    assert obj["attack"]["synced"] == ["1.0", "2.0"]
    assert (cache / "sigma_state.json").exists()
    runner.calls.clear()
    sigma_metrics.run_stage(out, cache, GEN, attack_churn=churn,
                            offline_fixtures=False, session=NoNetwork(),
                            git_run=runner, log=lambda m: None)
    assert runner.calls == ["ls-remote"]


def test_live_stage_bundle_failure_is_an_oserror(tmp_path, monkeypatch):
    """fetch_attack raises RuntimeError after its retries; the stage turns
    it into OSError so __main__ degrades the module instead of the run."""
    from .test_fetch_sigma import FakeGit, _tree

    class Down:
        def get(self, *args, **kwargs):
            raise OSError("connection reset")

    churn = {"versions": [{"version": "1.0", "released": "2018-01-17"}]}
    import pipeline.fetch_attack as fa

    def exhausted(session, url, timeout, log):
        raise RuntimeError(f"attack fetch failed for {url}: down")

    monkeypatch.setattr(fa, "_get_json", exhausted)
    with pytest.raises(OSError, match="attack fetch failed"):
        sigma_metrics.run_stage(tmp_path, tmp_path / "c", GEN,
                                attack_churn=churn,
                                offline_fixtures=False, session=Down(),
                                git_run=FakeGit(_tree()),
                                log=lambda m: None)
