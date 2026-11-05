"""attack_atlas tests: the graph extraction (node and edge filters, the
compact encoding), the contract (what it rejects), the meta source block,
run_stage's offline / live / cached / reconstructed paths, and the
pipeline's --skip-attack and outage carry-forwards."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

# contracts must load before the module contracts (registration order —
# see the note in test_attack_contracts.py).
from pipeline import contracts
from pipeline import attack_atlas
from pipeline.__main__ import main
from pipeline.attack_atlas import (build_atlas, extract_graph,
                                   reconstruct_state, run_stage,
                                   source_block)
from pipeline.contracts import ContractViolation
from pipeline.tests.test_fetch_attack import load_fixture

GENERATED_AT = "2026-11-05T00:00:00Z"
QUIET = {"log": lambda _: None}
DATA_FILE = Path(__file__).resolve().parents[2] / "site" / "data" / \
    "attack_atlas.json"


def fixture_graph() -> dict:
    return extract_graph(load_fixture("enterprise-attack-2.0.json"), **QUIET)


def fixture_obj() -> dict:
    return build_atlas("2.0", "2018-10-17",
                       "https://fixtures.invalid/enterprise-attack-2.0.json",
                       fixture_graph(), GENERATED_AT)


# ------------------------------------------------------------- extraction

def test_extract_fixture_graph_exactly():
    g = fixture_graph()
    # Active objects only, each kind sorted by ATT&CK id: the revoked tool
    # (S0003) and the deprecated / revoked techniques never become nodes.
    assert g["ids"] == ["G0001", "G0002", "S0001", "S0002",
                        "T1059", "T1566", "T1566.001", "T1566.002"]
    assert g["names"][:4] == ["FIXTURE BEAR", "FIXTURE SPIDER (added in 2.0)",
                              "Fixtureware", "Fresh Tool (added in 2.0)"]
    assert g["software_types"] == "mt"
    # Matrix order, not id order or bundle order.
    assert [t["id"] for t in g["tactics"]] == ["TA0001", "TA0002", "TA0003"]
    # T1059 lists persistence before execution; the row follows the matrix.
    assert g["technique_tactics"] == ["1 2", "0", "0", "0"]
    # Canonical name dropped from the aliases.
    assert g["aliases"] == [["Fixture Panda", "Grizzly Fixture"],
                            ["Web Fixture"]]
    # Group rows reach software and techniques, software rows techniques.
    assert g["uses"] == ["2 5 6", "3 4 5", "4 5 7", "4"]
    assert g["counts"] == {
        "groups": 2, "software": 2, "techniques": 4, "subtechniques": 2,
        "edges": 10, "group_software": 2, "group_technique": 4,
        "software_technique": 4}


def test_extract_drops_inactive_relationships_campaigns_and_other_types():
    g = fixture_graph()
    rows = [set(map(int, r.split())) for r in g["uses"]]
    # g2 -> T1566.002 is a revoked relationship; g2 -> T1566 via a
    # deprecated duplicate still exists through its active relationship.
    assert 7 not in rows[1]
    assert 5 in rows[1]
    # g1 -> T1059 is "mitigates", not "uses".
    assert 4 not in rows[0]
    # The duplicate g1 -> S0001 relationship is one edge.
    assert g["counts"]["group_software"] == 2


def _bundle(objects: list[dict]) -> dict:
    tactic = {"type": "x-mitre-tactic", "id": "x-mitre-tactic--a",
              "name": "Execution", "x_mitre_shortname": "execution",
              "external_references": [{"source_name": "mitre-attack",
                                       "external_id": "TA0002"}]}
    matrix = {"type": "x-mitre-matrix", "id": "x-mitre-matrix--a",
              "tactic_refs": ["x-mitre-tactic--a"]}
    return {"objects": [tactic, matrix, *objects]}


def _obj(kind: str, stix: str, aid: str | None, name: str = "X",
         **extra) -> dict:
    refs = [{"source_name": "mitre-attack", "external_id": aid}] if aid \
        else []
    return {"type": kind, "id": stix, "name": name,
            "external_references": refs, **extra}


def test_extract_skips_objects_without_an_attack_id():
    g = extract_graph(_bundle([
        _obj("intrusion-set", "intrusion-set--1", "G0001"),
        _obj("intrusion-set", "intrusion-set--2", None),        # no id
        _obj("malware", "malware--1", "X9999"),                  # wrong form
        _obj("attack-pattern", "attack-pattern--1", "T1059",
             kill_chain_phases=[{"kill_chain_name": "mitre-attack",
                                 "phase_name": "execution"}]),
    ]), **QUIET)
    assert g["ids"] == ["G0001", "T1059"]
    assert g["uses"] == [""]
    assert g["technique_tactics"] == ["0"]


def test_extract_ignores_other_kill_chains_and_unknown_phases():
    g = extract_graph(_bundle([
        _obj("intrusion-set", "intrusion-set--1", "G0001"),
        _obj("attack-pattern", "attack-pattern--1", "T1059",
             kill_chain_phases=[
                 {"kill_chain_name": "mitre-mobile-attack",
                  "phase_name": "execution"},
                 {"kill_chain_name": "mitre-attack",
                  "phase_name": "no-such-tactic"}]),
    ]), **QUIET)
    assert g["technique_tactics"] == [""]


def test_extract_fails_loudly_on_duplicate_ids_and_missing_matrix():
    with pytest.raises(ValueError, match="share ATT&CK id"):
        extract_graph(_bundle([
            _obj("intrusion-set", "intrusion-set--1", "G0001"),
            _obj("intrusion-set", "intrusion-set--2", "G0001"),
        ]), **QUIET)
    bundle = _bundle([_obj("intrusion-set", "intrusion-set--1", "G0001")])
    bundle["objects"] = [o for o in bundle["objects"]
                         if o["type"] != "x-mitre-matrix"]
    with pytest.raises(ValueError, match="x-mitre-matrix"):
        extract_graph(bundle, **QUIET)


# ----------------------------------------------------------------- contract

def test_fixture_output_passes_its_contract():
    contracts.validate("attack_atlas.json", fixture_obj())


@pytest.mark.parametrize("mutate,message", [
    (lambda o: o["uses"].__setitem__(0, "2 99"), "out of range"),
    (lambda o: o["uses"].__setitem__(0, "1 5"), "out of range"),   # group
    (lambda o: o["uses"].__setitem__(2, "3 4"), "out of range"),   # software
    (lambda o: o["uses"].__setitem__(0, "6 5 2"), "ascending"),
    (lambda o: o["uses"].__setitem__(0, "2,5"), "space-separated"),
    (lambda o: o["counts"].__setitem__("edges", 11), "edges"),
    (lambda o: o["counts"].__setitem__("group_software", 3),
     "group_software"),
    (lambda o: o["counts"].__setitem__("subtechniques", 1), "subtechniques"),
    (lambda o: o["ids"].__setitem__(2, "G0003"), "format"),
    (lambda o: o["ids"].__setitem__(4, "T1600"), "sorted"),
    (lambda o: o["names"].__setitem__(1, ""), "non-empty"),
    (lambda o: o.__setitem__("software_types", "m"), "software_types"),
    (lambda o: o.__setitem__("software_types", "mx"), "software_types"),
    (lambda o: o["aliases"].pop(), "aliases"),
    (lambda o: o["technique_tactics"].__setitem__(0, "3"), "out of range"),
    (lambda o: o["tactics"].append(dict(o["tactics"][0])), "duplicate"),
    (lambda o: o.__setitem__("stale", "yes"), "boolean"),
    (lambda o: o.__setitem__("bundle", "ftp://x"), "format"),
    (lambda o: o.__setitem__("version", "v20"), "format"),
])
def test_contract_rejects(mutate, message):
    obj = copy.deepcopy(fixture_obj())
    mutate(obj)
    with pytest.raises(ContractViolation, match=message):
        contracts.validate("attack_atlas.json", obj)


def test_meta_source_block_is_validated():
    meta = json.loads((Path(__file__).resolve().parents[2] / "site" / "data"
                       / "meta.json").read_text(encoding="utf-8"))
    meta["sources"]["atlas"] = source_block(fixture_obj(), GENERATED_AT)
    contracts.validate("meta.json", meta)
    meta["sources"]["atlas"]["node_count"] = 0
    with pytest.raises(ContractViolation, match="node_count"):
        contracts.validate("meta.json", meta)
    meta["sources"]["atlas"] = {"fetched_at": GENERATED_AT, "version": "2.0",
                                "node_count": 8, "edge_count": 10,
                                "stale": 1}
    with pytest.raises(ContractViolation, match="stale"):
        contracts.validate("meta.json", meta)


def test_source_block_counts_nodes_and_edges():
    assert source_block(fixture_obj(), GENERATED_AT) == {
        "fetched_at": GENERATED_AT, "version": "2.0", "node_count": 8,
        "edge_count": 10}


# ----------------------------------------------------------------- run_stage

def test_run_stage_offline_fixtures_writes_no_state(tmp_path):
    obj, source = run_stage(tmp_path, tmp_path, GENERATED_AT,
                            offline_fixtures=True, **QUIET)
    contracts.validate("attack_atlas.json", obj)
    assert obj["version"] == "2.0" and obj["released"] == "2018-10-17"
    assert obj == fixture_obj()
    assert source["edge_count"] == 10
    assert not (tmp_path / attack_atlas.STATE_FILENAME).exists()


@pytest.fixture
def fake_attack(monkeypatch):
    """Route the live fetches to the fixtures and record each call."""
    calls: list[str] = []
    index = load_fixture("index.json")

    def _index(session, log=print):
        calls.append("index.json")
        return index

    def _bundle(session, url, log=print):
        calls.append(url.rsplit("/", 1)[-1])
        return load_fixture(url.rsplit("/", 1)[-1])

    monkeypatch.setattr(attack_atlas, "fetch_index", _index)
    monkeypatch.setattr(attack_atlas, "fetch_bundle", _bundle)
    return calls, index


def _live(out_dir, cache_dir, at=GENERATED_AT):
    return run_stage(out_dir, cache_dir, at, offline_fixtures=False,
                     session=object(), **QUIET)


def test_live_fetches_the_bundle_once_per_release(tmp_path, fake_attack):
    calls, _ = fake_attack
    out_dir, cache_dir = tmp_path / "out", tmp_path / "cache"
    out_dir.mkdir()
    obj, source = _live(out_dir, cache_dir)
    contracts.validate("attack_atlas.json", obj)
    assert calls == ["index.json", "enterprise-attack-2.0.json"]
    assert (cache_dir / attack_atlas.STATE_FILENAME).exists()
    assert source["fetched_at"] == GENERATED_AT

    calls.clear()
    obj2, _ = _live(out_dir, cache_dir, "2026-11-06T00:00:00Z")
    assert calls == ["index.json"]                 # a normal night
    assert obj2["generated_at"] == "2026-11-06T00:00:00Z"
    assert {k: v for k, v in obj2.items() if k != "generated_at"} == \
        {k: v for k, v in obj.items() if k != "generated_at"}


def test_live_new_release_refetches(tmp_path, fake_attack):
    calls, index = fake_attack
    out_dir, cache_dir = tmp_path / "out", tmp_path / "cache"
    out_dir.mkdir()
    _live(out_dir, cache_dir)
    # MITRE publishes "2.1": the cached 2.0 graph no longer answers.
    enterprise = next(c for c in index["collections"]
                      if c["name"] == "Enterprise ATT&CK")
    enterprise["versions"].insert(0, {
        "version": "2.1",
        "url": "https://fixtures.invalid/enterprise-attack-2.0.json",
        "modified": "2019-01-01T00:00:00.000Z"})
    calls.clear()
    obj, _ = _live(out_dir, cache_dir)
    assert calls == ["index.json", "enterprise-attack-2.0.json"]
    assert obj["version"] == "2.1" and obj["released"] == "2019-01-01"


def test_live_lost_cache_reconstructs_from_published_output(tmp_path,
                                                            fake_attack):
    calls, _ = fake_attack
    out_dir, cache_dir = tmp_path / "out", tmp_path / "fresh-cache"
    out_dir.mkdir()
    published = {**fixture_obj(), "stale": True}
    (out_dir / "attack_atlas.json").write_text(json.dumps(published),
                                               encoding="utf-8")
    obj, _ = _live(out_dir, cache_dir)
    assert calls == ["index.json"]                 # no bundle download
    assert "stale" not in obj
    assert obj["uses"] == published["uses"]
    # ... and the cache is warm again for the next night.
    assert (cache_dir / attack_atlas.STATE_FILENAME).exists()


def test_live_corrupt_published_output_is_not_trusted(tmp_path,
                                                      fake_attack):
    calls, _ = fake_attack
    out_dir, cache_dir = tmp_path / "out", tmp_path / "cache"
    out_dir.mkdir()
    broken = fixture_obj()
    broken["uses"][0] = "2 99"
    (out_dir / "attack_atlas.json").write_text(json.dumps(broken),
                                               encoding="utf-8")
    assert reconstruct_state(out_dir, **QUIET) is None
    obj, _ = _live(out_dir, cache_dir)
    assert calls == ["index.json", "enterprise-attack-2.0.json"]
    contracts.validate("attack_atlas.json", obj)


def test_live_corrupt_cache_is_refetched(tmp_path, fake_attack):
    calls, _ = fake_attack
    out_dir, cache_dir = tmp_path / "out", tmp_path / "cache"
    out_dir.mkdir()
    cache_dir.mkdir()
    (cache_dir / attack_atlas.STATE_FILENAME).write_text("{not json",
                                                         encoding="utf-8")
    _live(out_dir, cache_dir)
    assert calls == ["index.json", "enterprise-attack-2.0.json"]


def test_live_fetch_failure_raises_for_the_caller(tmp_path, monkeypatch):
    def _down(session, log=print):
        raise RuntimeError("attack fetch failed: HTTP 503")

    monkeypatch.setattr(attack_atlas, "fetch_index", _down)
    with pytest.raises(RuntimeError):
        _live(tmp_path, tmp_path)


# ---------------------------------------------------------------------- e2e

def _load(out: Path, name: str) -> dict:
    return json.loads((out / name).read_text(encoding="utf-8"))


def test_offline_run_emits_atlas_and_meta_source(tmp_path, capsys):
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    obj = _load(tmp_path, "attack_atlas.json")
    contracts.validate("attack_atlas.json", obj)
    meta = _load(tmp_path, "meta.json")
    assert meta["sources"]["atlas"] == {
        "fetched_at": meta["generated_at"], "version": "2.0",
        "node_count": 8, "edge_count": 10}


def test_skip_attack_carries_the_atlas_forward(tmp_path, capsys):
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    first = _load(tmp_path, "attack_atlas.json")
    assert main(["--offline-fixtures", "--skip-attack", "--out",
                 str(tmp_path)]) == 0
    carried = _load(tmp_path, "attack_atlas.json")
    contracts.validate("attack_atlas.json", carried)
    assert carried["stale"] is True
    assert carried["uses"] == first["uses"]
    meta = _load(tmp_path, "meta.json")
    assert meta["sources"]["atlas"]["stale"] is True
    assert meta["sources"]["atlas"]["fetched_at"] == first["generated_at"]


def test_skip_attack_without_prior_atlas_omits_it(tmp_path, capsys):
    assert main(["--offline-fixtures", "--skip-attack", "--out",
                 str(tmp_path)]) == 0
    assert not (tmp_path / "attack_atlas.json").exists()
    assert "atlas" not in _load(tmp_path, "meta.json")["sources"]


def test_attack_outage_degrades_only_the_atlas(tmp_path, capsys,
                                               monkeypatch):
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    first = _load(tmp_path, "attack_atlas.json")

    def down(*args, **kwargs):
        raise RuntimeError("attack fetch failed: HTTP 503")

    monkeypatch.setattr(attack_atlas, "run_stage", down)
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    carried = _load(tmp_path, "attack_atlas.json")
    assert carried["stale"] is True
    assert carried["ids"] == first["ids"]
    meta = _load(tmp_path, "meta.json")
    assert meta["sources"]["atlas"]["stale"] is True
    assert meta["sources"]["atlas"]["fetched_at"] == first["generated_at"]
    # every other module refreshed as normal
    assert "stale" not in _load(tmp_path, "naming.json")


# ------------------------------------------------------- committed edition

def test_committed_edition_stays_small_and_valid():
    """The published file doubles as the cache's backup and ships to every
    visitor: keep it valid and well under the 600 KB budget (162 KB raw,
    42 KB gzipped for v20.0)."""
    if not DATA_FILE.exists():
        pytest.skip("no committed attack_atlas.json")
    assert DATA_FILE.stat().st_size < 400_000
    contracts.validate("attack_atlas.json",
                       json.loads(DATA_FILE.read_text(encoding="utf-8")))
