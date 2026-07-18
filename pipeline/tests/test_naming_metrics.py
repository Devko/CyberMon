"""naming_metrics tests: alias extraction, board/distribution assembly, the
builder's headline math, run_stage's offline + live + reconstruct paths, and
the offline end-to-end run emitting a valid naming.json."""
from __future__ import annotations

import json

# contracts must load before naming_contracts (registration order — see the
# note in test_attack_contracts.py).
from pipeline import contracts
from pipeline import naming_contracts  # noqa: E402
from pipeline.__main__ import main
from pipeline.naming_metrics import (board_and_distribution, build_naming,
                                     extract_groups, run_stage)

GENERATED_AT = "2026-07-09T00:00:00Z"


# ------------------------------------------------------------- extraction

def test_extract_excludes_canonical_inactive_and_nameless():
    bundle = {"objects": [
        {"type": "intrusion-set", "id": "g1", "name": "APT-X",
         "aliases": ["APT-X", "Fancy X", "Xbear"]},          # 2 alternates
        {"type": "intrusion-set", "id": "g2", "name": "Loner"},   # 0 aliases
        {"type": "intrusion-set", "id": "g3", "name": "Dead",
         "aliases": ["Dead", "Zombie"], "x_mitre_deprecated": True},
        {"type": "intrusion-set", "id": "g4", "name": "Gone",
         "revoked": True},
        {"type": "attack-pattern", "id": "t1", "name": "Not a group"},
        {"type": "intrusion-set", "id": "g5"},               # no name
        "not a dict",
    ]}
    groups = extract_groups(bundle)
    assert groups == [
        {"name": "APT-X", "aliases": ["Fancy X", "Xbear"], "alt_count": 2},
        {"name": "Loner", "aliases": [], "alt_count": 0},
    ]


def test_board_sorts_and_distribution_gap_fills():
    groups = [
        {"name": "B", "aliases": ["b1"], "alt_count": 1},
        {"name": "A", "aliases": ["a1", "a2", "a3"], "alt_count": 3},
        {"name": "Z", "aliases": [], "alt_count": 0},
        {"name": "Y", "aliases": [], "alt_count": 0},
    ]
    board, distribution = board_and_distribution(groups)
    assert [g["name"] for g in board] == ["A", "B"]           # by count desc
    assert distribution == [{"alt_count": 0, "n": 2},
                            {"alt_count": 1, "n": 1},
                            {"alt_count": 2, "n": 0},
                            {"alt_count": 3, "n": 1}]


# --------------------------------------------------------------- builder

def test_build_headline_and_contract():
    groups = [
        {"name": "APT28", "aliases": ["Fancy Bear", "Forest Blizzard"],
         "alt_count": 2},
        {"name": "APT29", "aliases": ["Cozy Bear"], "alt_count": 1},
        {"name": "Quiet", "aliases": [], "alt_count": 0},
    ]
    board, distribution = board_and_distribution(groups)
    obj = build_naming("19.1", "2026-05-12", board, distribution, GENERATED_AT)
    assert obj["headline"] == {
        "total_groups": 3, "groups_with_aliases": 2, "total_alias_strings": 3,
        "distinct_alias_strings": 3, "most_renamed": "APT28",
        "most_renamed_alt_count": 2}
    contracts.validate("naming.json", obj)


def test_build_empty_board_yields_null_headline():
    groups = [{"name": "Quiet", "aliases": [], "alt_count": 0}]
    board, distribution = board_and_distribution(groups)
    obj = build_naming("19.1", "2026-05-12", board, distribution, GENERATED_AT)
    assert obj["groups"] == [] and obj["headline"] is None
    contracts.validate("naming.json", obj)


# ----------------------------------------------------------------- run_stage

def test_run_stage_offline_fixtures(tmp_path):
    obj, source = run_stage(tmp_path, tmp_path, GENERATED_AT,
                            offline_fixtures=True, log=lambda _: None)
    contracts.validate("naming.json", obj)
    assert obj["version"] == "2.0"
    assert [g["name"] for g in obj["groups"]] == [
        "FIXTURE BEAR", "FIXTURE SPIDER (added in 2.0)"]
    assert obj["groups"][0]["aliases"] == ["Fixture Panda", "Grizzly Fixture"]
    assert obj["headline"]["most_renamed"] == "FIXTURE BEAR"
    assert source == {"fetched_at": GENERATED_AT, "version": "2.0",
                      "group_count": 2}
    # The offline path must not leave a state file behind.
    assert not (tmp_path / "naming_state.json").exists()


def test_run_stage_live_fetches_once_then_reuses_state(tmp_path, monkeypatch):
    from pipeline import naming_metrics
    from pipeline.tests.test_fetch_attack import load_fixture

    calls: list[str] = []

    def _fake_index(session, log=print):
        calls.append("index.json")
        return load_fixture("index.json")

    def _fake_bundle(session, url, log=print):
        name = url.rsplit("/", 1)[-1]
        calls.append(name)
        return load_fixture(name)

    monkeypatch.setattr(naming_metrics, "fetch_index", _fake_index)
    monkeypatch.setattr(naming_metrics, "fetch_bundle", _fake_bundle)

    out_dir, cache_dir = tmp_path / "out", tmp_path / "cache"
    out_dir.mkdir()
    obj, _ = run_stage(out_dir, cache_dir, GENERATED_AT,
                       offline_fixtures=False, session=object(),
                       log=lambda _: None)
    contracts.validate("naming.json", obj)
    # Only the latest bundle is fetched (no predecessor — this is a snapshot).
    assert calls == ["index.json", "enterprise-attack-2.0.json"]
    assert (cache_dir / "naming_state.json").exists()

    calls.clear()
    obj2, _ = run_stage(out_dir, cache_dir, "2026-07-10T00:00:00Z",
                        offline_fixtures=False, session=object(),
                        log=lambda _: None)
    assert calls == ["index.json"]     # a normal night: index only
    assert obj2["groups"] == obj["groups"]


def test_run_stage_reconstructs_lost_cache_from_published_output(tmp_path,
                                                                 monkeypatch):
    from pipeline import naming_metrics
    from pipeline.tests.test_fetch_attack import load_fixture

    monkeypatch.setattr(naming_metrics, "fetch_index",
                        lambda session, log=print: load_fixture("index.json"))

    def _no_bundles(session, url, log=print):
        raise AssertionError(f"unexpected bundle fetch: {url}")

    monkeypatch.setattr(naming_metrics, "fetch_bundle", _no_bundles)

    prior, _ = run_stage(tmp_path, tmp_path, GENERATED_AT,
                         offline_fixtures=True, log=lambda _: None)
    out_dir, cache_dir = tmp_path / "out", tmp_path / "empty-cache"
    out_dir.mkdir()
    (out_dir / "naming.json").write_text(json.dumps(prior), encoding="utf-8")
    obj, _ = run_stage(out_dir, cache_dir, "2026-07-10T00:00:00Z",
                       offline_fixtures=False, session=object(),
                       log=lambda _: None)
    assert obj["groups"] == prior["groups"]
    assert obj["distribution"] == prior["distribution"]


# ---------------------------------------------------------------------- e2e

def test_offline_pipeline_run_emits_valid_naming(tmp_path, capsys):
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    obj = json.loads((tmp_path / "naming.json").read_text(encoding="utf-8"))
    contracts.validate("naming.json", obj)
    assert obj["headline"]["most_renamed"] == "FIXTURE BEAR"

    meta = json.loads((tmp_path / "meta.json").read_text(encoding="utf-8"))
    contracts.validate("meta.json", meta)
    assert meta["sources"]["naming"] == {
        "fetched_at": meta["generated_at"], "version": "2.0",
        "group_count": 2}
