"""attack_metrics tests: builder shape/order, run_stage's three paths, and
the offline end-to-end run emitting a valid attack_churn.json."""
from __future__ import annotations

import json
from pathlib import Path

# contracts must load before attack_contracts (registration order — see
# the note in test_attack_contracts.py).
from pipeline import contracts
from pipeline import attack_contracts  # noqa: E402
from pipeline.__main__ import main
from pipeline.attack_metrics import build_attack_churn, run_stage

GENERATED_AT = "2026-07-09T00:00:00Z"


def _entry(released: str, techniques: int = 1, subtechniques: int = 0,
           churn: dict | None = None) -> dict:
    return {"released": released, "techniques": techniques,
            "subtechniques": subtechniques, "groups": 1, "software": 1,
            "churn": churn}


def _state(versions: dict) -> dict:
    return {"version": 1, "last_sync": GENERATED_AT, "versions": versions}


# ------------------------------------------------------------------- builder

def test_build_orders_by_version_number_not_lexically():
    state = _state({
        "10.0": _entry("2021-10-21", churn={"added": 1, "deprecated": 0,
                                            "revoked": 0}),
        "2.0": _entry("2018-10-17", churn={"added": 2, "deprecated": 1,
                                           "revoked": 0}),
        "1.0": _entry("2018-01-17"),
    })
    obj = build_attack_churn(state, GENERATED_AT)
    assert [v["version"] for v in obj["versions"]] == ["1.0", "2.0", "10.0"]
    attack_contracts.validate("attack_churn.json", obj)


def test_build_headline_compares_first_and_latest_release():
    state = _state({
        "1.0": _entry("2018-01-17", techniques=200, subtechniques=0),
        "19.1": _entry("2026-05-12", techniques=220, subtechniques=470,
                       churn={"added": 9, "deprecated": 2, "revoked": 1}),
    })
    obj = build_attack_churn(state, GENERATED_AT)
    assert obj["headline"] == {
        "latest_version": "19.1", "released_latest": "2026-05-12",
        "techniques_latest": 220, "subtechniques_latest": 470,
        "first_version": "1.0", "released_first": "2018-01-17",
        "techniques_first": 200, "subtechniques_first": 0}
    attack_contracts.validate("attack_churn.json", obj)


def test_build_empty_state_yields_null_headline():
    obj = build_attack_churn(_state({}), GENERATED_AT)
    assert obj["versions"] == [] and obj["headline"] is None
    attack_contracts.validate("attack_churn.json", obj)


# ----------------------------------------------------------------- run_stage

def test_run_stage_offline_fixtures(tmp_path):
    obj, source = run_stage(tmp_path, tmp_path, GENERATED_AT,
                            skip=False, offline_fixtures=True,
                            log=lambda _: None)
    attack_contracts.validate("attack_churn.json", obj)
    assert [v["version"] for v in obj["versions"]] == ["1.0", "2.0"]
    assert obj["versions"][1]["churn"] == {"added": 3, "deprecated": 1,
                                           "revoked": 1}
    assert source == {"fetched_at": GENERATED_AT, "latest_version": "2.0",
                      "version_count": 2}
    # The offline path must not leave a state file behind.
    assert not (tmp_path / "attack_state.json").exists()


def test_run_stage_skip_carries_prior_output_forward(tmp_path):
    prior, _ = run_stage(tmp_path, tmp_path, GENERATED_AT,
                         skip=False, offline_fixtures=True,
                         log=lambda _: None)
    (tmp_path / "attack_churn.json").write_text(json.dumps(prior),
                                                encoding="utf-8")
    obj, source = run_stage(tmp_path, tmp_path, "2026-07-10T00:00:00Z",
                            skip=True, offline_fixtures=False,
                            log=lambda _: None)
    attack_contracts.validate("attack_churn.json", obj)  # stale shape valid
    assert obj["stale"] is True
    assert obj["generated_at"] == "2026-07-10T00:00:00Z"
    assert obj["versions"] == prior["versions"]
    assert source == {"fetched_at": GENERATED_AT, "latest_version": "2.0",
                      "version_count": 2, "stale": True}


def test_run_stage_skip_without_prior_output_omits_stage(tmp_path):
    obj, source = run_stage(tmp_path, tmp_path, GENERATED_AT,
                            skip=True, offline_fixtures=False,
                            log=lambda _: None)
    assert obj is None and source is None


def test_run_stage_live_uses_state_and_persists_it(tmp_path, monkeypatch):
    """Live path with a stubbed session: index fetched, state saved, and a
    second run against an unchanged index downloads no bundles."""
    from pipeline import attack_metrics
    from pipeline.tests.test_fetch_attack import FIXTURES, load_fixture

    calls: list[str] = []

    def _fake_index(session, log=print):
        calls.append("index.json")
        return load_fixture("index.json")

    def _fake_bundle(session, url, log=print):
        calls.append(url.rsplit("/", 1)[-1])
        return load_fixture(url.rsplit("/", 1)[-1])

    monkeypatch.setattr(attack_metrics, "fetch_index", _fake_index)
    monkeypatch.setattr(attack_metrics, "fetch_bundle", _fake_bundle)

    out_dir, cache_dir = tmp_path / "out", tmp_path / "cache"
    out_dir.mkdir()
    obj, source = run_stage(out_dir, cache_dir, GENERATED_AT,
                            skip=False, offline_fixtures=False,
                            session=object(), log=lambda _: None)
    attack_contracts.validate("attack_churn.json", obj)
    assert sorted(calls) == ["enterprise-attack-1.0.json",
                             "enterprise-attack-2.0.json", "index.json"]
    assert (cache_dir / "attack_state.json").exists()

    calls.clear()
    obj2, _ = run_stage(out_dir, cache_dir, "2026-07-10T00:00:00Z",
                        skip=False, offline_fixtures=False,
                        session=object(), log=lambda _: None)
    assert calls == ["index.json"]  # a normal night: index only
    assert obj2["versions"] == obj["versions"]


def test_run_stage_live_reconstructs_lost_cache_from_published_output(
        tmp_path, monkeypatch):
    from pipeline import attack_metrics
    from pipeline.tests.test_fetch_attack import load_fixture

    def _fake_index(session, log=print):
        return load_fixture("index.json")

    def _no_bundles(session, url, log=print):
        raise AssertionError(f"unexpected bundle fetch: {url}")

    monkeypatch.setattr(attack_metrics, "fetch_index", _fake_index)
    monkeypatch.setattr(attack_metrics, "fetch_bundle", _no_bundles)

    prior, _ = run_stage(tmp_path, tmp_path, GENERATED_AT,
                         skip=False, offline_fixtures=True,
                         log=lambda _: None)
    out_dir, cache_dir = tmp_path / "out", tmp_path / "empty-cache"
    out_dir.mkdir()
    (out_dir / "attack_churn.json").write_text(json.dumps(prior),
                                               encoding="utf-8")
    obj, _ = run_stage(out_dir, cache_dir, "2026-07-10T00:00:00Z",
                       skip=False, offline_fixtures=False,
                       session=object(), log=lambda _: None)
    assert obj["versions"] == prior["versions"]


# ---------------------------------------------------------------------- e2e

def test_offline_pipeline_run_emits_valid_attack_churn(tmp_path, capsys):
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    obj = json.loads((tmp_path / "attack_churn.json")
                     .read_text(encoding="utf-8"))
    contracts.validate("attack_churn.json", obj)
    assert obj["headline"]["latest_version"] == "2.0"

    meta = json.loads((tmp_path / "meta.json").read_text(encoding="utf-8"))
    contracts.validate("meta.json", meta)
    assert meta["sources"]["attack"] == {
        "fetched_at": meta["generated_at"], "latest_version": "2.0",
        "version_count": 2}


def test_offline_pipeline_skip_attack_carries_forward(tmp_path, capsys):
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    first = json.loads((tmp_path / "attack_churn.json")
                       .read_text(encoding="utf-8"))
    assert main(["--offline-fixtures", "--skip-attack", "--out",
                 str(tmp_path)]) == 0
    carried = json.loads((tmp_path / "attack_churn.json")
                         .read_text(encoding="utf-8"))
    assert carried["stale"] is True
    assert carried["versions"] == first["versions"]
    meta = json.loads((tmp_path / "meta.json").read_text(encoding="utf-8"))
    assert meta["sources"]["attack"]["stale"] is True
    assert meta["sources"]["attack"]["fetched_at"] == first["generated_at"]


def test_offline_pipeline_skip_attack_without_prior_omits_output(tmp_path,
                                                                 capsys):
    assert main(["--offline-fixtures", "--skip-attack", "--out",
                 str(tmp_path)]) == 0
    assert not (tmp_path / "attack_churn.json").exists()
    meta = json.loads((tmp_path / "meta.json").read_text(encoding="utf-8"))
    contracts.validate("meta.json", meta)
    assert "attack" not in meta["sources"]
