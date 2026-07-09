"""Offline end-to-end: the full pipeline from fixtures into a temp dir,
every emitted file validated against the contracts. No network."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import contracts
from pipeline.__main__ import main

ALL_FILES = ["meta.json", "severity_inflation.json", "nine_eight_flood.json",
             "score_vs_reality.json", "nvd_decay.json", "cna_leaderboard.json",
             "volume_curve.json"]


def _load(out: Path, name: str) -> dict:
    return json.loads((out / name).read_text(encoding="utf-8"))


def test_offline_fixtures_run_emits_all_valid_outputs(tmp_path, capsys):
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0

    for name in ALL_FILES:
        assert (tmp_path / name).exists(), f"{name} missing"
        contracts.validate(name, _load(tmp_path, name))

    meta = _load(tmp_path, "meta.json")
    assert meta["sample"] is False  # fixture runs are real pipeline runs
    assert meta["sources"]["cvelist"] == {"release": "fixtures", "cve_count": 11}
    assert meta["sources"]["epss"]["row_count"] == 7
    assert meta["sources"]["kev"]["count"] == 3

    decay = _load(tmp_path, "nvd_decay.json")
    assert decay["current"]["backlog_total"] == 31102  # 290 + 30412 + 400
    assert len(decay["history"]) == 1
    assert (tmp_path / "history" / "nvd_backlog.csv").exists()


def test_offline_rerun_replaces_todays_history_row(tmp_path, capsys):
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    decay = _load(tmp_path, "nvd_decay.json")
    assert len(decay["history"]) == 1  # same date -> replaced, not duplicated


def test_skip_nvd_carries_previous_run_forward(tmp_path, capsys):
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    first = _load(tmp_path, "nvd_decay.json")

    assert main(["--offline-fixtures", "--skip-nvd", "--out",
                 str(tmp_path)]) == 0
    carried = _load(tmp_path, "nvd_decay.json")
    contracts.validate("nvd_decay.json", carried)
    assert carried["stale"] is True
    assert carried["current"] == first["current"]
    assert carried["history"] == first["history"]  # no fake extra snapshot

    meta = _load(tmp_path, "meta.json")
    assert meta["sources"]["nvd"]["stale"] is True
    assert meta["sources"]["nvd"]["fetched_at"] == first["generated_at"]


def test_validation_failure_writes_nothing(tmp_path, capsys, monkeypatch):
    """The append-only history CSV must not be touched by a run that fails
    contract validation — the write happens only after every output passes."""
    def _always_fail(name, obj):
        raise contracts.ContractViolation(f"forced failure for {name}")

    monkeypatch.setattr(contracts, "validate", _always_fail)
    with pytest.raises(contracts.ContractViolation):
        main(["--offline-fixtures", "--out", str(tmp_path)])
    assert not (tmp_path / "history" / "nvd_backlog.csv").exists()
    for name in ALL_FILES:
        assert not (tmp_path / name).exists()


def test_skip_nvd_without_prior_data_omits_nvd_outputs(tmp_path, capsys):
    assert main(["--offline-fixtures", "--skip-nvd", "--out",
                 str(tmp_path)]) == 0
    assert not (tmp_path / "nvd_decay.json").exists()
    meta = _load(tmp_path, "meta.json")
    contracts.validate("meta.json", meta)
    assert "nvd" not in meta["sources"]
    # the other six files are all present and valid
    for name in ALL_FILES:
        if name != "nvd_decay.json":
            contracts.validate(name, _load(tmp_path, name))
