"""Contract validators: real outputs pass, malformed outputs fail loudly."""
from __future__ import annotations

import copy

import pytest

from pipeline import contracts
from pipeline.contracts import ContractViolation


def test_all_built_outputs_validate(outputs):
    for name, obj in outputs.items():
        contracts.validate(name, obj)


def test_unknown_filename_has_no_contract():
    with pytest.raises(KeyError):
        contracts.validate("surprise.json", {})


def _corrupt(outputs, name):
    return copy.deepcopy(outputs[name])


def test_meta_missing_sample_flag(outputs):
    bad = _corrupt(outputs, "meta.json")
    del bad["sample"]
    with pytest.raises(ContractViolation, match="sample"):
        contracts.validate("meta.json", bad)


def test_meta_nvd_optional_but_checked_when_present(outputs):
    ok = _corrupt(outputs, "meta.json")
    del ok["sources"]["nvd"]
    contracts.validate("meta.json", ok)  # documented --skip-nvd shape

    bad = _corrupt(outputs, "meta.json")
    bad["sources"]["nvd"] = {"fetched_at": "yesterday-ish"}
    with pytest.raises(ContractViolation, match="fetched_at"):
        contracts.validate("meta.json", bad)


def test_pct_out_of_range_rejected(outputs):
    bad = _corrupt(outputs, "severity_inflation.json")
    bad["blended"][0]["pct_high_critical"] = 101.0
    with pytest.raises(ContractViolation, match="pct_high_critical"):
        contracts.validate("severity_inflation.json", bad)


def test_unrounded_float_rejected(outputs):
    bad = _corrupt(outputs, "severity_inflation.json")
    bad["series"]["v2"][0]["median"] = 5.44  # must be 1 decimal place
    with pytest.raises(ContractViolation, match="1 decimal"):
        contracts.validate("severity_inflation.json", bad)


def test_unsorted_years_rejected(outputs):
    bad = _corrupt(outputs, "nine_eight_flood.json")
    bad["years"].reverse()
    with pytest.raises(ContractViolation, match="sorted"):
        contracts.validate("nine_eight_flood.json", bad)


def test_missing_grid_cell_rejected(outputs):
    bad = _corrupt(outputs, "score_vs_reality.json")
    bad["grid"].pop()
    with pytest.raises(ContractViolation, match="missing cells"):
        contracts.validate("score_vs_reality.json", bad)


def test_duplicate_grid_cell_rejected(outputs):
    bad = _corrupt(outputs, "score_vs_reality.json")
    bad["grid"][1] = dict(bad["grid"][0])
    with pytest.raises(ContractViolation, match="duplicate cell"):
        contracts.validate("score_vs_reality.json", bad)


def test_negative_count_rejected(outputs):
    bad = _corrupt(outputs, "volume_curve.json")
    bad["years"][0]["rejected"] = -1
    with pytest.raises(ContractViolation, match="below minimum"):
        contracts.validate("volume_curve.json", bad)


def test_leaderboard_sort_order_enforced(outputs):
    bad = _corrupt(outputs, "cna_leaderboard.json")
    assert len(bad["cnas"]) >= 2
    bad["cnas"].reverse()  # ascending pct_geq_9 violates the contract
    with pytest.raises(ContractViolation, match="descending"):
        contracts.validate("cna_leaderboard.json", bad)


def test_history_bad_date_rejected(outputs):
    bad = _corrupt(outputs, "nvd_decay.json")
    bad["history"][0]["date"] = "07/09/2026"
    with pytest.raises(ContractViolation, match="date"):
        contracts.validate("nvd_decay.json", bad)


def test_wrong_type_rejected(outputs):
    bad = _corrupt(outputs, "nvd_decay.json")
    bad["current"]["backlog_total"] = "31102"
    with pytest.raises(ContractViolation, match="integer"):
        contracts.validate("nvd_decay.json", bad)


def test_committed_sample_data_conforms():
    """The samples committed under site/data must obey the same contracts."""
    import json
    from pathlib import Path

    data_dir = Path(__file__).resolve().parents[2] / "site" / "data"
    if not data_dir.exists():
        pytest.skip("site/data not present")
    for name in contracts.VALIDATORS:
        path = data_dir / name
        if path.exists():
            contracts.validate(name, json.loads(path.read_text("utf-8")))
