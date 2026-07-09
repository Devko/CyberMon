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


def test_advisory_quality_missing_over_n_rejected(outputs):
    bad = _corrupt(outputs, "advisory_quality.json")
    bad["years"][0]["missing_cwe"] = bad["years"][0]["n"] + 1
    with pytest.raises(ContractViolation, match="exceeds n"):
        contracts.validate("advisory_quality.json", bad)


def test_advisory_quality_unsorted_years_rejected(outputs):
    bad = _corrupt(outputs, "advisory_quality.json")
    assert len(bad["years"]) >= 2
    bad["years"].reverse()
    with pytest.raises(ContractViolation, match="sorted"):
        contracts.validate("advisory_quality.json", bad)


def test_cwe_distribution_share_key_mismatch_rejected(outputs):
    bad = _corrupt(outputs, "cwe_distribution.json")
    bad["years"][0]["shares"].pop("other")
    with pytest.raises(ContractViolation, match="'other'"):
        contracts.validate("cwe_distribution.json", bad)

    bad = _corrupt(outputs, "cwe_distribution.json")
    bad["years"][0]["shares"]["CWE-9999"] = 1.0
    with pytest.raises(ContractViolation, match="'other'"):
        contracts.validate("cwe_distribution.json", bad)


def test_cwe_distribution_year_outside_window_rejected(outputs):
    bad = _corrupt(outputs, "cwe_distribution.json")
    bad["years"][0]["year"] = bad["window"]["start_year"] - 1
    with pytest.raises(ContractViolation, match="outside window"):
        contracts.validate("cwe_distribution.json", bad)


def test_cwe_distribution_too_many_top_cwes_rejected(outputs):
    bad = _corrupt(outputs, "cwe_distribution.json")
    for i in range(9):
        bad["top_cwes"].append({"id": f"CWE-9{i:03d}", "name": "x"})
    with pytest.raises(ContractViolation, match="more than 8"):
        contracts.validate("cwe_distribution.json", bad)


def test_kev_ransomware_known_over_total_rejected(outputs):
    bad = _corrupt(outputs, "kev_ransomware.json")
    bad["years"][0]["known"] = bad["years"][0]["total"] + 1
    with pytest.raises(ContractViolation, match="exceeds total"):
        contracts.validate("kev_ransomware.json", bad)

    bad = _corrupt(outputs, "kev_ransomware.json")
    bad["catalog"]["known"] = bad["catalog"]["total"] + 1
    with pytest.raises(ContractViolation, match="exceeds total"):
        contracts.validate("kev_ransomware.json", bad)


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


# The `outputs` fixture builds from the fixture corpus (no current-year
# records), so the projection key is absent there — these tests bolt a
# hand-made block on and check both acceptance and each rejection rule.
_VOLUME_PROJECTION = {"year": 2026, "published": 51230, "rejected": 812,
                      "elapsed": 0.521}


def test_pace_projection_optional_but_checked_when_present(outputs):
    ok = _corrupt(outputs, "volume_curve.json")
    assert "projection" not in ok  # fixture corpus: absence is the contract
    ok["projection"] = dict(_VOLUME_PROJECTION)
    contracts.validate("volume_curve.json", ok)

    flood = _corrupt(outputs, "nine_eight_flood.json")
    flood["projection"] = {"year": 2026, "total": 48210, "elapsed": 0.521}
    contracts.validate("nine_eight_flood.json", flood)


def test_pace_projection_wrong_year_rejected(outputs):
    bad = _corrupt(outputs, "volume_curve.json")
    bad["projection"] = dict(_VOLUME_PROJECTION, year=2025)
    with pytest.raises(ContractViolation, match="generated_at year"):
        contracts.validate("volume_curve.json", bad)


def test_pace_projection_zero_published_rejected(outputs):
    bad = _corrupt(outputs, "volume_curve.json")
    bad["projection"] = dict(_VOLUME_PROJECTION, published=0)
    with pytest.raises(ContractViolation, match="below minimum"):
        contracts.validate("volume_curve.json", bad)


def test_pace_projection_zero_rejected_count_is_legal(outputs):
    ok = _corrupt(outputs, "volume_curve.json")
    ok["projection"] = dict(_VOLUME_PROJECTION, rejected=0)
    contracts.validate("volume_curve.json", ok)


def test_pace_projection_elapsed_out_of_range_rejected(outputs):
    for elapsed in (0.0, 1.001, -0.5):
        bad = _corrupt(outputs, "volume_curve.json")
        bad["projection"] = dict(_VOLUME_PROJECTION, elapsed=elapsed)
        with pytest.raises(ContractViolation, match="outside"):
            contracts.validate("volume_curve.json", bad)


def test_pace_projection_unrounded_elapsed_rejected(outputs):
    bad = _corrupt(outputs, "volume_curve.json")
    bad["projection"] = dict(_VOLUME_PROJECTION, elapsed=0.5214)
    with pytest.raises(ContractViolation, match="3 decimal"):
        contracts.validate("volume_curve.json", bad)


def test_flood_projection_zero_total_rejected(outputs):
    bad = _corrupt(outputs, "nine_eight_flood.json")
    bad["projection"] = {"year": 2026, "total": 0, "elapsed": 0.521}
    with pytest.raises(ContractViolation, match="below minimum"):
        contracts.validate("nine_eight_flood.json", bad)


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
