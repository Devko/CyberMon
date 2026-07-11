"""rescore_log.json contract: real shapes pass, corrupted shapes fail."""
from __future__ import annotations

import copy

import pytest

from pipeline import contracts, rescore_tracker
from pipeline.contracts import ContractViolation

GENERATED_AT = "2026-07-21T00:00:00Z"


def _rows():
    def ev(change_type, observed_date, cve, cna, vo, so, vn, sn):
        return {"observed_date": observed_date, "cve": cve, "cna": cna,
                "change_type": change_type, "version_old": vo,
                "score_old": so, "version_new": vn, "score_new": sn}
    return [
        ev("rescore", "2026-07-06", "CVE-2024-0001", "VendorX",
           "v3", 5.0, "v3", 9.8),
        ev("rescore", "2026-07-06", "CVE-2024-0009", "VendorX",
           "v3", 6.0, "v3", 7.0),
        ev("rescore", "2026-07-07", "CVE-2024-0002", "mitre",
           "v3", 9.8, "v3", 9.1),
        ev("first_score", "2026-07-07", "CVE-2024-0004", "mitre",
           None, None, "v3", 6.0),
        ev("version_shift", "2026-07-20", "CVE-2024-0006", "VendorX",
           "v3", 7.5, "v4", 9.1),
        ev("score_removed", "2026-07-20", "CVE-2024-0007", "mitre",
           "v3", 2.0, None, None),
    ]


@pytest.fixture()
def populated():
    return rescore_tracker.build_rescore_log(
        _rows(), state_size=7, release="r2", generated_at=GENERATED_AT,
        min_n=2, min_cna_events=1)


def test_populated_output_validates(populated):
    contracts.validate("rescore_log.json", populated)


def test_empty_launch_output_validates():
    contracts.validate("rescore_log.json", rescore_tracker.build_rescore_log(
        [], state_size=0, release="r1", generated_at=GENERATED_AT))


def _corrupt(obj):
    return copy.deepcopy(obj)


def test_weeks_must_sum_to_totals(populated):
    bad = _corrupt(populated)
    bad["weeks"][0]["rescore_up"] += 1
    with pytest.raises(ContractViolation, match="rescore up\\+down"):
        contracts.validate("rescore_log.json", bad)

    bad = _corrupt(populated)
    bad["weeks"][0]["version_shift"] += 1
    with pytest.raises(ContractViolation, match="version_shift"):
        contracts.validate("rescore_log.json", bad)


def test_week_labels_sorted_unique_and_shaped(populated):
    bad = _corrupt(populated)
    bad["weeks"].reverse()
    with pytest.raises(ContractViolation, match="not sorted"):
        contracts.validate("rescore_log.json", bad)

    bad = _corrupt(populated)
    bad["weeks"][0]["week"] = "2026-28"
    with pytest.raises(ContractViolation, match="week"):
        contracts.validate("rescore_log.json", bad)


def test_magnitude_gate_is_two_sided(populated):
    bad = _corrupt(populated)
    bad["magnitude"]["buckets"] = None  # n >= min_n but no distribution
    with pytest.raises(ContractViolation, match="null exactly when"):
        contracts.validate("rescore_log.json", bad)

    bad = _corrupt(populated)
    bad["magnitude"]["min_n"] = 99  # gated, yet buckets present
    with pytest.raises(ContractViolation, match="null exactly when"):
        contracts.validate("rescore_log.json", bad)


def test_magnitude_buckets_fixed_and_summing(populated):
    bad = _corrupt(populated)
    bad["magnitude"]["buckets"][0]["bucket"] = "way down"
    with pytest.raises(ContractViolation, match="bucket labels"):
        contracts.validate("rescore_log.json", bad)

    bad = _corrupt(populated)
    bad["magnitude"]["buckets"][0]["n"] += 1
    with pytest.raises(ContractViolation, match="sum"):
        contracts.validate("rescore_log.json", bad)

    bad = _corrupt(populated)
    bad["magnitude"]["n"] += 1
    with pytest.raises(ContractViolation, match="up .* down|magnitude"):
        contracts.validate("rescore_log.json", bad)


def test_board_direction_split_must_close(populated):
    bad = _corrupt(populated)
    bad["cna_board"]["cnas"][0]["up"] += 1
    with pytest.raises(ContractViolation, match="must equal"):
        contracts.validate("rescore_log.json", bad)

    bad = _corrupt(populated)
    bad["cna_board"]["cnas"].sort(key=lambda c: c["rescores"])  # ascending
    with pytest.raises(ContractViolation, match="descending"):
        contracts.validate("rescore_log.json", bad)


def test_catalog_arithmetic_enforced(populated):
    bad = _corrupt(populated)
    bad["catalog"]["events_total"] += 1
    with pytest.raises(ContractViolation, match="events_total"):
        contracts.validate("rescore_log.json", bad)

    bad = _corrupt(populated)
    del bad["catalog"]["totals"]["version_shift"]
    with pytest.raises(ContractViolation, match="exactly the keys"):
        contracts.validate("rescore_log.json", bad)

    bad = _corrupt(populated)
    bad["catalog"]["first_observed"] = None  # log is not empty
    with pytest.raises(ContractViolation, match="first_observed"):
        contracts.validate("rescore_log.json", bad)


def test_meta_rescores_optional_but_checked_when_present(outputs):
    ok = copy.deepcopy(outputs["meta.json"])
    del ok["sources"]["rescores"]
    contracts.validate("meta.json", ok)  # additive: absence is legal

    bad = copy.deepcopy(outputs["meta.json"])
    bad["sources"]["rescores"] = {"events_total": "many",
                                  "state_release": "r1"}
    with pytest.raises(ContractViolation, match="events_total"):
        contracts.validate("meta.json", bad)
