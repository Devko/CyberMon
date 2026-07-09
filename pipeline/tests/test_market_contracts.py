"""Market contract validator: real output passes, corruption fails loudly."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from pipeline import market_contracts, market_metrics
from pipeline.contracts import ContractViolation
from pipeline.market_terms import TERMS

from .conftest import GENERATED_AT

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def hype() -> dict:
    """market_hype.json built from the committed fixture state."""
    state = json.loads((FIXTURES / "market" / "state.json")
                       .read_text(encoding="utf-8"))
    terms = [t for t in TERMS if t.id in state["series"]]
    return market_metrics.build_market_hype(state, terms, GENERATED_AT)


def _corrupt(hype):
    return copy.deepcopy(hype)


def test_built_output_validates(hype):
    market_contracts.validate("market_hype.json", hype)


def test_unknown_filename_has_no_contract():
    with pytest.raises(KeyError):
        market_contracts.validate("surprise.json", {})


def test_stale_flag_optional_but_must_be_bool(hype):
    ok = _corrupt(hype)
    ok["stale"] = True
    market_contracts.validate("market_hype.json", ok)  # carry-forward shape
    bad = _corrupt(hype)
    bad["stale"] = "yes"
    with pytest.raises(ContractViolation, match="stale"):
        market_contracts.validate("market_hype.json", bad)


def test_bad_month_format_rejected(hype):
    bad = _corrupt(hype)
    bad["terms"][0]["series"]["gdelt"][0]["month"] = "2024-7"
    with pytest.raises(ContractViolation, match="month"):
        market_contracts.validate("market_hype.json", bad)


def test_unsorted_months_rejected(hype):
    bad = _corrupt(hype)
    bad["terms"][0]["series"]["gdelt"].reverse()
    with pytest.raises(ContractViolation, match="sorted"):
        market_contracts.validate("market_hype.json", bad)


def test_duplicate_months_rejected(hype):
    bad = _corrupt(hype)
    series = bad["terms"][0]["series"]["gdelt"]
    series[1] = dict(series[0])
    with pytest.raises(ContractViolation, match="duplicate months"):
        market_contracts.validate("market_hype.json", bad)


def test_index_above_100_rejected(hype):
    bad = _corrupt(hype)
    bad["terms"][0]["series"]["gdelt"][0]["index"] = 100.5
    with pytest.raises(ContractViolation, match="index"):
        market_contracts.validate("market_hype.json", bad)


def test_unrounded_index_rejected(hype):
    bad = _corrupt(hype)
    bad["terms"][0]["series"]["gdelt"][0]["index"] = 12.34
    with pytest.raises(ContractViolation, match="1 decimal"):
        market_contracts.validate("market_hype.json", bad)


def test_negative_n_rejected(hype):
    bad = _corrupt(hype)
    bad["terms"][0]["series"]["gdelt"][0]["n"] = -1
    with pytest.raises(ContractViolation, match="below minimum"):
        market_contracts.validate("market_hype.json", bad)


def test_pct_change_below_minus_100_rejected(hype):
    bad = _corrupt(hype)
    assert bad["terms"][0]["yoy"]["gdelt"] is not None  # zero_trust
    bad["terms"][0]["yoy"]["gdelt"]["pct_change"] = -100.1
    with pytest.raises(ContractViolation, match="pct_change"):
        market_contracts.validate("market_hype.json", bad)


def test_bad_direction_enum_rejected(hype):
    bad = _corrupt(hype)
    assert bad["terms"][0]["divergence"] is not None  # zero_trust
    bad["terms"][0]["divergence"]["direction"] = "sideways"
    with pytest.raises(ContractViolation, match="direction"):
        market_contracts.validate("market_hype.json", bad)


def test_wrong_sources_list_rejected(hype):
    bad = _corrupt(hype)
    bad["sources"] = ["gdelt", "arxiv", "hn"]  # right set, wrong order
    with pytest.raises(ContractViolation, match="sources"):
        market_contracts.validate("market_hype.json", bad)
