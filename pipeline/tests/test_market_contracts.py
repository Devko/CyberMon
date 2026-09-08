"""Market contract validator: real output passes, corruption fails loudly."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

# contracts must load before market_contracts: the coordinator registers
# module contracts from its own module bottom, so importing the contract
# file first would hit the registration mid-initialization.
from pipeline import contracts  # (see above)
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
    bad["sources"] = ["gdelt", "arxiv", "hn", "wiki", "edgar"]  # wrong order
    with pytest.raises(ContractViolation, match="sources"):
        market_contracts.validate("market_hype.json", bad)


def test_legacy_three_source_file_still_validates(hype):
    # The committed market_hype.json is one nightly behind the code: the
    # pre-v1.1 shape (exactly gdelt/hn/arxiv) must keep validating until
    # the first five-source nightly rewrites it.
    legacy = _corrupt(hype)
    legacy["sources"] = ["gdelt", "hn", "arxiv"]
    for t in legacy["terms"]:
        for src in ("wiki", "edgar"):
            del t["series"][src]
            del t["yoy"][src]
    market_contracts.validate("market_hype.json", legacy)
    # ... but a partial mix (legacy declaration, v1.1 keys required by a
    # five-source declaration) is caught the moment sources claims five.
    partial = _corrupt(legacy)
    partial["sources"] = market_contracts.SOURCES
    with pytest.raises(ContractViolation, match="wiki"):
        market_contracts.validate("market_hype.json", partial)


# ----------------------------------------------------------- stale_sources

def test_stale_sources_optional_but_validated_when_present(hype):
    assert hype["stale_sources"] == []   # the fixture state carries no stamps
    legacy = _corrupt(hype)
    del legacy["stale_sources"]          # pre-freshness file (a nightly behind)
    market_contracts.validate("market_hype.json", legacy)
    for value, why in (("hn", "expected array"),
                       (["hn", "hn"], "duplicate"),
                       (["telegram"], "unknown source"),
                       (["arxiv", "gdelt"], "order")):
        bad = _corrupt(hype)
        bad["stale_sources"] = value
        with pytest.raises(ContractViolation, match=why):
            market_contracts.validate("market_hype.json", bad)


def test_stale_source_must_not_carry_a_computed_yoy(hype):
    bad = _corrupt(hype)
    bad["stale_sources"] = ["gdelt"]
    assert bad["terms"][0]["yoy"]["gdelt"] is not None   # zero_trust
    with pytest.raises(ContractViolation, match="yoy.gdelt.*stale_sources"):
        market_contracts.validate("market_hype.json", bad)
    # the honest shape — null YoY, null divergence (gdelt is a side of
    # it), a headline that does not rank the dead lane — validates
    ok = _corrupt(hype)
    ok["stale_sources"] = ["gdelt"]
    for t in ok["terms"]:
        t["yoy"]["gdelt"] = None
        t["divergence"] = None
    ok["headline"] = {"top_riser": None, "top_faller": None,
                      "top_divergence": None}
    market_contracts.validate("market_hype.json", ok)


def test_stale_gdelt_or_arxiv_must_not_carry_a_divergence(hype):
    bad = _corrupt(hype)
    bad["stale_sources"] = ["arxiv"]
    for t in bad["terms"]:
        t["yoy"]["arxiv"] = None
    assert any(t["divergence"] for t in bad["terms"])
    with pytest.raises(ContractViolation, match="divergence must be null"):
        market_contracts.validate("market_hype.json", bad)


def test_stale_source_cannot_headline_the_movers_board(hype):
    bad = _corrupt(hype)
    assert bad["headline"]["top_riser"]["source"] == "gdelt"
    bad["stale_sources"] = ["gdelt"]
    for t in bad["terms"]:
        t["yoy"]["gdelt"] = None
        t["divergence"] = None
    with pytest.raises(ContractViolation, match="headline.top_riser.source"):
        market_contracts.validate("market_hype.json", bad)


def test_meta_market_stale_sources_validated(outputs):
    meta = copy.deepcopy(outputs["meta.json"])
    meta["sources"]["market"] = {"fetched_at": GENERATED_AT, "term_count": 6,
                                 "backfill_remaining": 3}
    contracts.validate("meta.json", meta)            # pre-freshness block
    meta["sources"]["market"]["stale_sources"] = ["hn", "edgar"]
    contracts.validate("meta.json", meta)
    meta["sources"]["market"]["stale_sources"] = ["reddit"]
    with pytest.raises(ContractViolation,
                       match="meta.sources.market.stale_sources"):
        contracts.validate("meta.json", meta)
