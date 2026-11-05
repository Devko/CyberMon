"""The Alias Graph's data: the naming-scheme rule table (naming_schemes),
alias_graph.json's builder (naming_metrics.build_alias_graph), its contract
(naming_contracts) and the offline pipeline run that emits it."""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest

# contracts must load before naming_contracts (registration order — see the
# note in test_naming_contracts.py).
from pipeline import (
    contracts,
    naming_contracts,  # noqa: F401
)
from pipeline import naming_schemes as ns
from pipeline.__main__ import main
from pipeline.contracts import ContractViolation
from pipeline.naming_metrics import build_alias_graph
from pipeline.tests import claims_support

GENERATED_AT = "2026-11-05T00:00:00Z"


# ------------------------------------------------------------------ the rules

@pytest.mark.parametrize("name,scheme", [
    # Microsoft: families, Storm-/DEV- designators, retired element names
    ("Forest Blizzard", "microsoft"), ("TWILL TYPHOON", "microsoft"),
    ("Octo Tempest", "microsoft"), ("Plaid Rain", "microsoft"),
    ("Zigzag Hail", "microsoft"), ("Marbled Dust", "microsoft"),
    ("Canvas Cyclone", "microsoft"), ("Viridian Vortex", "microsoft"),
    ("Storm-0587", "microsoft"), ("DEV-0537", "microsoft"),
    ("DEV-500", "microsoft"), ("STRONTIUM", "microsoft"),
    ("Krypton", "microsoft"), ("NICKEL", "microsoft"),
    # CrowdStrike: one adjective + animal, any case
    ("Fancy Bear", "crowdstrike"), ("PUNK SPIDER", "crowdstrike"),
    ("Velvet Chollima", "crowdstrike"), ("Mythic Leopard", "crowdstrike"),
    ("Cosmic Wolf", "crowdstrike"), ("Umbral Bison", "crowdstrike"),
    # Mandiant: exact case
    ("APT28", "mandiant"), ("FIN7", "mandiant"), ("UNC2452", "mandiant"),
    ("TEMP.Veles", "mandiant"),
    # Secureworks: capitals only, plus the retired numeric form
    ("IRON TWILIGHT", "secureworks"), ("NICKEL ACADEMY", "secureworks"),
    ("COPPER FIELDSTONE", "secureworks"), ("TG-3390", "secureworks"),
    ("Threat Group-4127", "secureworks"), ("Threat Group 2889", "secureworks"),
    # Unit 42
    ("STATELY TAURUS", "unit42"), ("Howling Scorpius", "unit42"),
    ("CL-STA-0969", "unit42"), ("TGR-STA-0001", "unit42"),
    # the rest
    ("TA453", "proofpoint"), ("UNK_SmudgedSerpent", "proofpoint"),
    ("EARTH PRETA", "trendmicro"), ("Water Galura", "trendmicro"),
    ("SHADOW-WATER-058", "trendmicro"), ("ITG23", "ibm"),
    ("HIVE0154", "ibm"), ("Hive0065", "ibm"), ("TAG-22", "recordedfuture"),
    ("NIMBUS MANTICORE", "checkpoint"),
])
def test_documented_forms_classify(name, scheme):
    c = ns.classify(name)
    assert (c.status, c.scheme) == (ns.CLASSIFIED, scheme), (name, c)


@pytest.mark.parametrize("name", [
    # free-form vendor names and undocumented schemes
    "Sednit", "Turla", "Lazarus Group", "ELECTRUM", "XENOTIME", "ELBRUS",
    "Pawn Storm", "SolarStorm", "MONSOON", "RedDelta", "Blue Kitsune",
    "UAC-0056", "APT-C-23", "APT-Q-98", "T-APT-17", "Group 72", "Ashen Lepus",
    # near misses of a documented form
    "KungFu Kittens", "Siamesekitten", "Cobalt Group", "Cobalt Gang",
    "apt28", "Grizzly Fixture", "Storm-12", "FIXTURE SPIDER (added in 2.0)",
])
def test_names_without_a_rule_stay_unclassified(name):
    c = ns.classify(name)
    assert (c.status, c.scheme) == (ns.NO_RULE, None), (name, c)


def test_two_schemes_forms_are_ambiguous_never_guessed():
    c = ns.classify("VOID MANTICORE")
    assert c.status == ns.AMBIGUOUS and c.scheme is None
    assert set(c.candidates) == {"trendmicro", "checkpoint"}


@pytest.mark.parametrize("name", ["Iron Tiger", "Fox Kitten", "Bleeding Bear",
                                  "  fox kitten "])
def test_cited_exceptions_are_not_counted_under_the_form(name):
    c = ns.classify(name)
    assert c.status == ns.EXCEPTION and c.scheme is None
    assert c.candidates == ("crowdstrike",)


def test_rule_table_is_versioned_and_every_rule_cites_its_documentation():
    assert isinstance(ns.RULES_VERSION, int) and ns.RULES_VERSION >= 1
    assert len(set(ns.SCHEME_IDS)) == len(ns.SCHEME_IDS)
    assert f"  {ns.RULES_VERSION} (" in ns.__doc__, \
        "RULES_VERSION changed without a changelog line"
    for s in ns.SCHEMES:
        assert s.doc.startswith("https://") and s.patterns and s.forms
    # Every pattern line sits under a comment block that carries a URL.
    src = Path(ns.__file__).read_text(encoding="utf-8")
    body = src[src.index("SCHEMES: tuple"):src.index("SCHEME_IDS =")]
    for m in re.finditer(r"\n(\s+)_full\(", body):
        before = body[:m.start()]
        block = before[before.rindex("patterns=("):]
        assert "https://" in block, body[m.start():m.start() + 60]
    for name, (scheme, source) in ns.EXCEPTIONS.items():
        assert name == name.casefold() and scheme in ns.SCHEME_IDS and source
        # an exception is only ever needed for a name that has the form
        assert scheme in ns.matching_schemes(name)


def test_secureworks_prefix_rule_is_case_sensitive():
    # Trend Micro's "Iron Tiger" must not read as Secureworks' IRON prefix.
    assert "secureworks" not in ns.matching_schemes("Iron Tiger")
    assert ns.matching_schemes("IRON TIGER") == ("crowdstrike", "secureworks")


# ---------------------------------------------------------------- the builder

def _naming(groups):
    return {"version": "20.0", "released": "2026-10-13",
            "groups": [{"name": n, "aliases": a, "alt_count": len(a)}
                       for n, a in groups]}


def test_builder_counts_and_reconciles():
    obj = build_alias_graph(_naming([
        ("APT28", ["Fancy Bear", "STRONTIUM", "Forest Blizzard", "Sofacy"]),
        ("VOID MANTICORE", ["Red Sandstorm", "Karma"]),
        ("Cleaver", ["TG-2889"]),
        ("Inception", ["Cloud Atlas"]),
    ]), GENERATED_AT)
    contracts.validate("alias_graph.json", obj)
    apt28 = obj["actors"][0]
    assert apt28["schemes"] == ["microsoft", "crowdstrike", "mandiant"]
    assert apt28["names"][0]["name"] == "APT28"
    assert obj["actors"][1]["names"][0] == {
        "name": "VOID MANTICORE", "status": "ambiguous", "scheme": None,
        "candidates": ["trendmicro", "checkpoint"]}
    assert obj["actors"][3]["schemes"] == []
    assert obj["coverage"] == {"names": 12, "classified": 6, "no_rule": 5,
                               "ambiguous": 1, "exception": 0}
    assert obj["headline"] == {"actors": 4, "placed": 3, "two_plus": 1,
                               "three_plus": 1, "max_schemes": 3}
    ms = next(s for s in obj["schemes"] if s["id"] == "microsoft")
    assert (ms["actors"], ms["names"]) == (2, 3)   # one group, two names
    assert [s["id"] for s in obj["schemes"]] == list(ns.SCHEME_IDS)
    assert obj["rules_version"] == ns.RULES_VERSION


def test_builder_empty_board_has_null_headline():
    obj = build_alias_graph(_naming([]), GENERATED_AT)
    contracts.validate("alias_graph.json", obj)
    assert obj["actors"] == [] and obj["headline"] is None
    assert obj["coverage"]["names"] == 0


# --------------------------------------------------------------- the contract

def _valid():
    return build_alias_graph(_naming([
        ("APT28", ["Fancy Bear", "Forest Blizzard", "Sofacy"]),
        ("Fox Kitten", ["Pioneer Kitten", "UNC757"]),
    ]), GENERATED_AT)


@pytest.mark.parametrize("mutate,match", [
    (lambda o: o.__setitem__("rules_version", 0), "rules_version"),
    (lambda o: o["schemes"].reverse(), "schemes"),
    (lambda o: o["schemes"][0].__setitem__("label", "MS"), "label"),
    (lambda o: o["schemes"][0].__setitem__("actors", 9), "count"),
    (lambda o: o["actors"][0]["names"][3].update(status="classified",
                                                 scheme="mandiant"),
     "classifies"),
    (lambda o: o["actors"][1]["names"][0].pop("candidates"), "candidates"),
    (lambda o: o["actors"][0]["names"].reverse(), "ATT&CK name"),
    (lambda o: o["actors"][0]["schemes"].reverse(), "schemes"),
    (lambda o: o["actors"].append(copy.deepcopy(o["actors"][0])), "duplicate"),
    (lambda o: o["coverage"].__setitem__("classified", 1), "coverage"),
    (lambda o: o["headline"].__setitem__("placed", 9), "headline"),
    (lambda o: o["exceptions"].pop(), "exceptions"),
])
def test_contract_violations_fail_loudly(mutate, match):
    obj = _valid()
    contracts.validate("alias_graph.json", obj)
    mutate(obj)
    with pytest.raises(ContractViolation, match=match):
        contracts.validate("alias_graph.json", obj)


# ----------------------------------------------------------------------- e2e

def test_offline_pipeline_run_emits_valid_alias_graph(tmp_path, capsys):
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    obj = json.loads((tmp_path / "alias_graph.json").read_text("utf-8"))
    naming = json.loads((tmp_path / "naming.json").read_text("utf-8"))
    contracts.validate("alias_graph.json", obj)
    assert obj["generated_at"] == naming["generated_at"]
    assert [a["name"] for a in obj["actors"]] == \
        [g["name"] for g in naming["groups"]]
    assert obj["actors"][0]["schemes"] == ["crowdstrike"]   # FIXTURE BEAR


def test_committed_edition_matches_its_naming_board():
    """The committed alias_graph.json is the committed naming.json's board
    under today's rules — a stale or hand-edited file fails here."""
    path = claims_support.DATA_DIR / "alias_graph.json"
    naming_path = claims_support.DATA_DIR / "naming.json"
    if not path.exists() or not naming_path.exists():
        pytest.skip("no committed alias_graph.json")
    obj = json.loads(path.read_text("utf-8"))
    naming = json.loads(naming_path.read_text("utf-8"))
    contracts.validate("alias_graph.json", obj)
    assert obj == build_alias_graph(naming, obj["generated_at"])
    assert len(path.read_bytes()) < 200_000
