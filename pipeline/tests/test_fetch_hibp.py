"""HIBP feed parsing: field extraction, defaults, malformed entries."""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline.fetch_hibp import load_hibp_file, parse_hibp

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_full_entry():
    data = parse_hibp([{
        "Name": "Acme", "BreachDate": "2024-01-10",
        "AddedDate": "2024-03-10T08:00:00Z", "PwnCount": 250000,
        "DataClasses": ["Email addresses", "Passwords"],
        "IsFabricated": False, "IsSpamList": False,
        "IsMalware": False, "IsStealerLog": True,
    }])
    assert data.breach_count == 1
    b = data.breaches[0]
    assert b.name == "Acme"
    assert b.breach_date == "2024-01-10"
    assert b.added_date == "2024-03-10T08:00:00Z"
    assert b.pwn_count == 250000
    assert b.data_classes == ["Email addresses", "Passwords"]
    assert b.is_stealer_log is True
    assert (b.is_fabricated, b.is_spam_list, b.is_malware) == \
        (False, False, False)


def test_parse_minimal_entry_gets_safe_defaults():
    b = parse_hibp([{"Name": "Bare"}]).breaches[0]
    assert b.breach_date == "" and b.added_date == ""
    assert b.pwn_count == 0 and b.data_classes == []
    assert not any([b.is_fabricated, b.is_spam_list,
                    b.is_malware, b.is_stealer_log])


def test_parse_skips_nameless_and_non_dict_entries():
    data = parse_hibp([{"Name": "Real"}, {"Title": "no Name key"},
                       "not a dict", 42, None])
    assert data.breach_count == 1
    assert [b.name for b in data.breaches] == ["Real"]


def test_parse_sanitizes_malformed_values():
    b = parse_hibp([{"Name": "Odd", "PwnCount": True,
                     "DataClasses": ["Email addresses", 7, "", None]}
                    ]).breaches[0]
    assert b.pwn_count == 0  # bools are not counts
    assert b.data_classes == ["Email addresses"]
    b = parse_hibp([{"Name": "Neg", "PwnCount": -5}]).breaches[0]
    assert b.pwn_count == 0
    # Truthy non-bool flags never count as True.
    b = parse_hibp([{"Name": "Flag", "IsFabricated": "yes"}]).breaches[0]
    assert b.is_fabricated is False


def test_parse_rejects_non_array_document():
    with pytest.raises(ValueError):
        parse_hibp({"Name": "not-a-list"})


def test_load_fixture_file():
    data = load_hibp_file(FIXTURES / "hibp_breaches.json")
    assert data.breach_count == 9
    by_name = {b.name: b for b in data.breaches}
    assert by_name["MadeUpLeak"].is_fabricated
    assert by_name["SpamHaul"].is_spam_list and by_name["SpamHaul"].is_malware
    assert by_name["BotnetDump"].is_malware
    assert by_name["StealerBatch"].is_stealer_log
    assert by_name["ImportEraForum"].added_date.startswith("2013-12-05")
