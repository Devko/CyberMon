"""Unit tests for the PoC-corpora fetch/parse layer (pipeline/fetch_poc.py)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.fetch_poc import (MIN_DATE, _cve_ids, _clean_date,
                                load_poc_files, parse_exploitdb,
                                parse_metasploit, parse_nuclei)

FIXTURES = Path(__file__).parent / "fixtures"


# ------------------------------------------------------------ helpers

def test_cve_ids_normalizes_dedupes_and_keeps_order():
    ids = _cve_ids("cve-2023-0001;OSVDB-1;CVE-2024-12345;CVE-2023-0001")
    assert ids == ["CVE-2023-0001", "CVE-2024-12345"]


def test_cve_ids_requires_at_least_four_digits():
    assert _cve_ids("CVE-2023-1") == []
    assert _cve_ids("CVE-2023-12345678") == ["CVE-2023-12345678"]


def test_clean_date_rejects_placeholders_and_junk():
    assert _clean_date("1900-01-01") is None  # Metasploit's "unknown"
    assert _clean_date("not-a-date") is None
    assert _clean_date(None) is None
    assert _clean_date("2023-05-01") == "2023-05-01"
    # timestamp precision is truncated to the day
    assert _clean_date("2023-05-01T10:00:00Z") == "2023-05-01"
    assert MIN_DATE == "1988-01-01"


# ------------------------------------------------------------ Exploit-DB

def test_parse_exploitdb_earliest_date_wins_per_cve():
    dates, ids, total, with_cve = parse_exploitdb(
        (FIXTURES / "exploitdb.csv").read_text(encoding="utf-8"))
    # id=1 (2023-01-10) beats the id=8 duplicate (2023-03-01)
    assert dates["CVE-2023-0001"] == "2023-01-10"
    assert total == 8 and with_cve == 7  # id=5 carries no CVE
    # the multi-CVE row dates both of its ids
    assert dates["CVE-2024-0002"] == dates["CVE-2024-0004"] == "2024-08-03"
    # lowercase code normalized
    assert "CVE-2024-0005" in ids


def test_parse_exploitdb_fails_loudly_on_zero_cve_rows():
    csv_text = ("id,file,description,date_published,codes\n"
                "1,x,no cve here,2020-01-01,EDB-1\n")
    with pytest.raises(ValueError, match="zero CVE-linked rows"):
        parse_exploitdb(csv_text)


# ------------------------------------------------------------ Metasploit

def test_parse_metasploit_placeholder_dates_cover_but_never_date():
    obj = json.loads((FIXTURES / "metasploit.json")
                     .read_text(encoding="utf-8"))
    dates, ids, total, with_cve = parse_metasploit(obj)
    assert total == 4 and with_cve == 3
    # 1900-01-01 module: its CVE is covered but carries no date
    assert "CVE-2023-0003" in ids
    assert "CVE-2023-0003" not in dates
    assert dates["CVE-2012-0002"] == "2012-06-05"


def test_parse_metasploit_fails_loudly_without_cves():
    with pytest.raises(ValueError, match="zero CVE-linked modules"):
        parse_metasploit({"m": {"references": ["URL-x"],
                                "disclosure_date": "2020-01-01"}})
    with pytest.raises(ValueError, match="expected a JSON object"):
        parse_metasploit([])


# ------------------------------------------------------------ Nuclei

def test_parse_nuclei_is_lenient_per_line_loud_in_aggregate():
    ids = parse_nuclei((FIXTURES / "nuclei_cves.json")
                       .read_text(encoding="utf-8"))
    # malformed line and ID-less line are skipped, three real ids remain
    assert ids == frozenset({"CVE-2025-0001", "CVE-2024-0005",
                             "CVE-2023-9001"})
    with pytest.raises(ValueError, match="zero CVE ids"):
        parse_nuclei('{"Info": {"Name": "no id"}}\nnot json\n')


# ------------------------------------------------------------ assembly

def test_load_poc_files_assembles_union_and_first_dates():
    poc = load_poc_files(FIXTURES / "exploitdb.csv",
                         FIXTURES / "metasploit.json",
                         FIXTURES / "nuclei_cves.json")
    # union spans all three sources, coverage wider than dating
    assert "CVE-2023-9001" in poc.all_ids       # Nuclei only, undated
    assert "CVE-2023-0003" in poc.all_ids       # MSF placeholder date
    assert "CVE-2023-0003" not in poc.first_poc_dates
    # first PoC = min across dated sources (EDB 2023-01-10 < MSF 2023-01-20)
    assert poc.first_poc_dates["CVE-2023-0001"] == "2023-01-10"
    assert poc.first_poc_dates["CVE-2012-0002"] == "2012-06-05"  # MSF only
    assert poc.nuclei_templates == 3
