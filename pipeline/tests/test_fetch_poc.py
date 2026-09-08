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


# ------------------------------------------------------------ cache

class _Resp:
    def __init__(self, body: bytes):
        self.status_code = 200
        self.content = body
        self.headers = {}

    def raise_for_status(self):
        pass


class _Session:
    """Serves one body per call; a call past the script is a failure."""

    def __init__(self, *bodies: bytes):
        self.bodies = list(bodies)
        self.calls = 0

    def get(self, url, **_kwargs):
        self.calls += 1
        if not self.bodies:
            raise AssertionError("unexpected download: cache not reused")
        return _Resp(self.bodies.pop(0))


def _edb_body() -> bytes:
    return (FIXTURES / "exploitdb.csv").read_bytes()


def test_cached_body_reuses_a_parsed_download(tmp_path):
    from pipeline.fetch_poc import _cached_body, _parse_edb_body

    session = _Session(_edb_body())
    first = _cached_body(tmp_path, "files_exploits.csv", "https://x/",
                         session, lambda _s: None, lambda _m: None,
                         parse=_parse_edb_body)
    assert session.calls == 1
    cached = list((tmp_path / "poc").glob("*_files_exploits.csv"))
    assert len(cached) == 1 and not cached[0].name.endswith(".part")
    # Second call: served from today's cache, no download at all.
    again = _cached_body(tmp_path, "files_exploits.csv", "https://x/",
                         _Session(), lambda _s: None, lambda _m: None,
                         parse=_parse_edb_body)
    assert again == first


def test_cached_body_never_caches_a_body_that_fails_to_parse(tmp_path):
    from pipeline.fetch_poc import _cached_body, _parse_edb_body

    session = _Session(b"<html>503 upstream sad</html>", _edb_body())
    with pytest.raises(ValueError):
        _cached_body(tmp_path, "files_exploits.csv", "https://x/", session,
                     lambda _s: None, lambda _m: None,
                     parse=_parse_edb_body)
    poc_dir = tmp_path / "poc"
    assert not poc_dir.exists() or not list(poc_dir.iterdir())
    # the retry downloads again rather than re-reading the garbage
    _cached_body(tmp_path, "files_exploits.csv", "https://x/", session,
                 lambda _s: None, lambda _m: None, parse=_parse_edb_body)
    assert session.calls == 2


def test_cached_body_sweeps_stale_part_files_and_old_days(tmp_path):
    from pipeline.fetch_poc import _cached_body, _parse_edb_body

    poc_dir = tmp_path / "poc"
    poc_dir.mkdir()
    (poc_dir / "2020-01-01_files_exploits.csv.part").write_bytes(b"crash")
    (poc_dir / "2020-01-01_files_exploits.csv").write_bytes(b"old day")
    (poc_dir / "2020-01-01_other.csv").write_bytes(b"keep")
    _cached_body(tmp_path, "files_exploits.csv", "https://x/",
                 _Session(_edb_body()), lambda _s: None, lambda _m: None,
                 parse=_parse_edb_body)
    names = sorted(p.name for p in poc_dir.iterdir())
    assert "2020-01-01_files_exploits.csv.part" not in names
    assert "2020-01-01_files_exploits.csv" not in names
    assert "2020-01-01_other.csv" in names
    assert sum(n.endswith("_files_exploits.csv") for n in names) == 1


def test_fetch_poc_assembles_from_three_cached_sources(tmp_path):
    from pipeline.fetch_poc import fetch_poc

    session = _Session(_edb_body(),
                       (FIXTURES / "metasploit.json").read_bytes(),
                       (FIXTURES / "nuclei_cves.json").read_bytes())
    poc = fetch_poc(tmp_path, session=session, sleep=lambda _s: None,
                    log=lambda _m: None)
    assert session.calls == 3
    assert poc.first_poc_dates["CVE-2023-0001"] == "2023-01-10"
    assert poc.nuclei_templates == 3
    # A second run the same day is entirely served from the cache.
    poc2 = fetch_poc(tmp_path, session=_Session(), sleep=lambda _s: None,
                     log=lambda _m: None)
    assert poc2 == poc
