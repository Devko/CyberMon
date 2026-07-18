"""Unit tests for the CVE.org organization-roster fetcher/parser
(pipeline/fetch_cna_roster.py)."""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline import fetch_cna_roster as fr

FIX = Path(__file__).parent / "fixtures" / "cna_roster.json"


def _org(short="acme", **kw):
    rec = {
        "shortName": short,
        "cnaID": "CNA-2020-0001",
        "organizationName": "Acme Corp",
        "scope": "Acme products.",
        "country": "USA",
        "CNA": {"isRoot": False,
                "root": {"shortName": "n/a", "organizationName": "n/a"},
                "type": ["Vendor"],
                "TLR": {"shortName": "mitre", "organizationName": "MITRE"},
                "roles": [{"role": "CNA", "helpText": ""}]},
    }
    rec.update(kw)
    return rec


# ---------------------------------------------------------------- parse

def test_parse_reads_all_tracked_fields():
    snap = fr.parse_roster([_org()])
    (o,) = snap.orgs
    assert o.short_name == "acme"
    assert o.org_name == "Acme Corp"
    assert o.cna_id == "CNA-2020-0001"
    assert o.country == "USA"
    assert o.scope == "Acme products."
    assert o.types == ("Vendor",)
    assert o.roles == ("CNA",)
    assert o.tlr == "mitre"
    assert o.root == "n/a"
    assert o.is_root is False
    assert o.type_label == "Vendor"


def test_parse_multi_type_is_sorted_and_labelled():
    o, = fr.parse_roster([_org(CNA={"type": ["Vendor", "Open Source"],
                                    "TLR": {"shortName": "mitre"},
                                    "root": {"shortName": "n/a"},
                                    "roles": [], "isRoot": False})]).orgs
    assert o.types == ("Open Source", "Vendor")  # sorted
    assert o.type_label == "Open Source + Vendor"


def test_parse_defaults_missing_country_and_types():
    o, = fr.parse_roster([_org(country="", CNA={})]).orgs
    assert o.country == "Unknown"
    assert o.types == ()
    assert o.type_label == "N/A"
    assert o.tlr == "n/a" and o.root == "n/a" and o.is_root is False


def test_parse_reads_root_and_tlr_and_isroot():
    o, = fr.parse_roster([_org(CNA={
        "type": ["Vendor"], "isRoot": True,
        "TLR": {"shortName": "CISA"},
        "root": {"shortName": "icscert"},
        "roles": [{"role": "CNA"}, {"role": "Root"}]})]).orgs
    assert o.tlr == "CISA" and o.root == "icscert" and o.is_root is True
    assert o.roles == ("CNA", "Root")


def test_parse_skips_unkeyable_and_duplicate_records():
    snap = fr.parse_roster([_org("a"), {"organizationName": "no short"},
                            _org("a"), _org("b")])
    assert [o.short_name for o in snap.orgs] == ["a", "b"]
    assert snap.org_count == 2


def test_parse_rejects_non_list_or_empty_document():
    with pytest.raises(ValueError):
        fr.parse_roster({"orgs": []})
    with pytest.raises(ValueError):
        fr.parse_roster([])
    with pytest.raises(ValueError):
        fr.parse_roster([{"organizationName": "unkeyable"}])  # nothing keyable


def test_fixture_file_parses():
    snap = fr.load_roster_file(FIX)
    assert snap.org_count == 8
    shorts = {o.short_name for o in snap.orgs}
    assert {"adobe", "redhat", "curl", "hackerone"} <= shorts


# ---------------------------------------------------------------- fetch/retry

class _Resp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise OSError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def test_fetch_retries_transient_then_succeeds():
    payload = [_org("a")]
    calls = {"n": 0}
    slept = []

    class Session:
        def get(self, url, timeout=None, headers=None):
            calls["n"] += 1
            return _Resp(503 if calls["n"] == 1 else 200, payload)

    snap = fr.fetch_roster(session=Session(), sleep=slept.append,
                           log=lambda *_: None)
    assert snap.org_count == 1
    assert calls["n"] == 2 and slept  # retried once, backed off


def test_fetch_exhausts_retries_and_raises():
    class Session:
        def get(self, url, timeout=None, headers=None):
            return _Resp(503, [])

    with pytest.raises(OSError):
        fr.fetch_roster(session=Session(), sleep=lambda *_: None,
                        log=lambda *_: None)
