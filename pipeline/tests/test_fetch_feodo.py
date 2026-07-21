"""Unit tests for the Feodo Tracker C2 blocklist fetcher/parser
(pipeline/fetch_feodo.py)."""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline import fetch_feodo as ff

FIX = Path(__file__).parent / "fixtures" / "feodo_c2.json"


def _c2(ip="203.0.113.7", **kw):
    rec = {
        "ip_address": ip,
        "port": 443,
        "status": "online",
        "hostname": None,
        "as_number": 64496,
        "as_name": "EXAMPLE-AS",
        "country": "US",
        "first_seen": "2025-12-30 13:56:31",
        "last_online": "2026-03-12",
        "malware": "QakBot",
    }
    rec.update(kw)
    return rec


# ---------------------------------------------------------------- parse

def test_parse_reads_all_tracked_fields():
    snap = ff.parse_blocklist([_c2()])
    (e,) = snap.entries
    assert e.ip == "203.0.113.7"
    assert e.port == 443
    assert e.status == "online" and e.online is True
    assert e.family == "QakBot"
    assert e.first_seen == "2025-12-30"  # date part only
    assert e.country == "US"
    assert e.as_name == "EXAMPLE-AS"
    assert e.as_number == 64496
    assert snap.entry_count == 1 and snap.online_count == 1


def test_parse_offline_status_and_null_optionals():
    e, = ff.parse_blocklist([_c2(status="offline", country=None,
                                 as_name=None, as_number=None,
                                 hostname=None)]).entries
    assert e.online is False
    assert e.country == "Unknown"
    assert e.as_name == "Unknown"
    assert e.as_number is None


def test_parse_empty_list_is_a_valid_snapshot():
    # THE key difference from the roster fetcher: the tracker's documented
    # post-takedown state is an empty array, and recording that zero is the
    # module's job — an empty document must parse, never raise.
    snap = ff.parse_blocklist([])
    assert snap.entry_count == 0
    assert snap.online_count == 0
    assert snap.entries == []


def test_parse_dedupes_ip_port_pairs():
    snap = ff.parse_blocklist([_c2(), _c2(malware="Emotet"),
                               _c2(port=8080)])
    assert snap.entry_count == 2  # same ip:443 collapsed, ip:8080 kept
    assert [e.family for e in snap.entries] == ["QakBot", "QakBot"]


@pytest.mark.parametrize("doc", [
    {"entries": []},          # not a list
    "[]",                     # not parsed JSON
    [42],                     # entry is not an object
    [_c2(ip_address="")],     # missing ip
    [_c2(ip_address=None)],
    [_c2(port="443")],        # unusable port
    [_c2(port=True)],
    [_c2(status="sinkholed")],  # unrecognized status must be looked at
    [_c2(status="")],
    [_c2(malware="")],        # missing family
    [_c2(malware=None)],
    [_c2(first_seen="soon")],  # unparseable first_seen (the age chart)
    [_c2(first_seen=None)],
    [_c2(first_seen="2026-3-4 00:00:00")],
])
def test_parse_rejects_malformed_documents_and_entries(doc):
    with pytest.raises(ValueError):
        ff.parse_blocklist(doc)


def test_fixture_file_parses():
    snap = ff.load_blocklist_file(FIX)
    assert snap.entry_count == 6
    assert snap.online_count == 2
    assert sorted({e.family for e in snap.entries}) == \
        ["Emotet", "Pikabot", "QakBot"]


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
    payload = [_c2()]
    calls = {"n": 0}
    slept = []

    class Session:
        def get(self, url, timeout=None, headers=None):
            calls["n"] += 1
            assert headers["User-Agent"].startswith("CyberMon/")
            return _Resp(503 if calls["n"] == 1 else 200, payload)

    snap = ff.fetch_blocklist(session=Session(), sleep=slept.append,
                              log=lambda *_: None)
    assert snap.entry_count == 1
    assert calls["n"] == 2 and slept  # retried once, backed off


def test_fetch_exhausts_retries_and_raises():
    class Session:
        def get(self, url, timeout=None, headers=None):
            return _Resp(503, [])

    with pytest.raises(OSError):
        ff.fetch_blocklist(session=Session(), sleep=lambda *_: None,
                           log=lambda *_: None)
