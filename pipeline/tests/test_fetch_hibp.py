"""HIBP feed parsing: field extraction, defaults, malformed entries —
plus the fetcher's bounded-retry discipline."""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline.fetch_hibp import fetch_hibp, load_hibp_file, parse_hibp

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


# ------------------------------------------------------------- bounded retry

class FakeResponse:
    def __init__(self, payload=None, status_code=200):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    """Serves a scripted sequence of responses (a scripted exception is
    raised instead of returned) and records every request — the
    test_fetch_nvd FakeSession pattern."""

    def __init__(self, script):
        self.script = list(script)
        self.requests = []

    def get(self, url, headers=None, timeout=None):
        self.requests.append({"url": url, "headers": dict(headers or {})})
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_fetch_retries_transient_failures_then_succeeds():
    session = FakeSession([FakeResponse(status_code=503),
                           OSError("connection reset"),
                           FakeResponse(payload=[{"Name": "Acme"}])])
    sleeps = []
    data = fetch_hibp(session=session, sleep=sleeps.append,
                      log=lambda m: None)
    assert data.breach_count == 1
    assert len(session.requests) == 3
    assert len(sleeps) == 2  # backoff between attempts, none after success


def test_fetch_persistent_failure_raises_after_bounded_attempts():
    session = FakeSession([FakeResponse(status_code=503)] * 5)
    with pytest.raises(RuntimeError, match="HTTP 503"):
        fetch_hibp(session=session, sleep=lambda s: None,
                   log=lambda m: None)
    assert len(session.requests) == 3  # bounded: never a fourth attempt


def test_fetch_non_retryable_status_raises_immediately():
    session = FakeSession([FakeResponse(status_code=404)] * 3)
    with pytest.raises(RuntimeError, match="HTTP 404"):
        fetch_hibp(session=session, sleep=lambda s: None,
                   log=lambda m: None)
    assert len(session.requests) == 1  # 404 is not a blip; no retry
