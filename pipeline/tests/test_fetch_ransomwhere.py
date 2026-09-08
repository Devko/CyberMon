"""fetch_ransomwhere network discipline: bounded retry, loud failure.

Export parsing itself is covered in test_extortion_metrics; this file only
exercises the retry loop around the one-shot HTTP fetch.
"""
from __future__ import annotations

import pytest

from pipeline.fetch_ransomwhere import (EPOCH_MIN, fetch_ransomwhere,
                                        parse_ransomwhere)

_EXPORT = {"result": [{"address": "1FX4", "family": "Maui",
                       "blockchain": "bitcoin", "transactions": []}]}


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
    session = FakeSession([FakeResponse(status_code=429),
                           OSError("connection reset"),
                           FakeResponse(payload=_EXPORT)])
    sleeps = []
    data = fetch_ransomwhere(session=session, sleep=sleeps.append,
                             log=lambda m: None)
    assert data.address_count == 1
    assert len(session.requests) == 3
    assert len(sleeps) == 2  # backoff between attempts, none after success


def test_fetch_persistent_status_failure_raises_after_bounded_attempts():
    session = FakeSession([FakeResponse(status_code=503)] * 5)
    with pytest.raises(RuntimeError, match="HTTP 503"):
        fetch_ransomwhere(session=session, sleep=lambda s: None,
                          log=lambda m: None)
    assert len(session.requests) == 3  # bounded: never a fourth attempt


def test_fetch_persistent_connection_failure_raises_after_bounded_attempts():
    session = FakeSession([OSError("boom")] * 5)
    with pytest.raises(OSError, match="boom"):
        fetch_ransomwhere(session=session, sleep=lambda s: None,
                          log=lambda m: None)
    assert len(session.requests) == 3


# -------------------------------------------------- transaction time bounds

def _tx(**overrides):
    base = {"hash": "h", "time": 1716192000, "amount": 1, "amountUSD": 1.0}
    base.update(overrides)
    return base


def _doc(tx):
    return {"result": [{"address": "1FX4", "family": "Maui",
                        "blockchain": "bitcoin", "transactions": [tx]}]}


def test_parse_rejects_millisecond_timestamps_inside_the_parser():
    # A time in milliseconds passed the old parser and blew up in the
    # date arithmetic of the ledger builder — outside the degrade handler
    # in __main__. Now it is a parse error like every other malformed field.
    with pytest.raises(ValueError, match="plausible epoch seconds"):
        parse_ransomwhere(_doc(_tx(time=1716192000000)))


def test_parse_time_bounds_are_2008_to_tomorrow():
    import time as _time

    parse_ransomwhere(_doc(_tx(time=EPOCH_MIN)))            # 2008-01-01
    now = int(_time.time())
    parse_ransomwhere(_doc(_tx(time=now + 3600)))           # clock skew
    for bad in (EPOCH_MIN - 1, now + 2 * 86400):
        with pytest.raises(ValueError, match="plausible epoch seconds"):
            parse_ransomwhere(_doc(_tx(time=bad)))


def test_fetch_surfaces_bad_timestamps_as_the_value_error_main_degrades_on():
    session = FakeSession([FakeResponse(payload=_doc(_tx(time=1716192000000)))])
    with pytest.raises(ValueError, match="plausible epoch seconds"):
        fetch_ransomwhere(session=session, sleep=lambda s: None,
                          log=lambda m: None)
