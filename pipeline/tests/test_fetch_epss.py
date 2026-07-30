"""EPSS feed parsing plus the fetcher's bounded-retry discipline."""
from __future__ import annotations

import gzip

import pytest

from pipeline.fetch_epss import fetch_epss

_CSV = ("#model_version:v2026.06.15,score_date:2026-07-29T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2026-0001,0.42,0.97\n")


class FakeResponse:
    def __init__(self, payload: str = _CSV, status_code: int = 200):
        self.status_code = status_code
        self.content = gzip.compress(payload.encode("utf-8"))

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    """Serves a scripted sequence of responses (a scripted exception is
    raised instead of returned) and records every request — the
    test_fetch_hibp FakeSession pattern."""

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
                           FakeResponse()])
    sleeps = []
    data = fetch_epss(session=session, sleep=sleeps.append,
                      log=lambda m: None)
    assert data.row_count == 1
    assert data.score_date == "2026-07-29"
    assert data.scores["CVE-2026-0001"] == pytest.approx(0.42)
    assert len(session.requests) == 3
    assert len(sleeps) == 2  # backoff between attempts, none after success


def test_fetch_persistent_failure_raises_after_bounded_attempts():
    session = FakeSession([FakeResponse(status_code=503)] * 5)
    with pytest.raises(RuntimeError, match="HTTP 503"):
        fetch_epss(session=session, sleep=lambda s: None,
                   log=lambda m: None)
    assert len(session.requests) == 3  # bounded: never a fourth attempt


def test_fetch_non_retryable_status_raises_immediately():
    session = FakeSession([FakeResponse(status_code=404)] * 3)
    with pytest.raises(RuntimeError, match="HTTP 404"):
        fetch_epss(session=session, sleep=lambda s: None,
                   log=lambda m: None)
    assert len(session.requests) == 1  # 404 is not a blip; no retry


def test_connection_reset_is_retried_then_reraised():
    """The 2026-07-30 nightly failure mode: the origin reset the connection
    mid-handshake. Unretried, that single blip aborted the whole run."""
    resets = [ConnectionResetError(104, "Connection reset by peer")] * 3
    session = FakeSession(resets)
    with pytest.raises(ConnectionResetError):
        fetch_epss(session=session, sleep=lambda s: None,
                   log=lambda m: None)
    assert len(session.requests) == 3  # retried, not fatal on first reset
