"""pipeline.fetch_http: the one bounded-retry GET every fetcher shares."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from pipeline import fetch_http as http
from pipeline.fetch_http import USER_AGENT, get_with_retry, retry_after_seconds


class FakeResponse:
    def __init__(self, status_code=200, headers=None, body=b"ok"):
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.content = body
        self.closed = False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    """Scripted responses (an Exception entry is raised instead); records
    every keyword the helper passed so header/param discipline is
    observable."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _quiet(_):
    pass


# ------------------------------------------------------------- the ladder

def test_transient_statuses_and_connection_errors_are_retried():
    session = FakeSession([FakeResponse(503), OSError("reset"),
                           FakeResponse(200)])
    sleeps, logs = [], []
    resp = get_with_retry(session, "https://x/", label="t",
                          sleep=sleeps.append, log=logs.append)
    assert resp.status_code == 200
    assert sleeps == [15.0, 30.0]  # linear backoff, none after success
    assert len(logs) == 2 and all(m.startswith("  t: ") for m in logs)
    assert "HTTP 503" in logs[0] and "request failed" in logs[1]
    assert "(attempt 1/3)" in logs[0] and "(attempt 2/3)" in logs[1]


def test_final_status_failure_raises_via_raise_for_status():
    session = FakeSession([FakeResponse(503)] * 5)
    with pytest.raises(RuntimeError, match="HTTP 503"):
        get_with_retry(session, "https://x/", label="t",
                       sleep=_quiet, log=_quiet)
    assert len(session.calls) == 3  # bounded: never a fourth attempt


def test_final_connection_failure_reraises_the_exception():
    session = FakeSession([ConnectionResetError(104, "reset")] * 3)
    with pytest.raises(ConnectionResetError):
        get_with_retry(session, "https://x/", label="t",
                       sleep=_quiet, log=_quiet)
    assert len(session.calls) == 3


def test_non_retryable_status_raises_immediately():
    session = FakeSession([FakeResponse(404)] * 3)
    with pytest.raises(RuntimeError, match="HTTP 404"):
        get_with_retry(session, "https://x/", label="t",
                       sleep=_quiet, log=_quiet)
    assert len(session.calls) == 1


def test_attempts_backoff_and_statuses_are_parameters():
    session = FakeSession([FakeResponse(403), FakeResponse(403),
                           FakeResponse(403), FakeResponse(200)])
    sleeps = []
    resp = get_with_retry(session, "https://x/", label="t", attempts=6,
                          backoff=2.0, retry_statuses={403},
                          sleep=sleeps.append, log=_quiet)
    assert resp.status_code == 200
    assert sleeps == [2.0, 4.0, 6.0]


def test_zero_attempts_is_a_programming_error():
    with pytest.raises(ValueError):
        get_with_retry(FakeSession([]), "https://x/", label="t", attempts=0)


# ---------------------------------------------------------- request shape

def test_user_agent_always_sent_and_extra_headers_merged():
    session = FakeSession([FakeResponse()])
    get_with_retry(session, "https://x/", label="t",
                   headers={"Accept": "application/json"}, timeout=7)
    call = session.calls[0]
    assert call["headers"]["User-Agent"] == USER_AGENT
    assert call["headers"]["Accept"] == "application/json"
    assert call["timeout"] == 7
    assert "params" not in call and "stream" not in call  # only when given


def test_params_and_stream_passed_only_when_given():
    session = FakeSession([FakeResponse()])
    get_with_retry(session, "https://x/", label="t", params={"x": "US"},
                   stream=True)
    call = session.calls[0]
    assert call["params"] == {"x": "US"} and call["stream"] is True


def test_minimal_fake_session_without_params_kwarg_still_works():
    class Minimal:
        def get(self, url, headers=None, timeout=None):
            return FakeResponse()

    assert get_with_retry(Minimal(), "https://x/", label="t").status_code \
        == 200


# ------------------------------------------------------------- Retry-After

def test_retry_after_seconds_is_honoured_over_the_backoff():
    session = FakeSession([FakeResponse(429, {"Retry-After": "42"}),
                           FakeResponse(200)])
    sleeps, logs = [], []
    get_with_retry(session, "https://x/", label="t",
                   sleep=sleeps.append, log=logs.append)
    assert sleeps == [42.0]
    assert "retrying in 42s" in logs[0]


def test_retry_after_http_date_is_honoured_and_capped():
    now = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)
    soon = (now + timedelta(seconds=90)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert retry_after_seconds(FakeResponse(429, {"Retry-After": soon}),
                               now=now) == 90.0
    far = (now + timedelta(hours=2)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert retry_after_seconds(FakeResponse(429, {"Retry-After": far}),
                               now=now) == http.MAX_RETRY_AFTER
    past = (now - timedelta(hours=2)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert retry_after_seconds(FakeResponse(429, {"Retry-After": past}),
                               now=now) == 0.0


def test_retry_after_garbage_or_absent_falls_back_to_backoff():
    assert retry_after_seconds(FakeResponse(429, {"Retry-After": "soon"})) \
        is None
    assert retry_after_seconds(FakeResponse(429, {})) is None
    assert retry_after_seconds(object()) is None  # no .headers at all
    assert retry_after_seconds(FakeResponse(429, {"Retry-After": "9999"})) \
        == http.MAX_RETRY_AFTER


# --------------------------------------------------------- consume / raw

def test_consume_runs_inside_the_ladder_and_its_oserror_is_retried():
    session = FakeSession([FakeResponse(200, body=b"partial"),
                           FakeResponse(200, body=b"whole")])
    seen = []

    def consume(resp):
        seen.append(resp.content)
        if resp.content == b"partial":
            raise ConnectionError("connection broken mid-body")
        return resp.content.decode()

    sleeps = []
    out = get_with_retry(session, "https://x/", label="t", consume=consume,
                         sleep=sleeps.append, log=_quiet)
    assert out == "whole" and seen == [b"partial", b"whole"]
    assert sleeps == [15.0]


def test_consume_oserror_on_the_last_attempt_propagates():
    session = FakeSession([FakeResponse(200)] * 3)

    def consume(resp):
        raise OSError("disk says no")

    with pytest.raises(OSError, match="disk says no"):
        get_with_retry(session, "https://x/", label="t", consume=consume,
                       sleep=_quiet, log=_quiet)
    assert len(session.calls) == 3


def test_consume_non_oserror_propagates_without_retry():
    session = FakeSession([FakeResponse(200)] * 3)

    def consume(resp):
        raise ValueError("bad payload")

    with pytest.raises(ValueError):
        get_with_retry(session, "https://x/", label="t", consume=consume,
                       sleep=_quiet, log=_quiet)
    assert len(session.calls) == 1


def test_raise_for_status_false_returns_the_final_response_unchecked():
    session = FakeSession([FakeResponse(503), FakeResponse(404)])
    resp = get_with_retry(session, "https://x/", label="t",
                          raise_for_status=False, sleep=_quiet, log=_quiet)
    assert resp.status_code == 404  # non-retryable: returned, not raised
    assert len(session.calls) == 2

    exhausted = FakeSession([FakeResponse(503)] * 3)
    resp = get_with_retry(exhausted, "https://x/", label="t",
                          raise_for_status=False, sleep=_quiet, log=_quiet)
    assert resp.status_code == 503  # ladder spent: still the caller's call
