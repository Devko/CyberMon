"""EPSS feed parsing plus the fetcher's bounded-retry discipline."""
from __future__ import annotations

import gzip

import pytest

from pipeline.fetch_epss import fetch_epss, parse_epss

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


# --------------------------------------------------------- parse hardening

def _parse(text: str):
    return parse_epss(text.splitlines())


def test_parse_valid_feed():
    data = _parse(_CSV)
    assert data.model_version == "v2026.06.15"
    assert data.score_date == "2026-07-29"
    assert data.row_count == 1
    assert data.scores == {"CVE-2026-0001": 0.42}
    assert data.percentiles == {"CVE-2026-0001": 0.97}


def test_parse_without_header_comment_is_refused():
    """An HTML error page or a bare CSV would otherwise parse as
    'unknown @ 1970-01-01' and flow into every EPSS-fed module."""
    with pytest.raises(ValueError, match="no '#model_version"):
        _parse("cve,epss,percentile\nCVE-2026-0001,0.42,0.97\n")
    with pytest.raises(ValueError, match="header comment"):
        _parse("<html>503 Service Unavailable</html>\n")
    with pytest.raises(ValueError):
        _parse("")


def test_parse_header_missing_model_version_or_score_date_is_refused():
    with pytest.raises(ValueError, match="lacks model_version"):
        _parse("#score_date:2026-07-29T00:00:00+0000\n"
               "cve,epss,percentile\nCVE-2026-0001,0.42,0.97\n")
    with pytest.raises(ValueError, match="lacks model_version"):
        _parse("#model_version:v2026.06.15\n"
               "cve,epss,percentile\nCVE-2026-0001,0.42,0.97\n")
    with pytest.raises(ValueError, match="lacks model_version"):
        _parse("#model_version:,score_date:\n"
               "cve,epss,percentile\nCVE-2026-0001,0.42,0.97\n")


def test_parse_csv_header_missing_columns_is_refused():
    head = "#model_version:v2026.06.15,score_date:2026-07-29T00:00:00+0000\n"
    with pytest.raises(ValueError, match=r"lacks column\(s\) \['epss'\]"):
        _parse(head + "cve,score,percentile\nCVE-2026-0001,0.42,0.97\n")
    with pytest.raises(ValueError, match=r"lacks column\(s\) \['cve'\]"):
        _parse(head + "id,epss,percentile\nCVE-2026-0001,0.42,0.97\n")
    with pytest.raises(ValueError, match=r"\['cve', 'epss'\]"):
        _parse(head)  # header comment, then nothing at all


def test_parse_zero_rows_is_refused():
    head = "#model_version:v2026.06.15,score_date:2026-07-29T00:00:00+0000\n"
    with pytest.raises(ValueError, match="parsed zero score rows"):
        _parse(head + "cve,epss,percentile\n")
    with pytest.raises(ValueError, match="parsed zero score rows"):
        _parse(head + "cve,epss,percentile\n,0.42,0.97\n")  # blank cve


def test_parse_missing_percentile_column_is_still_fine():
    """The earliest EPSS era shipped no percentile column; the score map
    must parse and the percentile map is simply empty."""
    data = _parse("#model_version:v2021.04.13,score_date:2021-04-13T00:00:00\n"
                  "cve,epss\nCVE-2021-0001,0.1\n")
    assert data.scores == {"CVE-2021-0001": 0.1} and data.percentiles == {}


def test_fetch_surfaces_parse_failure_as_value_error():
    session = FakeSession([FakeResponse(payload="<html>oops</html>\n")])
    with pytest.raises(ValueError, match="header comment"):
        fetch_epss(session=session, sleep=lambda s: None,
                   log=lambda m: None)
