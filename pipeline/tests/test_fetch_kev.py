"""fetch_kev network discipline: bounded retry through the shared helper,
User-Agent on every request, loud final failure."""
from __future__ import annotations

import pytest

from pipeline.fetch_kev import KEV_URL, fetch_kev

_DOC = {"catalogVersion": "2026.09.08", "count": 1,
        "vulnerabilities": [{"cveID": "CVE-2026-0001",
                             "dateAdded": "2026-09-01"}]}


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else _DOC

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class FakeSession:
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
    data = fetch_kev(session=session, sleep=sleeps.append,
                     log=lambda m: None)
    assert data.catalog_version == "2026.09.08"
    assert data.cve_ids == ["CVE-2026-0001"]
    assert len(session.requests) == 3 and len(sleeps) == 2
    assert all(r["url"] == KEV_URL for r in session.requests)
    assert all(r["headers"]["User-Agent"].startswith("CyberMon/")
               for r in session.requests)


def test_fetch_persistent_failure_raises_after_bounded_attempts():
    session = FakeSession([FakeResponse(status_code=503)] * 5)
    with pytest.raises(RuntimeError, match="HTTP 503"):
        fetch_kev(session=session, sleep=lambda s: None,
                  log=lambda m: None)
    assert len(session.requests) == 3


def test_fetch_non_retryable_status_raises_immediately():
    session = FakeSession([FakeResponse(status_code=404)] * 3)
    with pytest.raises(RuntimeError, match="HTTP 404"):
        fetch_kev(session=session, sleep=lambda s: None,
                  log=lambda m: None)
    assert len(session.requests) == 1
