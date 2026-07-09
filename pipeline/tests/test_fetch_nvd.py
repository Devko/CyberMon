"""Incremental NVD sync: full-sweep policy (via the static yearly feeds),
delta merge, counting."""
from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone

import pytest

from pipeline import fetch_nvd

NOW = datetime(2026, 7, 9, 6, 0, 0, tzinfo=timezone.utc)
FEED_YEARS = list(range(2002, 2027))  # FIRST_FEED_YEAR .. NOW.year


class FakeResponse:
    """API responses carry a JSON payload (``.json()``); feed responses
    carry gzipped bytes (``.content``) — mirroring how the fetchers read
    each kind."""

    def __init__(self, payload=None, content=b"", status_code=200):
        self.status_code = status_code
        self._payload = payload
        self.content = content

    def json(self):
        return self._payload


class FakeSession:
    """Serves canned API pages plus per-year gzipped feeds, and records
    every request (query params for the API, url+headers for feeds)."""

    def __init__(self, pages=(), feeds=None):
        self.pages = list(pages)
        self.feeds = dict(feeds or {})
        self.requests = []
        self.feed_requests = []

    def get(self, url, params=None, headers=None, timeout=None):
        if "feeds/json" in url:
            self.feed_requests.append({"url": url,
                                       "headers": dict(headers or {})})
            year = int(url.rsplit("-", 1)[-1].split(".")[0])
            return FakeResponse(content=self.feeds.get(year, _feed([])))
        self.requests.append(params)
        return FakeResponse(payload=self.pages.pop(0))


def _page(entries, total):
    return {"totalResults": total,
            "vulnerabilities": [
                {"cve": {"id": cve_id, "vulnStatus": status}}
                for cve_id, status in entries]}


def _feed(entries, total=None):
    """One gzipped yearly-feed body, same record shape as the API."""
    doc = _page(entries, total)
    if total is None:
        del doc["totalResults"]
    return gzip.compress(json.dumps(doc).encode())


def _no_sleep(_):
    pass


def test_no_state_triggers_feed_sweep_not_api_paging():
    session = FakeSession(feeds={
        2024: _feed([("CVE-1", "Analyzed")]),
        2025: _feed([("CVE-2", "Awaiting Analysis")]),
    })
    logs = []
    state = fetch_nvd.sync_status_state(None, session=session,
                                        sleep=_no_sleep, log=logs.append,
                                        now=NOW)
    assert session.requests == []  # full sweeps never page the API
    assert len(session.feed_requests) == len(FEED_YEARS)
    assert state["statuses"] == {"CVE-1": "Analyzed",
                                 "CVE-2": "Awaiting Analysis"}
    assert state["last_full_sync"] == "2026-07-09T06:00:00Z"
    # back-dated 25h: the next incremental pull re-covers feed staleness
    assert state["last_sync"] == "2026-07-08T05:00:00Z"
    assert any("full sweep via yearly feeds (no cached state)" in m
               for m in logs)
    assert fetch_nvd.status_counts(state) == {"Analyzed": 1,
                                              "Awaiting Analysis": 1}


def test_feed_sweep_covers_every_year_and_sends_user_agent():
    session = FakeSession()
    fetch_nvd.sync_status_state(None, session=session, sleep=_no_sleep,
                                log=lambda m: None, now=NOW)
    years = [int(r["url"].rsplit("-", 1)[-1].split(".")[0])
             for r in session.feed_requests]
    assert years == FEED_YEARS
    assert all(r["url"].startswith("https://nvd.nist.gov/feeds/json/cve/2.0/")
               for r in session.feed_requests)
    assert all(r["headers"]["User-Agent"].startswith("CyberMon/")
               for r in session.feed_requests)


def test_feed_total_results_mismatch_warns_but_keeps_parsed_records():
    session = FakeSession(feeds={2026: _feed([("CVE-1", "Analyzed")],
                                             total=5)})
    logs = []
    state = fetch_nvd.sync_status_state(None, session=session,
                                        sleep=_no_sleep, log=logs.append,
                                        now=NOW)
    assert any("totalResults=5" in m and "parsed 1" in m for m in logs)
    assert state["statuses"] == {"CVE-1": "Analyzed"}


def test_feed_http_error_raises_instead_of_writing_partial_state():
    class ErrorSession(FakeSession):
        def get(self, url, params=None, headers=None, timeout=None):
            return FakeResponse(status_code=503)

    with pytest.raises(RuntimeError, match="HTTP 503"):
        fetch_nvd.sync_status_state(None, session=ErrorSession(),
                                    sleep=_no_sleep, log=lambda m: None,
                                    now=NOW)


def test_fresh_state_syncs_incrementally_and_merges():
    prior = {"version": 1,
             "last_full_sync": "2026-07-08T06:00:00Z",
             "last_sync": "2026-07-08T06:00:00Z",
             "statuses": {"CVE-1": "Awaiting Analysis", "CVE-2": "Analyzed"}}
    session = FakeSession([_page([("CVE-1", "Analyzed"),
                                  ("CVE-3", "Received")], total=2)])
    state = fetch_nvd.sync_status_state(prior, session=session,
                                        sleep=_no_sleep, log=lambda m: None,
                                        now=NOW)
    params = session.requests[0]
    # window opens one hour of overlap before the previous sync
    assert params["lastModStartDate"] == "2026-07-08T05:00:00.000+00:00"
    assert params["lastModEndDate"] == "2026-07-09T06:00:00.000+00:00"
    assert state["statuses"] == {"CVE-1": "Analyzed", "CVE-2": "Analyzed",
                                 "CVE-3": "Received"}
    assert state["last_sync"] == "2026-07-09T06:00:00Z"
    assert state["last_full_sync"] == "2026-07-08T06:00:00Z"  # unchanged


def test_stale_full_sync_forces_feed_resweep():
    prior = {"version": 1,
             "last_full_sync": "2026-07-01T05:00:00Z",  # > 7 days before NOW
             "last_sync": "2026-07-08T06:00:00Z",
             "statuses": {"CVE-1": "Analyzed"}}
    session = FakeSession(feeds={2026: _feed([("CVE-9", "Received")])})
    logs = []
    state = fetch_nvd.sync_status_state(prior, session=session,
                                        sleep=_no_sleep, log=logs.append,
                                        now=NOW)
    assert session.requests == []
    assert state["statuses"] == {"CVE-9": "Received"}  # rebuilt, not merged
    assert state["last_full_sync"] == "2026-07-09T06:00:00Z"
    assert any("full sweep via yearly feeds (scheduled resync" in m
               for m in logs)


def test_malformed_state_forces_resweep():
    for bad in ({}, {"version": 99}, {"version": 1, "statuses": {}},
                {"version": 1, "last_full_sync": "not-a-date",
                 "last_sync": "also-not", "statuses": {"CVE-1": "Analyzed"}}):
        assert fetch_nvd._full_sweep_reason(bad, NOW) is not None


def test_multi_page_sweep_paginates():
    session = FakeSession([
        _page([("CVE-1", "Analyzed"), ("CVE-2", "Analyzed")], total=3),
        _page([("CVE-3", "Received")], total=3),
    ])
    # patch page size so two entries fill a page
    old = fetch_nvd.PAGE_SIZE
    fetch_nvd.PAGE_SIZE = 2
    try:
        counts = fetch_nvd.fetch_status_counts(session=session,
                                               sleep=_no_sleep,
                                               log=lambda m: None)
    finally:
        fetch_nvd.PAGE_SIZE = old
    assert counts == {"Analyzed": 2, "Received": 1}
    assert session.requests[1]["startIndex"] == 2
