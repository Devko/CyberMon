"""Incremental NVD sync: full-sweep policy, delta merge, counting."""
from __future__ import annotations

from datetime import datetime, timezone

from pipeline import fetch_nvd

NOW = datetime(2026, 7, 9, 6, 0, 0, tzinfo=timezone.utc)


class FakeResponse:
    def __init__(self, payload):
        self.status_code = 200
        self._payload = payload

    def json(self):
        return self._payload


class FakeSession:
    """Serves canned pages and records the query params of every request."""

    def __init__(self, pages):
        self.pages = list(pages)
        self.requests = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.requests.append(params)
        return FakeResponse(self.pages.pop(0))


def _page(entries, total):
    return {"totalResults": total,
            "vulnerabilities": [
                {"cve": {"id": cve_id, "vulnStatus": status}}
                for cve_id, status in entries]}


def _no_sleep(_):
    pass


def test_no_state_triggers_full_sweep_without_lastmod_params():
    session = FakeSession([_page(
        [("CVE-1", "Analyzed"), ("CVE-2", "Awaiting Analysis")], total=2)])
    state = fetch_nvd.sync_status_state(None, session=session,
                                        sleep=_no_sleep, log=lambda m: None,
                                        now=NOW)
    assert "lastModStartDate" not in session.requests[0]
    assert state["statuses"] == {"CVE-1": "Analyzed",
                                 "CVE-2": "Awaiting Analysis"}
    assert state["last_full_sync"] == state["last_sync"] == "2026-07-09T06:00:00Z"
    assert fetch_nvd.status_counts(state) == {"Analyzed": 1,
                                              "Awaiting Analysis": 1}


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


def test_stale_full_sync_forces_resweep():
    prior = {"version": 1,
             "last_full_sync": "2026-07-01T05:00:00Z",  # > 7 days before NOW
             "last_sync": "2026-07-08T06:00:00Z",
             "statuses": {"CVE-1": "Analyzed"}}
    session = FakeSession([_page([("CVE-9", "Received")], total=1)])
    state = fetch_nvd.sync_status_state(prior, session=session,
                                        sleep=_no_sleep, log=lambda m: None,
                                        now=NOW)
    assert "lastModStartDate" not in session.requests[0]
    assert state["statuses"] == {"CVE-9": "Received"}  # rebuilt, not merged
    assert state["last_full_sync"] == "2026-07-09T06:00:00Z"


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
