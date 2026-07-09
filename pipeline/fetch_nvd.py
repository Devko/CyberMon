"""NVD API 2.0: count CVEs by ``vulnStatus`` — nothing else.

The API has no status filter, so counting requires seeing every record.
Doing that nightly with a full corpus sweep is the pipeline's slow stage
(~45 min keyless, ~6 min keyed, for ~370k CVEs), so the sweep is
*incremental*: we keep a ``{cve_id: vulnStatus}`` map as sync state and,
on later runs, ask only for records modified since the last sync
(``lastModStartDate`` — typically a few thousand records, i.e. seconds).

Drift/corruption guards — the state is a cache, never a source of truth:

* a full resweep is forced every ``FULL_RESYNC_DAYS`` days, so any drift
  (a missed modification window) can never outlive a week;
* missing/unreadable/old state simply triggers a full sweep (self-healing);
* the incremental window starts ``_OVERLAP`` before the last sync so clock
  skew between us and NVD cannot drop records.

Rate limits are respected: 5 requests / 30 s without an API key, 50 / 30 s
with one (``NVD_API_KEY`` env var, passed in by the caller). Transient
failures (403/429/5xx — NVD uses 403 for rate limiting) are retried with
exponential backoff. The CLI's ``--skip-nvd`` flag bypasses the stage
entirely.
"""
from __future__ import annotations

import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Callable

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
STATE_VERSION = 1
FULL_RESYNC_DAYS = 7
_RETRY_STATUSES = {403, 429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 6
# 30s window / 5 (or 50) requests, plus a little slack.
_DELAY_KEYLESS = 6.5
_DELAY_KEYED = 0.7
# Incremental windows re-read this much history before the last sync so
# clock skew can't lose records; the API caps lastMod ranges at 120 days.
_OVERLAP = timedelta(hours=1)
_MAX_WINDOW_DAYS = 100


def _fetch_page(session, start_index: int, api_key: str | None,
                timeout: float, sleep: Callable[[float], None],
                log: Callable[[str], None],
                extra_params: dict | None = None) -> dict:
    headers = {"apiKey": api_key} if api_key else {}
    params = {"resultsPerPage": PAGE_SIZE, "startIndex": start_index}
    params.update(extra_params or {})
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            resp = session.get(NVD_URL, params=params, headers=headers,
                               timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            retryable = resp.status_code in _RETRY_STATUSES
            message = f"NVD returned HTTP {resp.status_code}"
        except (OSError, ValueError) as exc:  # connection errors, bad JSON
            retryable = True
            message = f"NVD request failed: {exc!r}"
        if not retryable or attempt == _MAX_ATTEMPTS:
            raise RuntimeError(f"{message} (startIndex={start_index}, "
                               f"attempt {attempt}/{_MAX_ATTEMPTS})")
        backoff = min(10.0 * 2 ** (attempt - 1), 120.0)
        log(f"  {message}; retrying in {backoff:.0f}s "
            f"(attempt {attempt}/{_MAX_ATTEMPTS})")
        sleep(backoff)
    raise AssertionError("unreachable")


def _collect_statuses(session, api_key: str | None, timeout: float,
                      sleep: Callable[[float], None],
                      log: Callable[[str], None],
                      extra_params: dict | None = None) -> dict[str, str]:
    """Page (part of) the corpus, return ``{cve_id: vulnStatus}``."""
    delay = _DELAY_KEYED if api_key else _DELAY_KEYLESS
    statuses: dict[str, str] = {}
    start_index = 0
    total: int | None = None
    while total is None or start_index < total:
        page = _fetch_page(session, start_index, api_key, timeout, sleep, log,
                           extra_params)
        total = int(page.get("totalResults", 0))
        vulns = page.get("vulnerabilities") or []
        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if cve_id:
                statuses[cve_id] = cve.get("vulnStatus") or "Unknown"
        if not vulns:  # defensive: never loop forever on an empty page
            break
        start_index += len(vulns)
        if start_index < total:
            log(f"  NVD: {start_index}/{total} CVEs read")
            sleep(delay)
    return statuses


def fetch_status_counts(session=None, api_key: str | None = None,
                        timeout: float = 60.0,
                        sleep: Callable[[float], None] = time.sleep,
                        log: Callable[[str], None] = print) -> dict[str, int]:
    """Page the whole NVD corpus and return ``{vulnStatus: count}``."""
    import requests

    session = session or requests.Session()
    statuses = _collect_statuses(session, api_key, timeout, sleep, log)
    return dict(Counter(statuses.values()))


# ------------------------------------------------- incremental sync state --

def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ") \
                   .replace(tzinfo=timezone.utc)


def _fmt_nvd(ts: datetime) -> str:
    """NVD's extended ISO-8601 with an explicit UTC offset."""
    return ts.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _full_sweep_reason(state: dict | None, now: datetime) -> str | None:
    """Why the state can't be synced incrementally, or None if it can."""
    if not state:
        return "no cached state"
    try:
        if state["version"] != STATE_VERSION or not state["statuses"]:
            return "unrecognized state format"
        last_full = _parse_iso(state["last_full_sync"])
        last_sync = _parse_iso(state["last_sync"])
    except (KeyError, TypeError, ValueError):
        return "unreadable state"
    if now - last_full > timedelta(days=FULL_RESYNC_DAYS):
        return f"scheduled resync (last full sweep {state['last_full_sync']})"
    if now - last_sync > timedelta(days=_MAX_WINDOW_DAYS):
        return "state predates the API's lastModified window"
    return None


def sync_status_state(state: dict | None, session=None,
                      api_key: str | None = None, timeout: float = 60.0,
                      sleep: Callable[[float], None] = time.sleep,
                      log: Callable[[str], None] = print,
                      now: datetime | None = None) -> dict:
    """Return up-to-date sync state (``{version, last_full_sync, last_sync,
    statuses}``), via an incremental ``lastModStartDate`` pull when the
    given state allows it and a full corpus sweep when it doesn't."""
    import requests

    session = session or requests.Session()
    now = now or datetime.now(timezone.utc)

    reason = _full_sweep_reason(state, now)
    if reason is not None:
        log(f"  NVD: full sweep ({reason})")
        statuses = _collect_statuses(session, api_key, timeout, sleep, log)
        return {"version": STATE_VERSION, "last_full_sync": _iso(now),
                "last_sync": _iso(now), "statuses": statuses}

    window_start = _parse_iso(state["last_sync"]) - _OVERLAP
    changed = _collect_statuses(
        session, api_key, timeout, sleep, log,
        extra_params={"lastModStartDate": _fmt_nvd(window_start),
                      "lastModEndDate": _fmt_nvd(now)})
    log(f"  NVD: incremental sync, {len(changed)} record(s) modified "
        f"since {state['last_sync']}")
    statuses = dict(state["statuses"])
    statuses.update(changed)
    return {"version": STATE_VERSION,
            "last_full_sync": state["last_full_sync"],
            "last_sync": _iso(now), "statuses": statuses}


def status_counts(state: dict) -> dict[str, int]:
    """Tally the sync state into the ``{vulnStatus: count}`` shape the
    metrics builders consume."""
    return dict(Counter(state["statuses"].values()))
