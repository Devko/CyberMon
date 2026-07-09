"""NVD API 2.0: count CVEs by ``vulnStatus`` — nothing else.

The API has no status filter, so we page the full corpus and tally
``vulnStatus`` per page, discarding everything else immediately (the page
JSON is never retained). Rate limits are respected: 5 requests / 30 s
without an API key, 50 / 30 s with one (``NVD_API_KEY`` env var, passed in
by the caller). Transient failures (403/429/5xx — NVD uses 403 for rate
limiting) are retried with exponential backoff.

This is the slow stage (~15 minutes keyless for ~300k CVEs); the CLI's
``--skip-nvd`` flag bypasses it entirely.
"""
from __future__ import annotations

import time
from collections import Counter
from typing import Callable

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
_RETRY_STATUSES = {403, 429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 6
# 30s window / 5 (or 50) requests, plus a little slack.
_DELAY_KEYLESS = 6.5
_DELAY_KEYED = 0.7


def _fetch_page(session, start_index: int, api_key: str | None,
                timeout: float, sleep: Callable[[float], None],
                log: Callable[[str], None]) -> dict:
    headers = {"apiKey": api_key} if api_key else {}
    params = {"resultsPerPage": PAGE_SIZE, "startIndex": start_index}
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


def fetch_status_counts(session=None, api_key: str | None = None,
                        timeout: float = 60.0,
                        sleep: Callable[[float], None] = time.sleep,
                        log: Callable[[str], None] = print) -> dict[str, int]:
    """Page the whole NVD corpus and return ``{vulnStatus: count}``."""
    import requests

    session = session or requests.Session()
    delay = _DELAY_KEYED if api_key else _DELAY_KEYLESS
    counts: Counter[str] = Counter()
    start_index = 0
    total: int | None = None
    while total is None or start_index < total:
        page = _fetch_page(session, start_index, api_key, timeout, sleep, log)
        total = int(page.get("totalResults", 0))
        vulns = page.get("vulnerabilities") or []
        for item in vulns:
            counts[item.get("cve", {}).get("vulnStatus") or "Unknown"] += 1
        if not vulns:  # defensive: never loop forever on an empty page
            break
        start_index += len(vulns)
        if start_index < total:
            log(f"  NVD: {start_index}/{total} CVEs counted")
            sleep(delay)
    return dict(counts)
