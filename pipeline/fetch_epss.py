"""EPSS scores: https://epss.cyentia.com/epss_scores-current.csv.gz

The file's first line is a comment header carrying the model version and
score date, e.g. ``#model_version:v2025.03.14,score_date:2026-07-08T...``;
the CSV proper (``cve,epss,percentile``) starts on line 2.

Failures are loud on purpose: transient blips (HTTP 429/5xx, connection
errors) get a bounded retry (3 attempts, backoff), but there is no
carry-forward machinery — if the feed stays down, the run fails and
nothing stale is deployed. This fetch is the first external call of the
nightly gather sequence, so an unretried blip here costs the whole run.
"""
from __future__ import annotations

import csv
import gzip
import io
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .fetch_market import USER_AGENT

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

_RETRY_STATUSES = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 3


@dataclass
class EpssData:
    """Parsed EPSS feed: header metadata + cve -> probability map.

    ``percentiles`` (cve -> published percentile, 0..1) rides alongside
    ``scores`` for the EPSS Volatility module, which needs both the raw
    probability and the corpus-relative rank to tell their movements apart.
    It is additive: the older consumers (score_vs_reality, epss_report)
    read only ``scores`` and never touch it, and a row without a parseable
    percentile is simply absent from the map (the earliest EPSS era shipped
    scores with no percentile column at all)."""

    model_version: str
    score_date: str  # YYYY-MM-DD
    row_count: int
    scores: dict[str, float] = field(default_factory=dict, repr=False)
    percentiles: dict[str, float] = field(default_factory=dict, repr=False)


def parse_epss(lines: Iterable[str]) -> EpssData:
    """Parse the EPSS CSV (comment header first, then cve,epss,percentile)."""
    iterator = iter(lines)
    first = next(iterator, "")
    model_version, score_date = "unknown", "1970-01-01"
    if first.startswith("#"):
        for token in first.lstrip("#").strip().split(","):
            key, _, value = token.partition(":")
            if key.strip() == "model_version":
                model_version = value.strip()
            elif key.strip() == "score_date":
                score_date = value.strip()[:10]  # date part of the timestamp
    else:
        iterator = iter([first, *iterator])  # no comment header: keep line 1

    scores: dict[str, float] = {}
    percentiles: dict[str, float] = {}
    row_count = 0
    for row in csv.DictReader(iterator):
        cve, epss = row.get("cve"), row.get("epss")
        if not cve or epss is None:
            continue
        row_count += 1
        scores[cve] = float(epss)
        pct = row.get("percentile")
        if pct not in (None, ""):
            try:
                percentiles[cve] = float(pct)
            except ValueError:
                pass  # unparseable percentile: absent, never fatal
    return EpssData(model_version=model_version, score_date=score_date,
                    row_count=row_count, scores=scores,
                    percentiles=percentiles)


def load_epss_file(path: Path) -> EpssData:
    """Load EPSS data from a local ``.csv`` or ``.csv.gz`` file."""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return parse_epss(f)
    return parse_epss(path.read_text(encoding="utf-8").splitlines())


def _get_with_retry(session, url: str, timeout: float, sleep, log):
    """GET with fetch_attack's bounded-retry discipline: up to
    ``_MAX_ATTEMPTS`` attempts, backing off on 429/5xx statuses and
    connection errors. The final failure raises exactly as an unretried
    call would — the retry absorbs blips, it never softens the
    loud-failure policy."""
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        last = attempt == _MAX_ATTEMPTS
        try:
            resp = session.get(url, timeout=timeout,
                               headers={"User-Agent": USER_AGENT})
        except OSError as exc:  # requests exceptions subclass OSError
            if last:
                raise
            message = f"request failed: {exc!r}"
        else:
            if last or resp.status_code not in _RETRY_STATUSES:
                resp.raise_for_status()
                return resp
            message = f"HTTP {resp.status_code}"
        backoff = 15.0 * attempt
        log(f"  epss: {message} for {url}; retrying in {backoff:.0f}s "
            f"(attempt {attempt}/{_MAX_ATTEMPTS})")
        sleep(backoff)


def fetch_epss(session=None, timeout: float = 120.0,
               sleep=time.sleep, log=print) -> EpssData:
    """Download and parse the current EPSS scores feed. Transient failures
    are retried (see :func:`_get_with_retry`); the last failure raises
    unchanged."""
    import requests

    session = session or requests.Session()
    resp = _get_with_retry(session, EPSS_URL, timeout, sleep, log)
    with gzip.open(io.BytesIO(resp.content), "rt", encoding="utf-8") as f:
        return parse_epss(f)
