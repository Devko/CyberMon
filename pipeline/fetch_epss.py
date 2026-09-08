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

from .fetch_http import USER_AGENT, get_with_retry  # noqa: F401

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


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
    """Parse the EPSS CSV (comment header first, then cve,epss,percentile).

    Raises ``ValueError`` when the feed is not the feed: no ``#`` header
    comment, a header without ``model_version`` or ``score_date``, a CSV
    header without ``cve``/``epss`` columns, or zero parseable rows. Each
    of those would otherwise flow downstream as "unknown @ 1970-01-01,
    0 rows" and every EPSS-fed module would quietly publish nonsense."""
    iterator = iter(lines)
    first = next(iterator, "")
    if not first.startswith("#"):
        raise ValueError("EPSS feed has no '#model_version:...,score_date:"
                         "...' header comment on line 1 "
                         f"(got {first.strip()[:60]!r})")
    model_version = score_date = None
    for token in first.lstrip("#").strip().split(","):
        key, _, value = token.partition(":")
        if key.strip() == "model_version" and value.strip():
            model_version = value.strip()
        elif key.strip() == "score_date" and value.strip():
            score_date = value.strip()[:10]  # date part of the timestamp
    if model_version is None or score_date is None:
        raise ValueError("EPSS feed header lacks model_version and/or "
                         f"score_date: {first.strip()[:120]!r}")

    scores: dict[str, float] = {}
    percentiles: dict[str, float] = {}
    row_count = 0
    reader = csv.DictReader(iterator)
    fieldnames = reader.fieldnames or []
    missing = [c for c in ("cve", "epss") if c not in fieldnames]
    if missing:
        raise ValueError(f"EPSS feed CSV header lacks column(s) {missing}: "
                         f"{fieldnames}")
    for row in reader:
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
    if row_count == 0:
        raise ValueError(f"EPSS feed {model_version} @ {score_date} "
                         f"parsed zero score rows")
    return EpssData(model_version=model_version, score_date=score_date,
                    row_count=row_count, scores=scores,
                    percentiles=percentiles)


def load_epss_file(path: Path) -> EpssData:
    """Load EPSS data from a local ``.csv`` or ``.csv.gz`` file."""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return parse_epss(f)
    return parse_epss(path.read_text(encoding="utf-8").splitlines())


def fetch_epss(session=None, timeout: float = 120.0,
               sleep=time.sleep, log=print) -> EpssData:
    """Download and parse the current EPSS scores feed. Transient failures
    are retried (see :func:`pipeline.fetch_http.get_with_retry`); the last
    failure raises unchanged."""
    import requests

    session = session or requests.Session()
    resp = get_with_retry(session, EPSS_URL, label="epss",
                          timeout=timeout, sleep=sleep, log=log)
    with gzip.open(io.BytesIO(resp.content), "rt", encoding="utf-8") as f:
        return parse_epss(f)
