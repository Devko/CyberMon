"""EPSS scores: https://epss.cyentia.com/epss_scores-current.csv.gz

The file's first line is a comment header carrying the model version and
score date, e.g. ``#model_version:v2025.03.14,score_date:2026-07-08T...``;
the CSV proper (``cve,epss,percentile``) starts on line 2.
"""
from __future__ import annotations

import csv
import gzip
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


@dataclass
class EpssData:
    """Parsed EPSS feed: header metadata + cve -> probability map."""

    model_version: str
    score_date: str  # YYYY-MM-DD
    row_count: int
    scores: dict[str, float] = field(default_factory=dict, repr=False)


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
    row_count = 0
    for row in csv.DictReader(iterator):
        cve, epss = row.get("cve"), row.get("epss")
        if not cve or epss is None:
            continue
        row_count += 1
        scores[cve] = float(epss)
    return EpssData(model_version=model_version, score_date=score_date,
                    row_count=row_count, scores=scores)


def load_epss_file(path: Path) -> EpssData:
    """Load EPSS data from a local ``.csv`` or ``.csv.gz`` file."""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return parse_epss(f)
    return parse_epss(path.read_text(encoding="utf-8").splitlines())


def fetch_epss(session=None, timeout: float = 120.0) -> EpssData:
    """Download and parse the current EPSS scores feed."""
    import requests

    session = session or requests.Session()
    resp = session.get(EPSS_URL, timeout=timeout)
    resp.raise_for_status()
    with gzip.open(io.BytesIO(resp.content), "rt", encoding="utf-8") as f:
        return parse_epss(f)
