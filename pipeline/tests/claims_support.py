"""Shared plumbing for the claims audits (test_claims_*.py, *_claims.py).

* ``DATA_DIR`` — site/data, or ``CYBERMON_DATA_DIR`` to judge another
  edition (an older nightly extracted with ``git archive``, a scratch run).
* ``GENERATION_YEAR`` — the edition's year, or ``CYBERMON_REHEARSE_YEAR``.
* ``read_json`` — ``json.loads`` plus the tiny-new-year rehearsal below.
* ``judged`` — whether a year's figures are settled enough to hold copy to.

Two rehearsals cover the January rollover, and both must pass except for
the guards docs/backlog.md lists as failing on purpose:

``CYBERMON_REHEARSE_YEAR=2027``
    The current partial year counts as complete (its values as they stand)
    and the rehearsal year has no rows yet: the edition of 1 January.

``CYBERMON_REHEARSE_YEAR=2027 CYBERMON_REHEARSE_TINY=low`` (or ``high``)
    Also appends a rehearsal-year row to every year series, built from the
    latest row with each integer cut to 1% and every other number set to 0
    (``low``) or doubled (``high``): the edition of a few days into January,
    when a handful of records can put a share anywhere. A guard that reads
    the current year without ``judged`` fails one of the two. Headline
    blocks the pipeline computes cannot be rehearsed this way; a failure
    there is noise unless the guard reads the year itself.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

DATA_DIR = Path(os.environ.get("CYBERMON_DATA_DIR")
                or Path(__file__).resolve().parents[2] / "site" / "data")

_META_PATH = DATA_DIR / "meta.json"
META: dict = (json.loads(_META_PATH.read_text("utf-8"))
              if _META_PATH.exists() else {})
GENERATION_YEAR: int = int(os.environ.get("CYBERMON_REHEARSE_YEAR")
                           or str(META.get("generated_at", "0"))[:4])
_TINY = os.environ.get("CYBERMON_REHEARSE_TINY", "").lower()
_YEAR_KEY = re.compile(r"^\d{4}$")


def judged(year: int, n: int | float | None = None, *,
           min_n: int | float | None = None) -> bool:
    """True when ``year``'s figures may be held to the copy: a complete
    year always; the current year only once ``n`` (its record count)
    reaches ``min_n``. A current year without a size bar is never judged —
    a few days of January can put any share anywhere."""
    if year < GENERATION_YEAR:
        return True
    if year > GENERATION_YEAR or min_n is None or n is None:
        return False
    return n >= min_n


def complete_years(rows: list[dict]) -> list[dict]:
    """Rows for complete years only (strictly before the generation year)."""
    return [r for r in rows if r["year"] < GENERATION_YEAR]


def read_json(path: Path):
    obj = json.loads(Path(path).read_text("utf-8"))
    if _TINY in ("low", "high") and GENERATION_YEAR:
        _add_tiny_year(obj)
    return obj


def _shrunk(value, key: str = ""):
    if (isinstance(value, bool) or value is None or isinstance(value, str)
            or "year" in key):
        return value
    if isinstance(value, int):
        return round(value * 0.01)
    if isinstance(value, float):
        if _TINY == "low":
            return 0.0
        doubled = value * 2
        return min(doubled, 100.0) if ("pct" in key or "share" in key) \
            else doubled
    if isinstance(value, dict):
        return {k: _shrunk(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_shrunk(v, key) for v in value]
    return value


def _add_tiny_year(node) -> None:
    """Walk ``node`` and give every year series a tiny rehearsal-year entry
    (lists of ``{"year": int, ...}`` rows; dicts keyed by year strings)."""
    year = GENERATION_YEAR
    if isinstance(node, list):
        rows = [r for r in node if isinstance(r, dict)]
        if rows and len(rows) == len(node) and all(
                isinstance(r.get("year"), int) and not isinstance(
                    r.get("year"), bool) for r in rows):
            latest = max(rows, key=lambda r: r["year"])
            if latest["year"] < year:
                tiny = {k: _shrunk(v, k) for k, v in latest.items()}
                tiny["year"] = year
                node.append(tiny)
        for item in node:
            _add_tiny_year(item)
    elif isinstance(node, dict):
        keys = list(node)
        if keys and all(isinstance(k, str) and _YEAR_KEY.match(k)
                        for k in keys):
            latest = max(keys)
            if int(latest) < year and str(year) not in node:
                node[str(year)] = _shrunk(node[latest], "")
        for value in list(node.values()):
            _add_tiny_year(value)
