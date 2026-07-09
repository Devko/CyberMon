"""The nightly NVD-backlog snapshot file: site/data/history/nvd_backlog.csv.

NVD publishes no backlog history, so our committed snapshots *are* the
historical record. One row per pipeline run date; re-running on the same
date replaces that date's row (last run wins). Rows are kept sorted
ascending by date.
"""
from __future__ import annotations

import csv
from pathlib import Path

COLUMNS = ("date", "backlog_total", "awaiting_analysis",
           "undergoing_analysis", "received")
_INT_COLUMNS = COLUMNS[1:]


def read_rows(path: Path) -> list[dict]:
    """Read history rows (numeric columns as ints), oldest first.

    Missing file -> empty list. Malformed rows fail loudly: this file is
    the historical record and silent data loss would be worse than a crash.
    """
    if not path.exists():
        return []
    rows: list[dict] = []
    with path.open("r", newline="", encoding="utf-8") as f:
        for lineno, raw in enumerate(csv.DictReader(f), start=2):
            try:
                row = {"date": raw["date"]}
                row.update({col: int(raw[col]) for col in _INT_COLUMNS})
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"{path}:{lineno}: malformed history row "
                                 f"{raw!r}") from exc
            rows.append(row)
    rows.sort(key=lambda r: r["date"])
    return rows


def merge_row(rows: list[dict], row: dict) -> list[dict]:
    """Pure merge, no I/O: insert ``row`` (replacing any existing row with
    the same date) and return a new list sorted ascending by date.

    Kept separate from :func:`write_rows` so the pipeline can build the
    merged history in memory and defer the disk write until every output
    has passed contract validation.
    """
    new_row = {"date": row["date"]}
    new_row.update({col: int(row[col]) for col in _INT_COLUMNS})
    merged = [r for r in rows if r["date"] != new_row["date"]]
    merged.append(new_row)
    merged.sort(key=lambda r: r["date"])
    return merged


def write_rows(path: Path, rows: list[dict]) -> None:
    """Rewrite the CSV atomically (temp file, then ``replace``).

    This file is the irreplaceable historical record: an interrupted run
    must leave either the old file or the new one, never a truncation.
    Same pattern as fetch_cvelist.download_zip's ``.part`` -> replace.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    tmp.replace(path)


def upsert_row(path: Path, row: dict) -> list[dict]:
    """merge_row + write_rows in one step; returns the full row list."""
    rows = merge_row(read_rows(path), row)
    write_rows(path, rows)
    return rows
