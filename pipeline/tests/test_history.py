"""nvd_backlog.csv snapshot file: create, append, replace-same-date."""
from __future__ import annotations

import pytest

from pipeline import history


def _row(date: str, total: int = 100) -> dict:
    return {"date": date, "backlog_total": total, "awaiting_analysis": total - 10,
            "undergoing_analysis": 6, "received": 4}


def test_creates_file_with_header(tmp_path):
    path = tmp_path / "history" / "nvd_backlog.csv"
    rows = history.upsert_row(path, _row("2026-07-09"))
    assert rows == [_row("2026-07-09")]
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "date,backlog_total,awaiting_analysis,undergoing_analysis,received"
    assert lines[1] == "2026-07-09,100,90,6,4"


def test_appends_new_dates_sorted(tmp_path):
    path = tmp_path / "nvd_backlog.csv"
    history.upsert_row(path, _row("2026-07-09", 100))
    history.upsert_row(path, _row("2026-07-07", 80))  # out of order on purpose
    rows = history.upsert_row(path, _row("2026-07-08", 90))
    assert [r["date"] for r in rows] == ["2026-07-07", "2026-07-08", "2026-07-09"]
    assert [r["backlog_total"] for r in rows] == [80, 90, 100]


def test_same_date_replaces_last_run_wins(tmp_path):
    path = tmp_path / "nvd_backlog.csv"
    history.upsert_row(path, _row("2026-07-08", 90))
    history.upsert_row(path, _row("2026-07-09", 100))
    rows = history.upsert_row(path, _row("2026-07-09", 120))  # re-run same day
    assert [r["date"] for r in rows] == ["2026-07-08", "2026-07-09"]
    assert rows[-1]["backlog_total"] == 120
    # and the rewrite is round-trippable
    assert history.read_rows(path) == rows


def test_merge_row_is_pure(tmp_path):
    existing = [_row("2026-07-07", 80)]
    merged = history.merge_row(existing, _row("2026-07-08", 90))
    assert [r["date"] for r in merged] == ["2026-07-07", "2026-07-08"]
    assert existing == [_row("2026-07-07", 80)]  # input untouched, no I/O


def test_write_rows_leaves_no_temp_file(tmp_path):
    path = tmp_path / "nvd_backlog.csv"
    history.write_rows(path, [_row("2026-07-09")])
    assert history.read_rows(path) == [_row("2026-07-09")]
    assert list(tmp_path.iterdir()) == [path]  # .tmp was replaced away


def test_read_missing_file_is_empty(tmp_path):
    assert history.read_rows(tmp_path / "absent.csv") == []


def test_malformed_row_fails_loudly(tmp_path):
    path = tmp_path / "nvd_backlog.csv"
    path.write_text("date,backlog_total,awaiting_analysis,"
                    "undergoing_analysis,received\n2026-07-09,oops,1,2,3\n",
                    encoding="utf-8")
    with pytest.raises(ValueError, match="malformed history row"):
        history.read_rows(path)
