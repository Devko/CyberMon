"""Unit tests for claims_support: the year gate and the January rehearsal."""
from __future__ import annotations

import pytest

from . import claims_support as cs


@pytest.fixture
def edition_2026(monkeypatch):
    monkeypatch.setattr(cs, "GENERATION_YEAR", 2026)


def test_complete_years_are_always_judged(edition_2026):
    assert cs.judged(2025)
    assert cs.judged(2025, 3, min_n=1000)


def test_current_year_needs_a_size_bar(edition_2026):
    assert not cs.judged(2026)
    assert not cs.judged(2026, 999, min_n=1000)
    assert cs.judged(2026, 1000, min_n=1000)
    assert not cs.judged(2027, 10**6, min_n=1)


@pytest.mark.parametrize(("mode", "pct"), [("low", 0.0), ("high", 100.0)])
def test_tiny_year_rows_join_every_year_series(monkeypatch, mode, pct):
    monkeypatch.setattr(cs, "GENERATION_YEAR", 2027)
    monkeypatch.setattr(cs, "_TINY", mode)
    obj = {"years": [{"year": 2025, "n": 40000, "pct": 60.0,
                      "first_year": 1999},
                     {"year": 2026, "n": 30000, "pct": 55.0,
                      "first_year": 1999}],
           "by_year": {"2025": 7, "2026": 900},
           "months": [{"month": "2026-12", "n": 5}]}
    cs._add_tiny_year(obj)
    tiny = obj["years"][-1]
    assert tiny == {"year": 2027, "n": 300, "pct": pct, "first_year": 1999}
    assert obj["by_year"]["2027"] == 9
    assert obj["months"] == [{"month": "2026-12", "n": 5}]


def test_series_already_holding_the_year_is_left_alone(monkeypatch):
    monkeypatch.setattr(cs, "GENERATION_YEAR", 2026)
    monkeypatch.setattr(cs, "_TINY", "low")
    rows = [{"year": 2025, "n": 1}, {"year": 2026, "n": 2}]
    cs._add_tiny_year(rows)
    assert rows == [{"year": 2025, "n": 1}, {"year": 2026, "n": 2}]
