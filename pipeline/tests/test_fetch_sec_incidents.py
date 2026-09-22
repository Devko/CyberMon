"""Unit tests for the SEC EDGAR 8-K incident-filing fetcher
(pipeline/fetch_sec_incidents.py). All responses are synthetic; they mimic
the EFTS shape the module docstring documents."""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline import fetch_sec_incidents as fs
from pipeline.fetch_market import EDGAR_URL, EDGAR_USER_AGENT

FIX = Path(__file__).parent / "fixtures" / "sec_incidents.json"


def _hit(adsh="0009999999-24-000001", cik="0009990001", date="2024-01-10",
         form="8-K", items=("1.05", "9.01"), file_type="8-K",
         name="Synthetic Co  (SYN)  (CIK 0009990001)", drop=()):
    src = {"ciks": [cik], "display_names": [name], "file_date": date,
           "form": form, "root_forms": ["8-K"], "adsh": adsh,
           "file_type": file_type}
    if items is not None:
        src["items"] = list(items)
    for key in drop:
        src.pop(key, None)
    return {"_id": f"{adsh}:d1d8k.htm", "_source": src}


def _page(hits, total=None, relation="eq"):
    total = len(hits) if total is None else total
    return {"hits": {"total": {"value": total, "relation": relation},
                     "hits": hits}}


class FakeResponse:
    def __init__(self, payload=None, status_code=200):
        self.status_code = status_code
        self._payload = payload
        self.headers = {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise OSError(f"HTTP {self.status_code}")

    def json(self):
        if self._payload is None:
            raise ValueError("response body is not JSON")
        return self._payload


class FakeSession:
    """Answers each request from ``respond(params)``; records every call."""

    def __init__(self, respond):
        self.respond = respond
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"url": url, "params": dict(params or {}),
                           "headers": dict(headers or {})})
        return self.respond(dict(params or {}))


def _no_sleep(_):
    pass


# ---------------------------------------------------------------- parsing

def test_parse_hit_reads_the_documented_fields():
    f = fs.parse_hit(_hit())
    assert f.adsh == "0009999999-24-000001"
    assert f.cik == "9990001"                       # leading zeros stripped
    assert (f.company, f.ticker) == ("Synthetic Co", "SYN")
    assert (f.file_date, f.form) == ("2024-01-10", "8-K")
    assert f.items == ("1.05", "9.01")
    assert f.primary is True
    assert f.url == ("https://www.sec.gov/Archives/edgar/data/9990001/"
                     "000999999924000001/0009999999-24-000001-index.htm")


def test_parse_hit_falls_back_to_the_id_prefix_for_the_accession_number():
    f = fs.parse_hit(_hit(adsh="0009999999-24-000007", drop=("adsh",)))
    assert f.adsh == "0009999999-24-000007"


@pytest.mark.parametrize("drop", ["file_date", "form", "ciks"])
def test_parse_hit_drops_unplaceable_hits(drop):
    assert fs.parse_hit(_hit(drop=(drop,))) is None


def test_parse_hit_tolerates_missing_items_names_and_file_type():
    f = fs.parse_hit(_hit(items=None, name="", file_type=""))
    assert f.items is None            # metrics fall back to the phrase
    assert f.primary is None          # unknown, not False
    assert f.company == "CIK 9990001" and f.ticker is None


def test_items_are_normalized():
    f = fs.parse_hit(_hit(items=["Item 1.05", "9.01", "1.05"]))
    assert f.items == ("1.05", "9.01")


def test_display_name_without_ticker():
    f = fs.parse_hit(_hit(name="Plain Holdings Inc  (CIK 0009990001)"))
    assert (f.company, f.ticker) == ("Plain Holdings Inc", None)


def test_parse_pages_dedupes_documents_by_accession_number():
    pages = [_page([_hit(file_type="EX-99.1", items=None),
                    _hit(file_type="8-K")])]
    r = fs.parse_pages("item_105", pages)
    assert r.hits == 2 and len(r.filings) == 1
    (f,) = r.filings
    assert f.primary is True and f.items == ("1.05", "9.01")


def test_exhibit_only_filing_is_not_primary():
    r = fs.parse_pages("item_801", [_page([_hit(file_type="EX-99.1")])])
    assert r.filings[0].primary is False


def test_parse_pages_raises_when_most_hits_are_unplaceable():
    pages = [_page([_hit(drop=("file_date",)), _hit(drop=("form",)),
                    _hit(adsh="0009999999-24-000002")])]
    with pytest.raises(ValueError, match="shape has changed"):
        fs.parse_pages("item_105", pages)


def test_parse_pages_raises_without_hits():
    with pytest.raises(ValueError, match="hits.hits"):
        fs.parse_pages("item_105", [{"error": "nope"}])


# ---------------------------------------------------------------- windows

def test_month_windows_clip_to_the_rule_date_and_today():
    w = fs.month_windows("2023-12-18", "2024-02-10")
    assert w == [("2023-12-18", "2023-12-31"), ("2024-01-01", "2024-01-31"),
                 ("2024-02-01", "2024-02-10")]


# ---------------------------------------------------------------- network

def test_fetch_pages_by_offset_and_sends_the_sec_user_agent():
    hits = [_hit(adsh=f"0009999999-24-{i:06d}") for i in range(1, 6)]

    def respond(params):
        if params["forms"] == "8-K" or params["startdt"] != "2024-01-01":
            return FakeResponse(_page([]))
        start = int(params.get("from", 0))
        return FakeResponse(_page(hits[start:start + 2], total=5))

    session = FakeSession(respond)
    data = fs.fetch_sec_incidents("2024-01-31", session=session,
                                  start="2023-12-18", sleep=_no_sleep,
                                  log=lambda m: None)
    r = data.results["item_105"]
    assert len(r.filings) == 5
    jan = [c for c in session.calls if c["params"]["startdt"] == "2024-01-01"
           and c["params"]["forms"] == "8-K,8-K/A"]
    assert [c["params"].get("from") for c in jan] == [None, 2, 4]
    call = session.calls[0]
    assert call["url"] == EDGAR_URL
    assert call["headers"]["User-Agent"] == EDGAR_USER_AGENT
    assert call["params"]["q"] == '"Item 1.05"'
    assert call["params"]["dateRange"] == "custom"


def test_capped_window_is_split_in_half():
    def respond(params):
        span = (params["startdt"], params["enddt"])
        if span == ("2024-01-01", "2024-01-31"):
            return FakeResponse(_page([], total=10_000, relation="gte"))
        return FakeResponse(_page([]))

    session = FakeSession(respond)
    fs.fetch_sec_incidents("2024-01-31", session=session, start="2024-01-01",
                           sleep=_no_sleep, log=lambda m: None)
    spans = [(c["params"]["startdt"], c["params"]["enddt"])
             for c in session.calls if c["params"]["forms"] == "8-K,8-K/A"]
    assert spans == [("2024-01-01", "2024-01-31"), ("2024-01-01", "2024-01-16"),
                     ("2024-01-17", "2024-01-31")]


def test_a_single_capped_day_raises():
    def respond(params):
        return FakeResponse(_page([], total=10_000, relation="gte"))

    with pytest.raises(ValueError, match="single day"):
        fs.fetch_sec_incidents("2024-01-01", session=FakeSession(respond),
                               start="2024-01-01", sleep=_no_sleep,
                               log=lambda m: None)


def test_empty_page_before_the_total_raises():
    def respond(params):
        if params.get("from"):
            return FakeResponse(_page([], total=3))
        return FakeResponse(_page([_hit()], total=3))

    with pytest.raises(ValueError, match="empty page"):
        fs.fetch_sec_incidents("2024-01-05", session=FakeSession(respond),
                               start="2024-01-01", sleep=_no_sleep,
                               log=lambda m: None)


def test_html_block_page_raises():
    with pytest.raises(ValueError):
        fs.fetch_sec_incidents(
            "2024-01-05", session=FakeSession(lambda p: FakeResponse(None)),
            start="2024-01-01", sleep=_no_sleep, log=lambda m: None)


def test_persistent_http_error_raises_after_retries():
    session = FakeSession(lambda p: FakeResponse(None, status_code=503))
    with pytest.raises(OSError):
        fs.fetch_sec_incidents("2024-01-05", session=session,
                               start="2024-01-01", sleep=_no_sleep,
                               log=lambda m: None)
    assert len(session.calls) == 3      # the bounded retry ladder


# ---------------------------------------------------------------- fixture

def test_fixture_is_clearly_synthetic_and_parses():
    import json
    raw = json.loads(FIX.read_text(encoding="utf-8"))
    assert "SYNTHETIC" in raw["_comment"]
    data = fs.load_sec_incidents_file(FIX)
    for r in data.results.values():
        for f in r.filings:
            assert f.company.startswith("Synthetic Fixture Co")
            assert f.adsh.startswith("0009999999-")
