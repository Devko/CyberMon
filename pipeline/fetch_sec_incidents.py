"""SEC EDGAR full-text search: Form 8-K cybersecurity-incident filings
(the Incident Clock feed).

Since 18 December 2023 a US public company must disclose a material
cybersecurity incident on Form 8-K under **Item 1.05**; after the SEC's
May 2024 guidance, incidents not (yet) judged material are disclosed
voluntarily under **Item 8.01**. EDGAR indexes the item list of every 8-K,
so both are countable from the full-text search API module 02 already
reads (``fetch_market.EDGAR_URL``, same User-Agent and pacing rules):

    https://efts.sec.gov/LATEST/search-index
        ?q="<phrase>"&forms=8-K,8-K/A&dateRange=custom
        &startdt=YYYY-MM-DD&enddt=YYYY-MM-DD&from=<offset>

**The two queries are measurement definitions** (:data:`QUERIES`; the
page's methodology prints them from the emitted JSON):

* ``item_105`` — ``q="Item 1.05"``, ``forms=8-K,8-K/A``. The phrase is only
  the recall net; a filing *counts* when EDGAR's own item list for it
  contains ``1.05``. Form 8-K = an original disclosure, 8-K/A = an
  amendment.
* ``item_801`` — ``q="cybersecurity incident"``, ``forms=8-K`` (originals
  only). A filing counts when its item list contains ``8.01`` and not
  ``1.05``, AND the phrase matched the filing's primary 8-K document —
  not only an exhibit, where press-release risk boilerplate ("...
  cybersecurity incidents ...") would otherwise count every dividend
  announcement. Classification lives in
  :mod:`pipeline.sec_incidents_metrics`; this module returns every
  de-duplicated filing the phrase found.

Response shape this module assumes (EFTS is Elasticsearch behind a thin
proxy; the shape below is what module 02 reads for ``hits.total`` plus the
per-hit ``_source`` fields EDGAR's own search UI renders — **not verified
from this sandbox**, which cannot reach efts.sec.gov; the first nightly
must confirm it, see the ``diagnostics`` block the stage emits)::

    {"hits": {"total": {"value": 123, "relation": "eq"},
              "hits": [{"_id": "0001193125-24-012345:d123456d8k.htm",
                        "_source": {"ciks": ["0000012345"],
                                    "display_names": ["Example Corp  (EXMP)  (CIK 0000012345)"],
                                    "file_date": "2024-01-05",
                                    "form": "8-K", "root_forms": ["8-K"],
                                    "file_type": "8-K",
                                    "adsh": "0001193125-24-012345",
                                    "items": ["1.05", "9.01"], ...}}]}}

* One hit per *document*: an 8-K and its EX-99.1 press release are two
  hits of one filing, so filings are **de-duplicated by accession number**
  (``_source.adsh``, falling back to the ``_id`` prefix before ``:``).
* ``from`` is the page offset. The page size is whatever EFTS returns
  (observed 100); the loop advances by the hits actually received and
  treats an empty page before ``hits.total.value`` as a broken response.
  Elasticsearch caps a result window at 10,000 hits and reports
  ``relation: "gte"`` past it, so the stage queries one calendar month at
  a time and splits any window at or over the cap in half, down to a
  single day (a single day over the cap raises — it cannot be counted).
* Defensive parsing: a hit missing its accession number, filing date,
  form or CIK cannot be placed and is dropped (counted); if more than half
  of a query's hits are unplaceable the shape has changed and the fetch
  raises instead of publishing a hollow count. A missing ``items`` list
  is kept as ``None`` and the metrics fall back to the phrase match
  (counted separately, so a nightly can see how much of the count rests
  on the fallback). A missing ``file_type`` leaves "primary document"
  unknown, which the 8.01 rule treats as a match.

Failure policy: any request that fails after the bounded retry (HTTP
429/5xx, connection errors), an HTML block page instead of JSON, or a
structurally broken response raises — the whole edition is all-or-nothing
because a month silently missing would read as a quiet month. The caller
(``pipeline/__main__.py``) carries the previous edition forward marked
stale, like HIBP and Ransomwhere. The stage is stateless: every night
re-reads the whole window (~30 months x 2 queries, a few hundred
requests at SEC's pacing), so late index corrections heal themselves.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Callable

from .fetch_http import get_with_retry
from .fetch_market import EDGAR_URL, EDGAR_USER_AGENT

# Item 1.05 became effective for most registrants on this date (smaller
# reporting companies followed on 2024-06-15). The window starts here.
RULE_EFFECTIVE = "2023-12-18"

QUERIES: dict[str, dict[str, str]] = {
    "item_105": {"q": '"Item 1.05"', "forms": "8-K,8-K/A", "item": "1.05"},
    "item_801": {"q": '"cybersecurity incident"', "forms": "8-K",
                 "item": "8.01"},
}

RESULT_CAP = 10_000            # Elasticsearch's default max result window
_EDGAR_HEADERS = {"User-Agent": EDGAR_USER_AGENT}
_EDGAR_DELAY = 0.25            # fetch_market's pacing: well under 10 req/s
_TIMEOUT = 60.0
_MAX_PAGES = RESULT_CAP // 10  # hard stop for a pager that never ends

_ADSH_RE = re.compile(r"^\d{10}-\d{2}-\d{6}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_ITEM_RE = re.compile(r"\d+\.\d+")
# "Example Corp  (EXMP, EXMPW)  (CIK 0000012345)" -> name, tickers
_DISPLAY_RE = re.compile(
    r"^\s*(?P<name>.*?)\s*(?:\((?P<ticker>[^()]*)\))?\s*\(CIK\s*\d+\)\s*$")


@dataclass
class Filing:
    """One de-duplicated 8-K / 8-K/A filing found by a query."""

    adsh: str
    cik: str                     # primary filer, leading zeros stripped
    company: str
    ticker: str | None
    file_date: str               # YYYY-MM-DD — the filing date, not the incident's
    form: str                    # "8-K" or "8-K/A"
    items: tuple[str, ...] | None    # EDGAR's item list; None = not in the response
    primary: bool | None         # phrase hit the primary 8-K document? None = unknown

    @property
    def url(self) -> str:
        return filing_url(self.cik, self.adsh)


@dataclass
class QueryResult:
    """Every filing one query found across the whole window."""

    query_id: str
    filings: list[Filing] = field(default_factory=list)
    hits: int = 0                # documents received (pre-dedup)
    dropped: int = 0             # hits too broken to place
    requests: int = 0


@dataclass
class SecIncidentData:
    results: dict[str, QueryResult]
    start: str
    end: str


def filing_url(cik: str, adsh: str) -> str:
    """The EDGAR filing index page, built from CIK + accession number."""
    return (f"https://www.sec.gov/Archives/edgar/data/{int(cik)}/"
            f"{adsh.replace('-', '')}/{adsh}-index.htm")


# ------------------------------------------------------------------ parsing

def _str(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _items(value: object) -> tuple[str, ...] | None:
    """EDGAR's item list normalized to ``("1.05", "9.01")``; None when the
    field is absent or unusable (the metrics then fall back to the phrase
    match). Tolerates ``"Item 1.05"`` spellings."""
    if not isinstance(value, list):
        return None
    out: list[str] = []
    for raw in value:
        m = _ITEM_RE.search(str(raw))
        if m and m.group(0) not in out:
            out.append(m.group(0))
    return tuple(out) if out else None


def _company(src: dict, cik: str) -> tuple[str, str | None]:
    names = src.get("display_names")
    raw = _str(names[0]) if isinstance(names, list) and names else ""
    m = _DISPLAY_RE.match(raw) if raw else None
    if m and m.group("name"):
        ticker = _str(m.group("ticker")) or None
        return m.group("name"), ticker
    return (raw or f"CIK {cik}"), None


def parse_hit(hit: object) -> Filing | None:
    """One EFTS hit -> a :class:`Filing`, or None when it cannot be placed
    (no accession number, filing date, form or CIK)."""
    if not isinstance(hit, dict):
        return None
    src = hit.get("_source")
    if not isinstance(src, dict):
        return None
    adsh = _str(src.get("adsh")) or _str(hit.get("_id")).split(":")[0]
    if not _ADSH_RE.match(adsh):
        return None
    file_date = _str(src.get("file_date"))[:10]
    if not _DATE_RE.match(file_date):
        return None
    form = _str(src.get("form")).upper()
    if not form:
        return None
    ciks = src.get("ciks")
    cik_raw = _str(ciks[0]) if isinstance(ciks, list) and ciks else ""
    if not cik_raw.isdigit() or int(cik_raw) == 0:
        return None
    cik = str(int(cik_raw))
    company, ticker = _company(src, cik)
    file_type = _str(src.get("file_type")).upper()
    primary = file_type.startswith("8-K") if file_type else None
    return Filing(adsh=adsh, cik=cik, company=company, ticker=ticker,
                  file_date=file_date, form=form,
                  items=_items(src.get("items")), primary=primary)


def _merge(into: Filing, other: Filing) -> None:
    """Fold another document hit of the same filing into ``into``."""
    if into.items is None and other.items is not None:
        into.items = other.items
    # True if any document hit was the primary 8-K; unknown if any hit
    # could not say; False only when every hit was an exhibit.
    if into.primary is True or other.primary is True:
        into.primary = True
    elif into.primary is None or other.primary is None:
        into.primary = None


def parse_pages(query_id: str, pages: list[dict]) -> QueryResult:
    """Parse and de-duplicate a query's response pages (network or
    fixture). Raises ``ValueError`` when the shape is broken: no
    ``hits.hits`` list, or most hits unplaceable."""
    result = QueryResult(query_id=query_id)
    by_adsh: dict[str, Filing] = {}
    for i, page in enumerate(pages):
        hits = _page_hits(page, f"{query_id} page {i}")
        for hit in hits:
            result.hits += 1
            filing = parse_hit(hit)
            if filing is None:
                result.dropped += 1
                continue
            if filing.adsh in by_adsh:
                _merge(by_adsh[filing.adsh], filing)
            else:
                by_adsh[filing.adsh] = filing
    if result.hits and result.dropped * 2 > result.hits:
        raise ValueError(
            f"sec: {query_id}: {result.dropped} of {result.hits} hits lack "
            f"an accession number, filing date, form or CIK — the EFTS "
            f"response shape has changed")
    result.filings = sorted(by_adsh.values(),
                            key=lambda f: (f.file_date, f.adsh))
    return result


def _page_hits(page: object, where: str) -> list:
    try:
        hits = page["hits"]["hits"]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"sec: {where}: no hits.hits in the response "
                         f"({exc!r})") from None
    if not isinstance(hits, list):
        raise ValueError(f"sec: {where}: hits.hits is not a list")
    return hits


def _page_total(page: object, where: str) -> tuple[int, bool]:
    """(``hits.total.value``, capped?) — capped when ES reports a lower
    bound (``relation`` other than ``"eq"``) or the value reaches the
    result-window cap. A bare-integer total (older ES) is accepted."""
    try:
        total = page["hits"]["total"]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"sec: {where}: no hits.total ({exc!r})") from None
    if isinstance(total, dict):
        value, relation = total.get("value"), total.get("relation", "eq")
    else:
        value, relation = total, "eq"
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"sec: {where}: unusable hits.total {total!r}")
    return value, (relation != "eq" or value >= RESULT_CAP)


# ------------------------------------------------------------------ windows

def month_windows(start: str, end: str) -> list[tuple[str, str]]:
    """Inclusive ``(startdt, enddt)`` pairs, one per calendar month,
    clipped to ``[start, end]``."""
    lo, hi = date.fromisoformat(start), date.fromisoformat(end)
    out: list[tuple[str, str]] = []
    cur = lo
    while cur <= hi:
        nxt = date(cur.year + (cur.month == 12), cur.month % 12 + 1, 1)
        last = min(nxt - timedelta(days=1), hi)
        out.append((cur.isoformat(), last.isoformat()))
        cur = nxt
    return out


def _split(startdt: str, enddt: str) -> list[tuple[str, str]]:
    lo, hi = date.fromisoformat(startdt), date.fromisoformat(enddt)
    mid = lo + (hi - lo) // 2
    return [(lo.isoformat(), mid.isoformat()),
            ((mid + timedelta(days=1)).isoformat(), hi.isoformat())]


# ------------------------------------------------------------------ network

def _get_page(session, query: dict, startdt: str, enddt: str, offset: int,
              sleep, log) -> dict:
    params = {"q": query["q"], "forms": query["forms"],
              "dateRange": "custom", "startdt": startdt, "enddt": enddt}
    if offset:
        params["from"] = offset
    resp = get_with_retry(session, EDGAR_URL, label="sec", params=params,
                          headers=_EDGAR_HEADERS, timeout=_TIMEOUT,
                          sleep=sleep, log=log)
    sleep(_EDGAR_DELAY)
    # SEC's block page is HTML: .json() raising ValueError is the signal.
    return resp.json()


def _fetch_window(session, query_id: str, startdt: str, enddt: str,
                  sleep, log) -> tuple[list[dict], int]:
    """Every response page for one date window, splitting the window when
    it is at or over the result cap. Returns (pages, request count)."""
    query = QUERIES[query_id]
    where = f"{query_id} {startdt}..{enddt}"
    first = _get_page(session, query, startdt, enddt, 0, sleep, log)
    total, capped = _page_total(first, where)
    if capped:
        if startdt == enddt:
            raise ValueError(f"sec: {where}: a single day holds "
                             f"{RESULT_CAP}+ hits — cannot be counted")
        pages: list[dict] = []
        requests = 1
        for lo, hi in _split(startdt, enddt):
            sub, n = _fetch_window(session, query_id, lo, hi, sleep, log)
            pages += sub
            requests += n
        return pages, requests
    pages = [first]
    received = len(_page_hits(first, where))
    while received < total:
        if len(pages) >= _MAX_PAGES:
            raise ValueError(f"sec: {where}: pager exceeded {_MAX_PAGES} "
                             f"pages")
        page = _get_page(session, query, startdt, enddt, received, sleep,
                         log)
        hits = _page_hits(page, where)
        if not hits:
            raise ValueError(f"sec: {where}: empty page at offset "
                             f"{received} of {total} hits")
        pages.append(page)
        received += len(hits)
    return pages, len(pages)


def fetch_sec_incidents(end: str, session=None, start: str = RULE_EFFECTIVE,
                        sleep=time.sleep,
                        log: Callable[[str], None] = print
                        ) -> SecIncidentData:
    """Run both queries month by month over ``[start, end]``. Any failure
    raises (see module docstring) — the caller carries forward."""
    import requests

    session = session or requests.Session()
    results: dict[str, QueryResult] = {}
    for query_id in QUERIES:
        pages: list[dict] = []
        requests_made = 0
        for lo, hi in month_windows(start, end):
            sub, n = _fetch_window(session, query_id, lo, hi, sleep, log)
            pages += sub
            requests_made += n
        result = parse_pages(query_id, pages)
        result.requests = requests_made
        log(f"  sec/{query_id}: {result.hits} hits -> "
            f"{len(result.filings)} filings ({result.dropped} dropped, "
            f"{requests_made} requests)")
        results[query_id] = result
    return SecIncidentData(results=results, start=start, end=end)


def load_sec_incidents_file(path: Path) -> SecIncidentData:
    """Offline fixture: ``{"start", "end", "pages": {query_id: [EFTS
    response page, ...]}}`` — the same parser the network path uses."""
    obj = json.loads(path.read_text(encoding="utf-8"))
    results = {qid: parse_pages(qid, obj["pages"].get(qid, []))
               for qid in QUERIES}
    return SecIncidentData(results=results, start=obj.get("start",
                                                          RULE_EFFECTIVE),
                           end=obj["end"])
