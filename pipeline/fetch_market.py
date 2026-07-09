"""Security Market fetchers: monthly interest counts per term x source.

Three public corpora feed one nightly sync-state file
(``.cache/market_state.json``, plain JSON — it stays small and greppable):

* **GDELT DOC 2.0** (news volume) — ``mode=timelinevolraw`` returns the raw
  *daily* article curve for the last 5 years in a single response, so GDELT
  has no backfill concept: every night re-fetches each term's whole curve,
  buckets it into months, and replaces the cached curve (any success is
  self-healing). GDELT is slow (8-55s per response) and rate-limits
  viciously — HTTP 429 with a *plaintext* (non-JSON) body and penalty
  windows that outlast a minute — so terms are spaced ``10s`` apart, a
  failed term gets exactly one retry after ``75s``, and a term that still
  fails keeps its previously cached months for the night. Because a
  penalty window that opens mid-pass punishes whichever terms happen to
  trail it, the pass order is not fixed (a fixed order starves the same
  tail terms night after night): terms with *no* cached GDELT months
  fetch first — they are the ones rendering blank on the site, and a
  single success heals them completely — and within the starved group
  and the rest alike the starting offset rotates with the UTC day
  ordinal (:func:`gdelt_term_order`), so every term periodically gets a
  turn at the front.
* **Hacker News via Algolia** (practitioner buzz) — one cheap request per
  *(term, month)* cell: ``hitsPerPage=0`` plus ``created_at_i`` month-bound
  filters, reading only ``nbHits`` (default tags, i.e. stories+comments).
  One request per cell means a full 60-month x N-term history cannot be
  fetched in one night, so HN is the only source with a backfill queue.
  Nightly: the current *and* previous months are always re-fetched for
  every term (the closing month must finalize), any window month still
  missing from the series is appended to the FIFO ``pending`` queue
  (oldest month first) as ``["hn", term_id, "YYYY-MM"]``, and up to
  ``backfill_batch`` queued cells are drained per run. A failed cell stays
  queued. Only ``hn`` entries ever live in the queue.
* **arXiv API** (research attention, scoped to ``cat:cs.CR``) — an Atom
  feed paged 2000 entries at a time (must be https; http 301s). Each night
  re-buckets every term's submissions over the whole window by
  ``<published>`` date, capped at 3 pages per term (logged when the cap
  bites), keeping the term's cached months on failure. arXiv's ToS asks
  for at least 3s between API requests; we sleep 3.1s after every one.

The state is a cache, never a source of truth: months are pruned to the
rolling window on every sync, and pending entries whose month left the
window (or whose term left the watchlist) are dropped. A missing/unreadable
state is first reconstructed from the previously published market_hype.json
(:func:`reconstruct_state` — the raw ``n`` counts round-trip losslessly),
so a lost cache does not restart the ~960-cell HN backfill from zero and
regress the published data; with no usable published output either,
everything rebuilds — GDELT and arXiv fully the next night, HN via the
pending queue.
"""
from __future__ import annotations

import json
import time
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Callable

from .market_terms import TermDef

GDELT_URL = "https://api.gdeltproject.org/api/v2/doc/doc"
HN_URL = "https://hn.algolia.com/api/v1/search"
ARXIV_URL = "https://export.arxiv.org/api/query"
USER_AGENT = "CyberMon/1.0 (+https://github.com/Devko/CyberMon)"
STATE_VERSION = 1
STATE_FILENAME = "market_state.json"
ARXIV_PAGE_SIZE = 2000

_HEADERS = {"User-Agent": USER_AGENT}
_TIMEOUT = 60.0
_GDELT_TIMEOUT = 90.0          # measured: normal responses take 8-55s
_GDELT_TERM_DELAY = 10.0       # politeness gap between term curves
_GDELT_RETRY_DELAY = 75.0      # penalty windows outlast 60s; wait them out
_HN_DELAY = 1.0
_ARXIV_DELAY = 3.1             # arXiv ToS: >= 3s between API requests
_ARXIV_MAX_PAGES = 3
_RETRY_STATUSES = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 4
_ATOM = "{http://www.w3.org/2005/Atom}"
_OPENSEARCH = "{http://a9.com/-/spec/opensearch/1.1/}"


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------ month helpers

def month_window(now: datetime, months: int = 60) -> list[str]:
    """Chronological list of ``YYYY-MM`` strings ending at ``now``'s month."""
    year, month = now.year, now.month
    out: list[str] = []
    for _ in range(max(int(months), 1)):
        out.append(f"{year:04d}-{month:02d}")
        year, month = (year, month - 1) if month > 1 else (year - 1, 12)
    out.reverse()
    return out


def _next_month(month: str) -> str:
    year, mon = int(month[:4]), int(month[5:7])
    year, mon = (year + 1, 1) if mon == 12 else (year, mon + 1)
    return f"{year:04d}-{mon:02d}"


def _month_epochs(month: str) -> tuple[int, int]:
    """[start, end) epoch seconds of a UTC calendar month."""
    year, mon = int(month[:4]), int(month[5:7])
    start = datetime(year, mon, 1, tzinfo=timezone.utc)
    ny, nm = (year + 1, 1) if mon == 12 else (year, mon + 1)
    end = datetime(ny, nm, 1, tzinfo=timezone.utc)
    return int(start.timestamp()), int(end.timestamp())


# ---------------------------------------------------------------- state I/O

def _state_path(cache_dir: Path) -> Path:
    return cache_dir / STATE_FILENAME


def load_state(cache_dir: Path,
               log: Callable[[str], None] = print) -> dict | None:
    """Cached market sync state, or None when absent/unreadable (the sync
    then rebuilds from scratch — the state is only ever a cache)."""
    path = _state_path(cache_dir)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log(f"warning: ignoring unreadable market state {path}: {exc!r}")
        return None


def save_state(cache_dir: Path, state: dict) -> None:
    """Write the state atomically (temp file, then ``replace``) so an
    interrupted run leaves either the old file or the new one."""
    path = _state_path(cache_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, separators=(",", ":")),
                   encoding="utf-8")
    tmp.replace(path)


def reconstruct_state(out_dir: Path,
                      log: Callable[[str], None] = print) -> dict | None:
    """Best-effort sync state rebuilt from a previously published
    ``out_dir/market_hype.json``, for when the cached state is lost (first
    run on a fresh CI cache, actions/cache eviction): the raw ``n`` counts
    per term/source/month become the series, window months absent from a
    term's hn series re-enter the pending queue (oldest month first, like
    the nightly enqueue), and ``last_sync`` carries the file's
    ``generated_at``. None when the file is absent or unusable — the sync
    then rebuilds from scratch, exactly as before."""
    path = out_dir / "market_hype.json"
    if not path.exists():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        last_sync = str(obj["generated_at"])
        window = month_window(
            datetime.strptime(last_sync, "%Y-%m-%dT%H:%M:%SZ")
                    .replace(tzinfo=timezone.utc),
            int(obj.get("window_months") or 60))
        series: dict[str, dict[str, dict[str, int]]] = {}
        term_ids: list[str] = []
        for term in obj["terms"]:
            term_id = str(term["id"])
            term_ids.append(term_id)
            sources = {}
            for source, points in (term.get("series") or {}).items():
                months = {str(p["month"]): int(p["n"]) for p in points}
                if months:
                    sources[source] = months
            if sources:
                series[term_id] = sources
        pending = [["hn", term_id, month]
                   for month in window for term_id in term_ids
                   if month not in series.get(term_id, {}).get("hn", {})]
    except (OSError, KeyError, TypeError, ValueError) as exc:
        log(f"warning: cannot reconstruct market state from {path}: {exc!r}")
        return None
    log("  market: reconstructed sync state from published market_hype.json "
        f"({len(series)} term(s), {len(pending)} hn cell(s) re-queued)")
    return {"version": STATE_VERSION, "last_sync": last_sync,
            "series": series, "pending": pending}


# ------------------------------------------------------------------ pruning

def _pruned_state(state: dict | None, terms: list[TermDef],
                  window_set: set[str],
                  log: Callable[[str], None]) -> tuple[dict, list]:
    """Carry the prior state forward, dropping months outside the window,
    terms no longer on the watchlist, and pending entries that are out of
    window / duplicated / not ``hn`` cells."""
    known = {t.id for t in terms}
    series: dict[str, dict[str, dict[str, int]]] = {}
    pending: list[list] = []
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
        if state:
            log("  market: discarding unrecognized cached state")
        return series, pending
    for term_id, sources in (state.get("series") or {}).items():
        if term_id not in known:
            continue
        kept_sources = {}
        for source, months in (sources or {}).items():
            try:
                kept = {m: int(n) for m, n in months.items()
                        if m in window_set}
            except (AttributeError, TypeError, ValueError):
                continue
            if kept:
                kept_sources[source] = kept
        if kept_sources:
            series[term_id] = kept_sources
    seen: set[tuple] = set()
    for entry in state.get("pending") or []:
        try:
            source, term_id, month = entry
        except (TypeError, ValueError):
            continue
        key = (source, term_id, month)
        if (source == "hn" and term_id in known and month in window_set
                and key not in seen):
            pending.append([source, term_id, month])
            seen.add(key)
    return series, pending


# -------------------------------------------------------------------- GDELT

def _rotated(group: list[TermDef], offset: int) -> list[TermDef]:
    k = offset % len(group) if group else 0
    return group[k:] + group[:k]


def gdelt_term_order(terms: list[TermDef], series: dict,
                     day: date) -> list[TermDef]:
    """Deterministic per-day fetch order for the GDELT pass (pure — same
    inputs, same order): terms whose cached GDELT series is empty come
    first, so the terms visibly blank on the site heal fastest, then the
    terms that already have cached months. Within each group the starting
    offset rotates with ``day``'s ordinal, so when a rate-limit penalty
    bites mid-pass it lands on different terms each night instead of
    starving a fixed tail."""
    offset = day.toordinal()
    starved = [t for t in terms if not series.get(t.id, {}).get("gdelt")]
    cached = [t for t in terms if series.get(t.id, {}).get("gdelt")]
    return _rotated(starved, offset) + _rotated(cached, offset)


def _bucket_gdelt(payload: dict) -> dict[str, int]:
    """Sum the daily ``timeline[0].data`` points into ``{YYYY-MM: count}``."""
    timeline = payload.get("timeline") or []
    points = (timeline[0].get("data") or []) if timeline else []
    monthly: dict[str, int] = {}
    for point in points:
        date = str(point.get("date", ""))  # "20210711T000000Z"
        if len(date) >= 6:
            month = f"{date[:4]}-{date[4:6]}"
            monthly[month] = monthly.get(month, 0) + int(point.get("value")
                                                         or 0)
    return monthly


def _fetch_gdelt(session, term: TermDef, sleep: Callable[[float], None],
                 log: Callable[[str], None]) -> dict[str, int] | None:
    """One term's whole 5y curve as ``{YYYY-MM: count}``, or None when
    GDELT stayed unusable after the single long-delay retry."""
    params = {"query": term.gdelt_query, "mode": "timelinevolraw",
              "format": "json", "timespan": "5y"}
    message = "no attempt made"
    for attempt in (1, 2):
        try:
            resp = session.get(GDELT_URL, params=params, headers=_HEADERS,
                               timeout=_GDELT_TIMEOUT)
            if resp.status_code == 200:
                payload = resp.json()  # 429 penalty pages are plaintext
                if isinstance(payload, dict) and "timeline" in payload:
                    return _bucket_gdelt(payload)
                message = "GDELT returned JSON without a timeline"
            else:
                message = f"GDELT returned HTTP {resp.status_code}"
        except (OSError, ValueError) as exc:  # connection error / non-JSON
            message = f"GDELT response unusable: {exc!r}"
        if attempt == 1:
            log(f"  market/gdelt: {message} ({term.id}); one retry in "
                f"{_GDELT_RETRY_DELAY:.0f}s")
            sleep(_GDELT_RETRY_DELAY)
    log(f"  market/gdelt: {message} ({term.id}); keeping cached months")
    return None


def _gdelt_pass(session, series: dict, terms: list[TermDef],
                window_set: set[str], day: date,
                sleep: Callable[[float], None],
                log: Callable[[str], None]) -> None:
    ordered = gdelt_term_order(terms, series, day)
    starved = sum(1 for t in ordered
                  if not series.get(t.id, {}).get("gdelt"))
    if starved:
        log(f"  market/gdelt: {starved} term(s) with no cached months "
            f"fetch first")
    refreshed = kept = 0
    for i, term in enumerate(ordered):
        if i:
            sleep(_GDELT_TERM_DELAY)
        monthly = _fetch_gdelt(session, term, sleep, log)
        if monthly is None:
            kept += 1
            continue
        series.setdefault(term.id, {})["gdelt"] = \
            {m: n for m, n in monthly.items() if m in window_set}
        refreshed += 1
    log(f"  market/gdelt: {refreshed}/{len(terms)} term curve(s) refreshed, "
        f"{kept} kept from cache")


# -------------------------------------------------------------------- arXiv

def _fetch_arxiv(session, term: TermDef, window: list[str],
                 sleep: Callable[[float], None],
                 log: Callable[[str], None]) -> dict[str, int] | None:
    """Bucket one term's cs.CR submissions over the window into
    ``{YYYY-MM: count}``, or None on failure (keep the cached months)."""
    date_start = window[0].replace("-", "") + "010000"
    date_end = _next_month(window[-1]).replace("-", "") + "010000"
    search_query = (f"cat:cs.CR AND all:{term.arxiv_query} "
                    f"AND submittedDate:[{date_start} TO {date_end}]")
    monthly: dict[str, int] = {}
    fetched = 0
    total: int | None = None
    pages = 0
    while total is None or fetched < total:
        if pages >= _ARXIV_MAX_PAGES:
            log(f"  market/arxiv: {term.id} capped at {_ARXIV_MAX_PAGES} "
                f"page(s) ({fetched}/{total} entries bucketed)")
            break
        params = {"search_query": search_query, "start": fetched,
                  "max_results": ARXIV_PAGE_SIZE}
        try:
            resp = session.get(ARXIV_URL, params=params, headers=_HEADERS,
                               timeout=_TIMEOUT)
            sleep(_ARXIV_DELAY)
            pages += 1
            if resp.status_code != 200:
                raise ValueError(f"HTTP {resp.status_code}")
            root = ET.fromstring(resp.text)
            total = int(root.findtext(_OPENSEARCH + "totalResults"))
        except (OSError, TypeError, ValueError, ET.ParseError) as exc:
            log(f"  market/arxiv: request failed ({term.id}): {exc!r}; "
                f"keeping cached months")
            return None
        entries = root.findall(_ATOM + "entry")
        for entry in entries:
            published = entry.findtext(_ATOM + "published") or ""
            if len(published) >= 7:  # ISO date -> "YYYY-MM"
                month = published[:7]
                monthly[month] = monthly.get(month, 0) + 1
        if not entries:  # defensive: never loop forever on an empty page
            break
        fetched += len(entries)
    return monthly


def _arxiv_pass(session, series: dict, terms: list[TermDef],
                window: list[str], window_set: set[str],
                sleep: Callable[[float], None],
                log: Callable[[str], None]) -> None:
    refreshed = kept = 0
    for term in terms:
        monthly = _fetch_arxiv(session, term, window, sleep, log)
        if monthly is None:
            kept += 1
            continue
        series.setdefault(term.id, {})["arxiv"] = \
            {m: n for m, n in monthly.items() if m in window_set}
        refreshed += 1
    log(f"  market/arxiv: {refreshed}/{len(terms)} term curve(s) "
        f"re-bucketed, {kept} kept from cache")


# ----------------------------------------------------------------------- HN

def _fetch_hn_month(session, term: TermDef, month: str,
                    sleep: Callable[[float], None],
                    log: Callable[[str], None]) -> int | None:
    """``nbHits`` for one (term, calendar month) cell, or None after the
    retry budget is spent (the caller keeps whatever it had)."""
    epoch_start, epoch_end = _month_epochs(month)
    params = {"query": term.hn_query,
              "numericFilters": (f"created_at_i>={epoch_start},"
                                 f"created_at_i<{epoch_end}"),
              "hitsPerPage": 0}
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            resp = session.get(HN_URL, params=params, headers=_HEADERS,
                               timeout=_TIMEOUT)
            if resp.status_code == 200:
                return int(resp.json()["nbHits"])
            retryable = resp.status_code in _RETRY_STATUSES
            message = f"HN returned HTTP {resp.status_code}"
        except (OSError, KeyError, TypeError, ValueError) as exc:
            retryable = True
            message = f"HN request failed: {exc!r}"
        if not retryable or attempt == _MAX_ATTEMPTS:
            log(f"  market/hn: {message} ({term.id} {month}, attempt "
                f"{attempt}/{_MAX_ATTEMPTS}); leaving cell for a later run")
            return None
        backoff = min(10.0 * 2 ** (attempt - 1), 120.0)
        log(f"  market/hn: {message}; retrying in {backoff:.0f}s "
            f"(attempt {attempt}/{_MAX_ATTEMPTS})")
        sleep(backoff)
    return None  # unreachable


def _hn_pass(session, series: dict, pending: list[list],
             terms: list[TermDef], window: list[str], backfill_batch: int,
             sleep: Callable[[float], None],
             log: Callable[[str], None]) -> list[list]:
    """Refresh current+previous month per term, keep the backfill queue in
    shape, drain up to ``backfill_batch`` cells; returns the new queue."""
    refresh_months = window[-2:]  # previous + current: the closing month
    refreshed = 0                 # must finalize once the calendar flips
    for term in terms:
        for month in refresh_months:
            count = _fetch_hn_month(session, term, month, sleep, log)
            sleep(_HN_DELAY)
            if count is not None:
                series.setdefault(term.id, {}) \
                      .setdefault("hn", {})[month] = count
                refreshed += 1
    # A queued cell the nightly refresh just filled is no longer pending.
    hn_months = lambda tid: series.get(tid, {}).get("hn", {})  # noqa: E731
    pending = [e for e in pending if e[2] not in hn_months(e[1])]
    queued = {tuple(e) for e in pending}
    for month in window:  # oldest first, so backfill walks forward in time
        for term in terms:
            entry = ("hn", term.id, month)
            if month not in hn_months(term.id) and entry not in queued:
                pending.append(list(entry))
                queued.add(entry)
    by_id = {t.id: t for t in terms}
    still_pending: list[list] = []
    backfilled = 0
    for entry in pending[:backfill_batch]:  # FIFO drain
        _, term_id, month = entry
        count = _fetch_hn_month(session, by_id[term_id], month, sleep, log)
        sleep(_HN_DELAY)
        if count is None:
            still_pending.append(entry)  # stays queued for the next night
        else:
            series.setdefault(term_id, {}) \
                  .setdefault("hn", {})[month] = count
            backfilled += 1
    pending = still_pending + pending[backfill_batch:]
    log(f"  market/hn: {refreshed} refresh cell(s), {backfilled} "
        f"backfilled, {len(pending)} pending remain")
    return pending


# --------------------------------------------------------------------- sync

def sync_state(state: dict | None, terms: list[TermDef],
               window_months: int = 60, backfill_batch: int = 8,
               now: datetime | None = None, session=None,
               sleep: Callable[[float], None] = time.sleep,
               log: Callable[[str], None] = print) -> dict:
    """Return up-to-date market sync state (``{version, last_sync, series,
    pending}``): prune the prior state to the rolling window, re-fetch the
    whole GDELT and arXiv curves per term (GDELT in the starved-first,
    day-rotated order of :func:`gdelt_term_order`), refresh the two most
    recent HN months per term, and drain up to ``backfill_batch`` HN cells
    from the pending queue (see the module docstring for the per-source
    policy)."""
    if session is None:
        import requests

        session = requests.Session()
    now = now or datetime.now(timezone.utc)
    window = month_window(now, window_months)
    window_set = set(window)
    series, pending = _pruned_state(state, terms, window_set, log)
    _gdelt_pass(session, series, terms, window_set, now.date(), sleep, log)
    _arxiv_pass(session, series, terms, window, window_set, sleep, log)
    pending = _hn_pass(session, series, pending, terms, window,
                       backfill_batch, sleep, log)
    return {"version": STATE_VERSION, "last_sync": _iso(now),
            "series": series, "pending": pending}
