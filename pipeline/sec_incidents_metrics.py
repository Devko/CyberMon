"""Incident Clock: SEC Form 8-K cybersecurity-incident filings
(``sec_incidents.json``).

Reads the de-duplicated filings :mod:`pipeline.fetch_sec_incidents` found
and classifies them by EDGAR's own item list:

* **Item 1.05 originals** — form 8-K whose item list contains ``1.05``;
* **Item 1.05 amendments** — form 8-K/A whose item list contains ``1.05``;
* **Item 8.01 cyber filings** — form 8-K whose item list contains ``8.01``
  and not ``1.05``, where the phrase matched the primary document (not only
  an exhibit), and whose accession number is not already an Item 1.05
  filing.

When a filing's item list is missing from the response, the phrase match is
the fallback (``diagnostics.phrase_fallback_*`` counts those filings; a
healthy EFTS response keeps them at zero).

Signals: filings per month and quarter (by **filing date** — the incident
date is prose, not a field, so nothing here measures breach-to-disclosure
time); distinct filers (primary CIK); the amendment lag — for each Item
1.05 amendment, the nearest prior Item 1.05 original from the same CIK
(same day allowed), and for each original its FIRST amendment's lag in
days; and a receipts board of the most recent Item 1.05 filings with their
EDGAR links.

The first month (December 2023, from the 18th — the rule's effective date)
and the current month are partial and flagged, as are their quarters.

A stateless stage: the whole window is re-read every night, so there is no
history file. :func:`build_empty` is the honest edition for "never fetched
yet" — no series, no totals, nothing implied to be zero.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date
from statistics import median

from .fetch_sec_incidents import (QUERIES, RULE_EFFECTIVE, Filing,
                                  SecIncidentData)

RECENT_LIMIT = 25
# (label, lo, hi) in whole days, hi inclusive; None = open-ended.
LAG_BUCKETS: list[tuple[str, int, int | None]] = [
    ("0–7 days", 0, 7),
    ("8–30 days", 8, 30),
    ("31–90 days", 31, 90),
    ("91–180 days", 91, 180),
    ("181–365 days", 181, 365),
    ("over a year", 366, None),
]
LAG_BUCKET_LABELS = [b[0] for b in LAG_BUCKETS]
SERIES_KEYS = ("originals", "amendments", "voluntary")


# ------------------------------------------------------------ classification

def is_item_105(f: Filing) -> tuple[bool, bool]:
    """(counts as an Item 1.05 filing, decided by phrase fallback)."""
    if f.form not in ("8-K", "8-K/A"):
        return False, False
    if f.items is not None:
        return "1.05" in f.items, False
    return f.primary is not False, True


def is_item_801(f: Filing) -> tuple[bool, bool]:
    """(counts as an Item 8.01 cyber filing, decided by phrase fallback).
    The caller also excludes accession numbers already counted as 1.05."""
    if f.form != "8-K" or f.primary is False:
        return False, False
    if f.items is not None:
        return ("8.01" in f.items and "1.05" not in f.items), False
    return True, True


# ------------------------------------------------------------------ helpers

def _month_range(first: str, last: str) -> list[str]:
    y, m = int(first[:4]), int(first[5:7])
    out: list[str] = []
    while f"{y:04d}-{m:02d}" <= last:
        out.append(f"{y:04d}-{m:02d}")
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    return out


def _quarter(month: str) -> str:
    return f"{month[:4]}-Q{(int(month[5:7]) - 1) // 3 + 1}"


def _days(a: str, b: str) -> int:
    return (date.fromisoformat(b) - date.fromisoformat(a)).days


def _definitions() -> dict:
    return {qid: dict(q) for qid, q in QUERIES.items()}


def _window(generated_at: str) -> dict:
    return {"start": RULE_EFFECTIVE, "end": generated_at[:10]}


# -------------------------------------------------------------- amendments

def amendment_lag(originals: list[Filing], amendments: list[Filing]
                  ) -> tuple[dict, dict[str, tuple[str, int]]]:
    """Match each amendment to the nearest prior original from the same
    CIK. Returns the lag block and ``{amendment adsh: (original date,
    lag days)}`` for the receipts board."""
    by_cik: dict[str, list[Filing]] = defaultdict(list)
    for o in originals:
        by_cik[o.cik].append(o)
    for lst in by_cik.values():
        lst.sort(key=lambda f: (f.file_date, f.adsh))
    first_lag: dict[str, int] = {}          # original adsh -> first lag
    matched: dict[str, tuple[str, int]] = {}
    unmatched = 0
    for a in sorted(amendments, key=lambda f: (f.file_date, f.adsh)):
        prior = [o for o in by_cik.get(a.cik, [])
                 if o.file_date <= a.file_date]
        if not prior:
            unmatched += 1
            continue
        orig = prior[-1]
        lag = _days(orig.file_date, a.file_date)
        matched[a.adsh] = (orig.file_date, lag)
        first_lag.setdefault(orig.adsh, lag)
    lags = sorted(first_lag.values())
    buckets = []
    for label, lo, hi in LAG_BUCKETS:
        n = sum(1 for d in lags if d >= lo and (hi is None or d <= hi))
        buckets.append({"label": label, "n": n})
    block = {
        "originals": len(originals),
        "amended": len(lags),
        "matched_amendments": len(matched),
        "unmatched_amendments": unmatched,
        "median_days": round(float(median(lags)), 1) if lags else None,
        "max_days": lags[-1] if lags else None,
        "buckets": buckets,
    }
    return block, matched


# ------------------------------------------------------------------ builders

def build_empty(generated_at: str, note: str = "not_fetched") -> dict:
    """The edition before the first successful fetch: definitions and the
    window only. Series are empty and totals are null — never zeros, which
    would claim a count nobody made."""
    return {
        "generated_at": generated_at,
        "status": "empty",
        "status_reason": note,
        "window": _window(generated_at),
        "definitions": _definitions(),
        "monthly": [],
        "quarterly": [],
        "totals": None,
        "amendment_lag": None,
        "recent": [],
    }


def build_sec_incidents(data: SecIncidentData, generated_at: str,
                        recent_limit: int = RECENT_LIMIT) -> dict:
    r105 = data.results["item_105"]
    r801 = data.results["item_801"]
    lo, hi = RULE_EFFECTIVE, generated_at[:10]

    def in_window(f: Filing) -> bool:
        return lo <= f.file_date <= hi

    originals: list[Filing] = []
    amendments: list[Filing] = []
    fallback_105 = fallback_801 = 0
    for f in filter(in_window, r105.filings):
        ok, by_phrase = is_item_105(f)
        if not ok:
            continue
        fallback_105 += by_phrase
        (amendments if f.form == "8-K/A" else originals).append(f)
    taken = {f.adsh for f in originals + amendments}
    voluntary: list[Filing] = []
    for f in filter(in_window, r801.filings):
        if f.adsh in taken:
            continue
        ok, by_phrase = is_item_801(f)
        if ok:
            fallback_801 += by_phrase
            voluntary.append(f)

    last_month = generated_at[:7]
    first_month = RULE_EFFECTIVE[:7]
    months = _month_range(first_month, last_month)
    counts = {m: dict.fromkeys(SERIES_KEYS, 0) for m in months}
    for key, lst in (("originals", originals), ("amendments", amendments),
                     ("voluntary", voluntary)):
        for f in lst:
            counts[f.file_date[:7]][key] += 1
    partial_months = {first_month, last_month}
    monthly = [{"month": m, **counts[m], "partial": m in partial_months}
               for m in months]
    quarters: dict[str, dict] = {}
    for row in monthly:
        q = quarters.setdefault(_quarter(row["month"]), {
            "quarter": _quarter(row["month"]),
            **dict.fromkeys(SERIES_KEYS, 0), "partial": False})
        for key in SERIES_KEYS:
            q[key] += row[key]
    partial_q = {_quarter(RULE_EFFECTIVE[:7]), _quarter(last_month)}
    quarterly = []
    for q in quarters.values():
        q["partial"] = q["quarter"] in partial_q
        quarterly.append(q)

    lag, matched = amendment_lag(originals, amendments)
    recent_src = sorted(originals + amendments,
                        key=lambda f: (f.file_date, f.adsh), reverse=True)
    recent = []
    for f in recent_src[:recent_limit]:
        row = {"date": f.file_date, "form": f.form, "company": f.company,
               "ticker": f.ticker, "cik": f.cik, "adsh": f.adsh,
               "url": f.url}
        if f.adsh in matched:
            row["original_date"], row["lag_days"] = matched[f.adsh]
        recent.append(row)

    return {
        "generated_at": generated_at,
        "status": "ok",
        "window": _window(generated_at),
        "definitions": _definitions(),
        "monthly": monthly,
        "quarterly": quarterly,
        "totals": {
            "originals": len(originals),
            "amendments": len(amendments),
            "voluntary": len(voluntary),
            "companies_105": len({f.cik for f in originals + amendments}),
            "companies_801": len({f.cik for f in voluntary}),
            "latest_105": recent[0]["date"] if recent else None,
        },
        "amendment_lag": lag,
        "recent": recent,
        "diagnostics": {
            "hits_105": r105.hits, "hits_801": r801.hits,
            "filings_105": len(r105.filings),
            "filings_801": len(r801.filings),
            "dropped_105": r105.dropped, "dropped_801": r801.dropped,
            "phrase_fallback_105": fallback_105,
            "phrase_fallback_801": fallback_801,
            "requests": r105.requests + r801.requests,
        },
    }


def source_block(obj: dict, fetched_at: str) -> dict:
    """``meta.sources.sec_incidents`` for a fresh edition."""
    t = obj["totals"]
    return {"fetched_at": fetched_at, "filings_105": t["originals"],
            "amendments_105": t["amendments"],
            "filings_801": t["voluntary"]}


EMPTY_SOURCE = {"status": "empty"}
