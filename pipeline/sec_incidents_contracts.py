"""Contract for the Incident Clock output (sec_incidents.json).

Same philosophy as pipeline/contracts.py — a hand-rolled stdlib validator
that fails loudly — in its own module (the botnet_contracts pattern).

Two editions are legal:

* ``status: "empty"`` — before the first successful EDGAR fetch. Series and
  the receipts board are empty lists; ``totals`` and ``amendment_lag`` are
  null (never zeros: nobody counted). The page renders "the first nightly
  fills this page" cards, not error cards.
* ``status: "ok"`` — every month from the rule's effective month to the
  edition month, contiguous; the quarterly rows are exact sums of the
  monthly ones; totals equal the series sums; the amendment-lag block
  partitions consistently; receipts are newest-first with EDGAR links
  built from CIK + accession number.

The query definitions ride in both editions: they are the measurement
definition the methodology prints.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from .contracts import (DATE_RE, _check_bool, _check_generated_at,
                        _check_int, _check_list, _check_num, _check_str,
                        _fail, _get)
from .fetch_sec_incidents import QUERIES, RULE_EFFECTIVE
from .sec_incidents_metrics import LAG_BUCKET_LABELS, SERIES_KEYS

_ADSH_RE = re.compile(r"^\d{10}-\d{2}-\d{6}$")
_MONTH_RE = re.compile(r"^\d{4}-\d{2}$")
_QUARTER_RE = re.compile(r"^\d{4}-Q[1-4]$")
_FORMS = ("8-K", "8-K/A")
P = "sec_incidents"


def _check_definitions(obj: Any) -> None:
    defs = _get(obj, "definitions", P)
    for qid, q in QUERIES.items():
        d = _get(defs, qid, f"{P}.definitions")
        for key in ("q", "forms", "item"):
            v = _get(d, key, f"{P}.definitions.{qid}")
            _check_str(v, f"{P}.definitions.{qid}.{key}")
            if v != q[key]:
                _fail(f"{P}.definitions.{qid}.{key}",
                      f"{v!r} differs from the pipeline's query {q[key]!r}")


def _next_month(month: str) -> str:
    y, m = int(month[:4]), int(month[5:7])
    return f"{y + (m == 12):04d}-{m % 12 + 1:02d}"


def _check_monthly(rows: list, generated_at: str) -> dict[str, int]:
    expect = RULE_EFFECTIVE[:7]
    last = generated_at[:7]
    sums = dict.fromkeys(SERIES_KEYS, 0)
    for i, row in enumerate(rows):
        p = f"{P}.monthly[{i}]"
        month = _get(row, "month", p)
        _check_str(month, f"{p}.month", _MONTH_RE)
        if month != expect:
            _fail(f"{p}.month", f"expected {expect} (months must be "
                                f"contiguous from {RULE_EFFECTIVE[:7]})")
        for key in SERIES_KEYS:
            _check_int(_get(row, key, p), f"{p}.{key}")
            sums[key] += row[key]
        partial = _get(row, "partial", p)
        _check_bool(partial, f"{p}.partial")
        if partial != (month in (RULE_EFFECTIVE[:7], last)):
            _fail(f"{p}.partial", "only the first and the edition month "
                                  "are partial")
        expect = _next_month(month)
    if not rows or rows[-1]["month"] != last:
        _fail(f"{P}.monthly", f"must run through the edition month {last}")
    return sums


def _check_quarterly(rows: list, monthly: list) -> None:
    want: dict[str, dict[str, int]] = {}
    for m in monthly:
        q = f"{m['month'][:4]}-Q{(int(m['month'][5:7]) - 1) // 3 + 1}"
        slot = want.setdefault(q, dict.fromkeys(SERIES_KEYS, 0))
        for key in SERIES_KEYS:
            slot[key] += m[key]
    if [_get(r, "quarter", f"{P}.quarterly") for r in rows] != list(want):
        _fail(f"{P}.quarterly", "quarters must match the monthly series, "
                                "in order")
    first_q, last_q = list(want)[0], list(want)[-1]
    for i, row in enumerate(rows):
        p = f"{P}.quarterly[{i}]"
        _check_str(row["quarter"], f"{p}.quarter", _QUARTER_RE)
        for key in SERIES_KEYS:
            _check_int(_get(row, key, p), f"{p}.{key}")
            if row[key] != want[row["quarter"]][key]:
                _fail(f"{p}.{key}", "does not equal the sum of its months")
        partial = _get(row, "partial", p)
        _check_bool(partial, f"{p}.partial")
        if partial != (row["quarter"] in (first_q, last_q)):
            _fail(f"{p}.partial", "only the first and the edition quarter "
                                  "are partial")


def _check_lag(lag: Any, totals: dict) -> None:
    p = f"{P}.amendment_lag"
    originals = _get(lag, "originals", p)
    _check_int(originals, f"{p}.originals")
    if originals != totals["originals"]:
        _fail(f"{p}.originals", "differs from totals.originals")
    amended = _get(lag, "amended", p)
    _check_int(amended, f"{p}.amended")
    if amended > originals:
        _fail(f"{p}.amended", "exceeds originals")
    matched = _get(lag, "matched_amendments", p)
    unmatched = _get(lag, "unmatched_amendments", p)
    _check_int(matched, f"{p}.matched_amendments")
    _check_int(unmatched, f"{p}.unmatched_amendments")
    if matched + unmatched != totals["amendments"]:
        _fail(p, "matched + unmatched amendments must equal "
                 "totals.amendments")
    if amended > matched:
        _fail(f"{p}.amended", "exceeds matched amendments")
    med, mx = _get(lag, "median_days", p), _get(lag, "max_days", p)
    if amended == 0:
        if med is not None or mx is not None:
            _fail(p, "median/max must be null when nothing was amended")
    else:
        _check_num(med, f"{p}.median_days", 0, 100_000)
        _check_int(mx, f"{p}.max_days")
        if med > mx:
            _fail(f"{p}.median_days", "exceeds max_days")
    buckets = _check_list(_get(lag, "buckets", p), f"{p}.buckets")
    if [_get(b, "label", f"{p}.buckets") for b in buckets] \
            != LAG_BUCKET_LABELS:
        _fail(f"{p}.buckets", f"labels must be {LAG_BUCKET_LABELS}")
    total = 0
    for i, b in enumerate(buckets):
        _check_int(_get(b, "n", f"{p}.buckets[{i}]"), f"{p}.buckets[{i}].n")
        total += b["n"]
    if total != amended:
        _fail(f"{p}.buckets", f"sum {total} != amended {amended}")


def _check_recent(rows: list, generated_at: str) -> None:
    keys = []
    for i, r in enumerate(rows):
        p = f"{P}.recent[{i}]"
        d = _get(r, "date", p)
        _check_str(d, f"{p}.date", DATE_RE)
        if not RULE_EFFECTIVE <= d <= generated_at[:10]:
            _fail(f"{p}.date", "outside the window")
        if _get(r, "form", p) not in _FORMS:
            _fail(f"{p}.form", f"must be one of {_FORMS}")
        _check_str(_get(r, "company", p), f"{p}.company")
        ticker = _get(r, "ticker", p)
        if ticker is not None:
            _check_str(ticker, f"{p}.ticker")
        cik = _get(r, "cik", p)
        _check_str(cik, f"{p}.cik")
        if not cik.isdigit() or cik.startswith("0"):
            _fail(f"{p}.cik", "must be digits without leading zeros")
        adsh = _get(r, "adsh", p)
        _check_str(adsh, f"{p}.adsh", _ADSH_RE)
        url = (f"https://www.sec.gov/Archives/edgar/data/{cik}/"
               f"{adsh.replace('-', '')}/{adsh}-index.htm")
        if _get(r, "url", p) != url:
            _fail(f"{p}.url", f"must be the EDGAR index link {url}")
        if "lag_days" in r:
            if r["form"] != "8-K/A":
                _fail(f"{p}.lag_days", "only amendments carry a lag")
            _check_int(r["lag_days"], f"{p}.lag_days")
            _check_str(_get(r, "original_date", p), f"{p}.original_date",
                       DATE_RE)
        keys.append((d, adsh))
    if keys != sorted(keys, reverse=True):
        _fail(f"{P}.recent", "must be newest first")
    if len({k[1] for k in keys}) != len(keys):
        _fail(f"{P}.recent", "duplicate accession number")


def _validate_sec_incidents(obj: Any) -> None:
    _check_generated_at(obj, P)
    generated_at = obj["generated_at"]
    status = _get(obj, "status", P)
    if status not in ("ok", "empty"):
        _fail(f"{P}.status", f"must be 'ok' or 'empty', got {status!r}")
    window = _get(obj, "window", P)
    if _get(window, "start", f"{P}.window") != RULE_EFFECTIVE:
        _fail(f"{P}.window.start", f"must be {RULE_EFFECTIVE}")
    _check_str(_get(window, "end", f"{P}.window"), f"{P}.window.end",
               DATE_RE)
    _check_definitions(obj)
    monthly = _check_list(_get(obj, "monthly", P), f"{P}.monthly")
    quarterly = _check_list(_get(obj, "quarterly", P), f"{P}.quarterly")
    recent = _check_list(_get(obj, "recent", P), f"{P}.recent")
    totals = _get(obj, "totals", P)
    lag = _get(obj, "amendment_lag", P)

    if status == "empty":
        if monthly or quarterly or recent:
            _fail(P, "an empty edition carries no series and no receipts")
        if totals is not None or lag is not None:
            _fail(P, "an empty edition's totals and amendment_lag are "
                     "null — nothing was counted")
        return

    sums = _check_monthly(monthly, generated_at)
    _check_quarterly(quarterly, monthly)
    for key in SERIES_KEYS:
        _check_int(_get(totals, key, f"{P}.totals"), f"{P}.totals.{key}")
        if totals[key] != sums[key]:
            _fail(f"{P}.totals.{key}", f"{totals[key]} != monthly sum "
                                       f"{sums[key]}")
    c105 = _get(totals, "companies_105", f"{P}.totals")
    c801 = _get(totals, "companies_801", f"{P}.totals")
    _check_int(c105, f"{P}.totals.companies_105")
    _check_int(c801, f"{P}.totals.companies_801")
    if c105 > totals["originals"]:
        _fail(f"{P}.totals.companies_105", "exceeds Item 1.05 originals")
    if c801 > totals["voluntary"]:
        _fail(f"{P}.totals.companies_801", "exceeds Item 8.01 filings")
    latest = _get(totals, "latest_105", f"{P}.totals")
    _check_lag(lag, totals)
    _check_recent(recent, generated_at)
    n105 = totals["originals"] + totals["amendments"]
    if len(recent) > n105 or (n105 and not recent):
        _fail(f"{P}.recent", "must list the latest Item 1.05 filings")
    if latest != (recent[0]["date"] if recent else None):
        _fail(f"{P}.totals.latest_105", "must equal the newest receipt date")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "sec_incidents.json": _validate_sec_incidents,
}
