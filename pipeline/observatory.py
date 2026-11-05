"""Mutation Observatory: one per-CVE event trail from CyberMon's own
histories (observatory.json).

Not a module — an instrument (site/observatory.html, beside The Field). It
charts nothing the modules do not already publish; it re-reads the three
append-only logs CyberMon keeps and lays their events on one dated stream,
so a reader can brush a window, or follow one record's trail across all
three:

* ``history/rescore_log.csv`` (Silent Rescores) — every CNA score event:
  ``rescore``, ``version_shift``, ``first_score``, ``score_removed``.
* ``history/kev_changelog.csv`` (KEV Changelog) — ``added`` / ``removed``
  entries and per-field edits, split here into the ransomware flag, the
  due date, the other value fields (vendor/product/name) and the
  hash-tracked text fields. Each keeps its ``granularity``.
* ``history/epss_volatility.csv`` (EPSS Volatility) — the night's single
  biggest EPSS probability move (``top_cve``: ``top_old`` -> ``top_new``).
  Nights the EPSS module quarantines as ``reset`` (a new model rescored the
  whole corpus) or ``anomaly`` (a whole-corpus lurch that moved back — a
  feed glitch) are left out, counted in ``sources.epss``: their top mover
  is not the model changing its mind about one CVE. A ``gap`` night (the
  diff spans missed nights) stays in with granularity ``pooled``.

Dating rule (the page states it): every event is dated by its FIRST
OBSERVATION by CyberMon — the nightly run that saw it (``daily``), the
first Internet Archive capture that shows it (``capture``, KEV backfill
only: the change happened at or before that date), or the first run after
missed nights (``pooled``). ``sources`` names when each history begins, so
nothing is drawn before monitoring began.

Encoding (size): ~10k events would cost ~0.6 MB as indented column
arrays (the pipeline writes every output with ``indent=1``), so each
event is one ``"|"``-joined string —
``day|cve|kind|detail|granularity`` with ``day`` an integer offset from
``base_date`` and ``kind``/``granularity`` indexes into :data:`KINDS` /
:data:`GRANULARITIES`. A ``|`` inside a detail (KEV vendor text) is
written as ``/``.

Missed nights (the page draws them as gaps, never as zero): the three
logs only hold rows for nights with events, so a quiet night and a night
the pipeline never ran look the same in them. ``missed_nights`` lists the
nights with no nightly run, judged from the per-night logs that write a
row on every successful run (``run_dates``: the NVD backlog, the CNA
roster size history and the Feodo C2 counts — any one of them is proof
the run happened), from the first such row to ``last_observed``. EPSS is
dated by score date, so its lane has its own lists: ``sources.epss.missed``
(score dates with no snapshot in the log) and ``sources.epss.excluded``
(the quarantined reset/anomaly nights).

Pure function of the three logs (and the KEV state's backfill block, for
the capture-era bounds, and the run dates): the same committed files
always yield the same file. No state, no network, no writes of its own.
"""
from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import date, timedelta
from pathlib import Path
from typing import Iterable

from .epss_volatility import classify

KINDS = (
    "kev_added", "kev_removed", "kev_flag", "kev_due", "kev_field",
    "kev_text", "rescore", "version_shift", "first_score", "score_removed",
    "epss_move",
)
SOURCE_OF = {k: ("kev" if k.startswith("kev_") else
                 "epss" if k == "epss_move" else "rescore") for k in KINDS}
GRANULARITIES = ("daily", "capture", "pooled")
SOURCES = ("kev", "rescore", "epss")
SEP = "|"

_KEV_FIELD_KIND = {
    "knownRansomwareCampaignUse": "kev_flag",
    "dueDate": "kev_due",
}
# ASCII on purpose: json.dumps spends six bytes on an escaped arrow; the
# page draws "->" as an arrow.
_ARROW = "->"


def _clean(text: str) -> str:
    return str(text).replace(SEP, "/").strip()


def _score(version: str | None, score: float | None) -> str:
    if score is None:
        return version or "none"
    return f"{version} {score:.1f}" if version else f"{score:.1f}"


def kev_events(rows: Iterable[dict]) -> list[tuple]:
    """(date, cve, kind, detail, granularity) for every changelog row."""
    out = []
    for r in rows:
        ct, fld = r["change_type"], r["field"]
        if ct == "added":
            kind, detail = "kev_added", ""
        elif ct == "removed":
            kind, detail = "kev_removed", ""
        elif ct == "text_changed":
            kind, detail = "kev_text", fld
        else:
            kind = _KEV_FIELD_KIND.get(fld, "kev_field")
            change = f"{r['old'] or '(empty)'}{_ARROW}{r['new'] or '(empty)'}"
            detail = change if kind in ("kev_flag", "kev_due") \
                else f"{fld}: {change}"
        out.append((r["observed_date"], r["cve"], kind, _clean(detail),
                    r["granularity"]))
    return out


def rescore_events(rows: Iterable[dict]) -> list[tuple]:
    out = []
    for r in rows:
        ct = r["change_type"]
        new = _score(r["version_new"], r["score_new"])
        old = _score(r["version_old"], r["score_old"])
        detail = new if ct == "first_score" else f"{old}{_ARROW}{new}"
        if r.get("cna"):
            detail += f" ({r['cna']})"
        out.append((r["observed_date"], r["cve"], ct, _clean(detail),
                    "daily"))
    return out


def _days(first: str, last: str) -> list[str]:
    a, b = date.fromisoformat(first), date.fromisoformat(last)
    return [(a + timedelta(days=i)).isoformat() for i in range((b - a).days + 1)]


def read_run_dates(history_dir: Path) -> set[str]:
    """Dates on which a nightly run left a row in a per-night log.

    Each of these logs gets a row on every successful run unless its own
    upstream failed that night (NVD stale or skipped, a broken roster
    fetch, a Feodo outage), so their union is the run record. A missing
    or unreadable file contributes nothing."""
    dates: set[str] = set()
    for name in ("nvd_backlog.csv", "botnet_c2.csv"):
        try:
            with open(history_dir / name, newline="", encoding="utf-8") as fh:
                dates.update(r["date"] for r in csv.DictReader(fh) if r.get("date"))
        except (OSError, KeyError, csv.Error):
            pass
    try:
        state = json.loads((history_dir / "cna_roster_state.json")
                           .read_text(encoding="utf-8"))
        dates.update(str(d) for d, _n in state.get("size_history") or [])
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return dates


def missed_nights(run_dates: Iterable[str], start: str | None,
                  last: str | None, also_ran: Iterable[str] = ()) -> list[str]:
    """Nights from ``start`` to ``last`` with no run on record. Judged only
    from the run record's own first date: before it, nothing is known.
    ``also_ran``: further proof of a run (a night with a nightly event),
    which never moves that first date."""
    runs = set(run_dates)
    if not runs or not start or not last:
        return []
    start = max(start, min(runs))
    if start > last:
        return []
    runs |= set(also_ran)
    return [d for d in _days(start, last) if d not in runs]


def epss_events(rows: list[dict]) -> tuple[list[tuple], Counter]:
    """Top-mover events plus the count of excluded nights by reason."""
    rows = sorted(rows, key=lambda r: r["observed_date"])
    reasons = classify(rows)
    out, excluded = [], Counter()
    for r, reason in zip(rows, reasons):
        if reason in ("reset", "anomaly"):
            excluded[reason] += 1
            continue
        if not r["top_cve"] or r["top_old"] is None or r["top_new"] is None:
            continue
        detail = f"{r['top_old']:.5f}{_ARROW}{r['top_new']:.5f}"
        out.append((r["observed_date"], r["top_cve"], "epss_move", detail,
                    "pooled" if reason == "gap" else "daily"))
    return out, excluded


def build_observatory(*, kev_rows: list[dict], kev_state: dict | None,
                      rescore_rows: list[dict], epss_rows: list[dict],
                      generated_at: str,
                      run_dates: Iterable[str] = ()) -> dict:
    """Assemble observatory.json from the three merged logs.

    ``run_dates``: nights a nightly run is on record for (see
    :func:`read_run_dates`); tonight's run, which builds this file, is
    added here."""
    kev = kev_events(kev_rows)
    rescore = rescore_events(rescore_rows)
    epss, excluded = epss_events(epss_rows)
    epss_sorted = sorted(epss_rows, key=lambda r: r["observed_date"])
    epss_dates = [r["observed_date"] for r in epss_sorted]
    epss_excluded = [d for d, reason in zip(epss_dates, classify(epss_sorted))
                     if reason in ("reset", "anomaly")]
    epss_missed = (sorted(set(_days(epss_dates[0], epss_dates[-1]))
                          - set(epss_dates)) if epss_dates else [])

    # ---- when each history begins (first observation, never earlier) -------
    backfill = (kev_state or {}).get("backfill") or {}
    capture_dates = [e[0] for e in kev if e[4] == "capture"]
    daily_kev = [e[0] for e in kev if e[4] == "daily"]
    kev_start = (kev_state or {}).get("baseline_date") or \
        (min(e[0] for e in kev) if kev else None)
    watermark = backfill.get("watermark") or ""
    sources = {
        "kev": {
            # The KEV state's baseline is the first observation (the first
            # capture); it logs nothing — diffs start at the next one.
            "first_observed": kev_start,
            "capture_until": (f"{watermark[:4]}-{watermark[4:6]}-"
                              f"{watermark[6:8]}" if watermark
                              else (max(capture_dates) if capture_dates
                                    else None)),
            "nightly_from": min(daily_kev) if daily_kev else None,
            "events": len(kev),
        },
        "rescore": {
            "first_observed": min((e[0] for e in rescore), default=None),
            "events": len(rescore),
        },
        "epss": {
            "first_observed": min((r["observed_date"] for r in epss_rows),
                                  default=None),
            "events": len(epss),
            "nights": len(epss_rows),
            "excluded_reset": excluded["reset"],
            "excluded_anomaly": excluded["anomaly"],
            "excluded": epss_excluded,
            "missed": epss_missed,
        },
    }

    # ---- the stream ----------------------------------------------------------
    order = {k: i for i, k in enumerate(KINDS)}
    events = sorted(kev + rescore + epss,
                    key=lambda e: (e[0], order[e[2]], e[1], e[3]))
    starts = [s["first_observed"] for s in sources.values()
              if s["first_observed"]]
    base = min(starts + [e[0] for e in events]) if (starts or events) \
        else None
    base_day = date.fromisoformat(base) if base else None
    encoded = []
    for d, cve, kind, detail, grain in events:
        offset = (date.fromisoformat(d) - base_day).days
        encoded.append(SEP.join((str(offset), cve, str(order[kind]), detail,
                                 str(GRANULARITIES.index(grain)))))
    counts = Counter(e[2] for e in events)
    last = events[-1][0] if events else None
    # The KEV and score lanes run nightly from the first nightly KEV diff or
    # the first score event, whichever is earlier.
    nightly = [d for d in (sources["kev"]["nightly_from"],
                           sources["rescore"]["first_observed"]) if d]
    # Tonight's run builds this file; a nightly KEV or score event is proof
    # of a run too.
    missed = missed_nights(set(run_dates) | {generated_at[:10]},
                           min(nightly, default=None), last,
                           also_ran=set(daily_kev) | {e[0] for e in rescore})
    return {
        "generated_at": generated_at,
        "base_date": base,
        "last_observed": last,
        "missed_nights": missed,
        "kinds": list(KINDS),
        "kind_source": [SOURCE_OF[k] for k in KINDS],
        "granularities": list(GRANULARITIES),
        "sources": sources,
        "counts": {k: counts.get(k, 0) for k in KINDS},
        "cves": len({e[1] for e in events}),
        "events": encoded,
    }


def decode(obj: dict) -> list[dict]:
    """The inverse of the event encoding (tests and the contract use it)."""
    base = date.fromisoformat(obj["base_date"]) if obj["base_date"] else None
    out = []
    for s in obj["events"]:
        day, cve, kind, detail, grain = s.split(SEP)
        out.append({"date": date.fromordinal(base.toordinal() + int(day))
                    .isoformat(), "cve": cve, "kind": KINDS[int(kind)],
                    "detail": detail,
                    "granularity": GRANULARITIES[int(grain)]})
    return out
