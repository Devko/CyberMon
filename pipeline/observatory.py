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

Pure function of the three logs (and the KEV state's backfill block, for
the capture-era bounds): the same committed files always yield the same
file. No state, no network, no writes of its own.
"""
from __future__ import annotations

from collections import Counter
from datetime import date
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
                      generated_at: str) -> dict:
    """Assemble observatory.json from the three merged logs."""
    kev = kev_events(kev_rows)
    rescore = rescore_events(rescore_rows)
    epss, excluded = epss_events(epss_rows)

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
    return {
        "generated_at": generated_at,
        "base_date": base,
        "last_observed": events[-1][0] if events else None,
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
