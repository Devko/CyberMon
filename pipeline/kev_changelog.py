"""KEV Changelog: the diff history CISA does not publish (kev_changelog.json).

CISA edits the Known Exploited Vulnerabilities catalog in place — due dates
move, ransomware flags flip, descriptions get rewritten, entries vanish —
and publishes no changelog. This stage keeps one:

* ``site/data/history/kev_state.json`` — a compact fingerprint of every
  catalog entry (tracked fields verbatim, free-text fields as short stable
  hashes) as of the last observed catalog, plus a ledger of removed
  entries. Committed, like the NVD backlog history.
* ``site/data/history/kev_changelog.csv`` — the append-only event log.
  Like ``history/nvd_backlog.csv``, this file is an **original dataset
  accumulated by this project and CANNOT be regenerated**: CISA publishes
  only the current catalog snapshot, so a lost event log is lost history
  (the pre-launch backfill from Wayback captures is reconstructable at
  capture granularity; everything observed live is not).

Diff rules (the site methodology quotes them):

* Tracked value fields (old/new logged verbatim): ``dueDate``,
  ``knownRansomwareCampaignUse`` (normalized to Known/Unknown — a missing
  field never counts as Known, the kev_metrics rule), ``vendorProject``,
  ``product``, ``vulnerabilityName``.
* Tracked text fields (whitespace-normalized sha256, first 12 hex chars;
  the event says "text_changed", never the text): ``shortDescription``,
  ``requiredAction``, ``notes``.
* Entry appearance/disappearance: ``added`` / ``removed`` events.
  Additions are logged but are NOT edits — a growing catalog is the
  system working — while a removal is real news and the removed entry is
  kept in the state's ``removed`` ledger, never silently dropped.
* First-ever run = baseline: the state is written, zero events are
  logged (there is no prior observation to diff against).
* ``dateAdded`` is carried in the state for lag arithmetic but is not a
  tracked field — the catalog treats it as an identity property, and a
  changed dateAdded would surface through the fields that describe it.

Granularity (the CSV's last column, per event):

* ``daily`` — observed by a nightly run; dated to the run that first saw
  it (if the pipeline misses nights, changes pool on the next run's date).
* ``capture`` — from the one-time Wayback backfill; dated to the FIRST
  Internet Archive capture that shows the change. The true date lies
  between that capture and the one before it.

Wayback backfill (``--kev-changelog-backfill N``, the EPSS-backfill
pattern: the integrator runs it once, CI never does — the default 0 means
the archive is never contacted):

* Capture list via the CDX API, one query per historical URL variant of
  the feed (verified 2026-07-11: only the ``/sites/default/files/feeds/``
  path ever served the JSON to the archive — 71 daily-collapsed captures
  from 2021-12-23; the ``/csv/`` sibling has none), collapsed to one per
  day upstream and thinned to one per ISO week client-side.
* Snapshot bodies are cached in ``.cache/kev_wayback/`` — a rerun never
  refetches. Requests are paced ~1/s; an unfetchable or unparseable
  capture is skipped with a warning, never fatal.
* Captures diff sequentially oldest -> newest starting from an empty
  state (the first capture is the baseline). ``N`` caps fetches per run;
  an interrupted backfill resumes at its timestamp watermark. While
  captures remain pending, the live diff is deliberately skipped — diffing
  today's catalog against a half-backfilled 2023 state would date three
  years of edits to one night.

Write discipline: this module never touches disk state itself. It returns
the merged CSV rows and the new state as pending writes; ``__main__.run()``
persists them (via :func:`persist`) only after every output validates —
the nvd_backlog.csv discipline, applied to a file that is just as
irreplaceable.
"""
from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Callable, Iterable

from .fetch_kev import KevEntry, parse_kev
from .metrics import _pct, _quartiles, _r1

FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures"

STATE_VERSION = 1
STATE_FILENAME = "kev_state.json"
CSV_FILENAME = "kev_changelog.csv"

CSV_COLUMNS = ("observed_date", "cve", "change_type", "field", "old",
               "new", "granularity")
CHANGE_TYPES = ("added", "removed", "field_changed", "text_changed")
GRANULARITIES = ("daily", "capture")

# Tracked fields: catalog key -> compact state key. Value fields log
# old/new verbatim; text fields are hash-tracked (event only, no text).
VALUE_FIELDS = {
    "dueDate": "due",
    "knownRansomwareCampaignUse": "ransom",
    "vendorProject": "vendor",
    "product": "product",
    "vulnerabilityName": "name",
}
TEXT_FIELDS = {
    "shortDescription": "desc",
    "requiredAction": "action",
    "notes": "notes",
}

# Hero chart categories (added events are excluded by design — catalog
# growth is the system working, not an edit; the site says so).
HERO_CATEGORIES = ("due_date", "ransomware_flag", "text", "removed")
_FIELD_CATEGORY = {
    "dueDate": "due_date",
    "knownRansomwareCampaignUse": "ransomware_flag",
    "vendorProject": "text",
    "product": "text",
    "vulnerabilityName": "text",
}

# ---- Wayback -----------------------------------------------------------------

CDX_API = "http://web.archive.org/cdx/search/cdx"
SNAPSHOT_URL = "https://web.archive.org/web/{timestamp}id_/{original}"
USER_AGENT = "CyberMon/1.0 (+https://github.com/Devko/CyberMon)"
# Every URL the feed has lived at. Verified against the CDX index
# 2026-07-11: the feeds/ path holds every capture (first: 2021-12-23);
# the csv/ sibling never served JSON to the archive but stays queried in
# case the archive backfills it. CDX canonicalization already folds
# www./non-www. and http/https into one key.
KEV_URL_VARIANTS = (
    "www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json",
    "www.cisa.gov/sites/default/files/csv/"
    "known_exploited_vulnerabilities.json",
)
REQUEST_SLEEP = 1.0  # politeness: ~1 request/second against the archive
_TIMEOUT = 120.0

# A fresh catalog (live or capture) that lost more than half of the known
# entries is a broken fetch, not history — mass-logging removals from it
# would poison the irreplaceable event log.
_SHRINK_GUARD = 0.5
_SHRINK_MIN_PREV = 50


# ------------------------------------------------------------------ fingerprints

def _norm_value(v: object) -> str:
    """Value-field normalization: verbatim minus edge whitespace (the
    catalog carries stray spaces; a whitespace-only edit is not news)."""
    return str(v).strip() if isinstance(v, str) else ""


def _norm_ransom(v: object) -> str:
    """"Known" or "Unknown", nothing else: a missing or unrecognized flag
    never counts as Known (kev_metrics applies the same rule)."""
    return "Known" if isinstance(v, str) and v.strip().lower() == "known" \
        else "Unknown"


def text_hash(text: object) -> str:
    """Short stable fingerprint of a free-text field: sha256 of the
    whitespace-normalized text, first 12 hex chars. Whitespace-only
    reflows do not count as revisions."""
    normalized = " ".join(str(text or "").split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]


def fingerprint(entry: KevEntry) -> dict:
    """One compact state record for a catalog entry."""
    return {
        "added": _norm_value(entry.date_added)[:10],
        "due": _norm_value(entry.due_date),
        "ransom": _norm_ransom(entry.ransomware_use),
        "vendor": _norm_value(entry.vendor_project),
        "product": _norm_value(entry.product),
        "name": _norm_value(entry.vulnerability_name),
        "desc": text_hash(entry.short_description),
        "action": text_hash(entry.required_action),
        "notes": text_hash(entry.notes),
    }


def fingerprint_catalog(entries: Iterable[KevEntry]) -> dict[str, dict]:
    """cve id -> fingerprint for a whole catalog snapshot."""
    return {e.cve_id: fingerprint(e) for e in entries}


# ------------------------------------------------------------------- diff engine

def diff_catalogs(prev: dict[str, dict], curr: dict[str, dict],
                  observed_date: str, granularity: str) -> list[dict]:
    """Events turning ``prev`` into ``curr``, dated ``observed_date``.

    Deterministic order: additions, removals, then per-entry field events,
    each block sorted by cve (and field). Re-running the same diff yields
    the same rows — the same-day idempotency the CSV depends on.
    """
    if granularity not in GRANULARITIES:
        raise ValueError(f"unknown granularity {granularity!r}")
    events: list[dict] = []

    def _event(cve: str, change_type: str, fld: str = "",
               old: str = "", new: str = "") -> dict:
        return {"observed_date": observed_date, "cve": cve,
                "change_type": change_type, "field": fld,
                "old": old, "new": new, "granularity": granularity}

    for cve in sorted(set(curr) - set(prev)):
        events.append(_event(cve, "added"))
    for cve in sorted(set(prev) - set(curr)):
        events.append(_event(cve, "removed"))
    for cve in sorted(set(prev) & set(curr)):
        before, after = prev[cve], curr[cve]
        for fld, key in VALUE_FIELDS.items():
            if before.get(key, "") != after.get(key, ""):
                events.append(_event(cve, "field_changed", fld,
                                     before.get(key, ""),
                                     after.get(key, "")))
        for fld, key in TEXT_FIELDS.items():
            if before.get(key, "") != after.get(key, ""):
                events.append(_event(cve, "text_changed", fld))
    return events


def apply_snapshot(state: dict, curr: dict[str, dict],
                   observed_date: str) -> None:
    """Advance ``state`` to the catalog snapshot ``curr`` (in place).

    Removed entries move to the state's ``removed`` ledger (vendor,
    product, dateAdded, removal date) — logged AND remembered, never
    silently dropped. A removed entry that reappears leaves the ledger
    again (its return is an ``added`` event in the CSV).
    """
    prev = state["entries"]
    removed = state["removed"]
    for cve in set(prev) - set(curr):
        fp = prev[cve]
        removed[cve] = {"vendor": fp.get("vendor", ""),
                        "product": fp.get("product", ""),
                        "added": fp.get("added", ""),
                        "removed_on": observed_date}
    for cve in curr:
        removed.pop(cve, None)
    state["entries"] = dict(curr)
    state["last_observed"] = observed_date


def _shrink_guard(prev_n: int, curr_n: int) -> bool:
    """True when a snapshot lost enough of the catalog to look like a
    broken fetch rather than history."""
    return prev_n >= _SHRINK_MIN_PREV and curr_n < prev_n * _SHRINK_GUARD


def new_state(baseline_date: str) -> dict:
    return {"version": STATE_VERSION, "baseline_date": baseline_date,
            "last_observed": baseline_date, "backfill": None,
            "entries": {}, "removed": {}}


# --------------------------------------------------------------------- state I/O

def state_path(out_dir: Path) -> Path:
    return out_dir / "history" / STATE_FILENAME


def csv_path(out_dir: Path) -> Path:
    return out_dir / "history" / CSV_FILENAME


def load_state(out_dir: Path) -> dict | None:
    """The committed diff state, or None on first ever run. Malformed
    state fails loudly — it is half of the historical record, and
    silently rebaselining would fake a fresh catalog into the log."""
    path = state_path(out_dir)
    if not path.exists():
        return None
    state = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION \
            or not isinstance(state.get("entries"), dict) \
            or not isinstance(state.get("removed"), dict):
        raise ValueError(f"{path}: unrecognized kev-changelog state")
    return state


def read_events(path: Path) -> list[dict]:
    """Read the event log, oldest first (file order — the log is
    append-only and appended chronologically). Missing file -> empty.
    Malformed rows fail loudly: this file is the historical record and
    silent data loss would be worse than a crash."""
    if not path.exists():
        return []
    rows: list[dict] = []
    with path.open("r", newline="", encoding="utf-8") as f:
        for lineno, raw in enumerate(csv.DictReader(f), start=2):
            try:
                row = {col: raw[col] for col in CSV_COLUMNS}
            except KeyError as exc:
                raise ValueError(f"{path}:{lineno}: malformed changelog row "
                                 f"{raw!r}") from exc
            if None in row.values() or \
                    row["change_type"] not in CHANGE_TYPES or \
                    row["granularity"] not in GRANULARITIES:
                raise ValueError(f"{path}:{lineno}: malformed changelog row "
                                 f"{raw!r}")
            rows.append(row)
    return rows


def write_events(path: Path, rows: list[dict]) -> None:
    """Rewrite the CSV atomically (temp file, then ``replace``) — an
    interrupted run must leave either the old file or the new one, never
    a truncation (the nvd_backlog.csv pattern)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    tmp.replace(path)


def write_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True) + "\n",
                   encoding="utf-8")
    tmp.replace(path)


@dataclass
class PendingWrites:
    """Everything run() persists after contract validation."""
    state: dict
    events: list[dict] = field(default_factory=list)  # full merged log


def persist(out_dir: Path, pending: PendingWrites,
            log: Callable[[str], None] = print) -> None:
    """Write the event log and state — called by ``__main__.run()`` only
    after every pipeline output has validated."""
    write_events(csv_path(out_dir), pending.events)
    write_state(state_path(out_dir), pending.state)
    log(f"  kev-changelog: {len(pending.events)} event(s) in "
        f"{csv_path(out_dir)}; state covers "
        f"{len(pending.state['entries'])} entries")


# ----------------------------------------------------------------------- wayback

def cdx_captures(session, log: Callable[[str], None] = print
                 ) -> list[tuple[str, str]]:
    """(timestamp, original_url) for every archived KEV JSON capture,
    ascending, collapsed to one per day upstream and thinned to one per
    ISO week here. Queries every historical URL variant and merges."""
    import time

    merged: dict[str, str] = {}
    for i, variant in enumerate(KEV_URL_VARIANTS):
        if i:
            time.sleep(REQUEST_SLEEP)
        params = {"url": variant, "output": "json",
                  "collapse": "timestamp:8", "filter": "statuscode:200"}
        resp = session.get(CDX_API, params=params,
                           headers={"User-Agent": USER_AGENT},
                           timeout=_TIMEOUT)
        resp.raise_for_status()
        rows = resp.json()
        for row in rows[1:]:  # row 0 is the header
            timestamp, original = str(row[1]), str(row[2])
            merged.setdefault(timestamp, original)
        log(f"  kev-changelog: CDX {variant}: {max(len(rows) - 1, 0)} "
            f"capture(s)")

    weekly: dict[tuple[int, int], tuple[str, str]] = {}
    for timestamp in sorted(merged):
        day = date(int(timestamp[:4]), int(timestamp[4:6]),
                   int(timestamp[6:8]))
        weekly.setdefault(day.isocalendar()[:2], (timestamp,
                                                  merged[timestamp]))
    captures = sorted(weekly.values())
    log(f"  kev-changelog: {len(merged)} daily capture(s) -> "
        f"{len(captures)} after weekly thinning")
    return captures


def fetch_capture(session, cache_dir: Path, timestamp: str, original: str,
                  log: Callable[[str], None] = print) -> dict | None:
    """One archived snapshot as a parsed KEV document, cached on disk so
    a rerun never refetches. None = unusable capture (skip, keep going);
    tolerated because the archive serves the occasional truncated body."""
    cache = cache_dir / "kev_wayback" / f"{timestamp}.json"
    if not cache.exists():
        url = SNAPSHOT_URL.format(timestamp=timestamp, original=original)
        try:
            resp = session.get(url, headers={"User-Agent": USER_AGENT},
                               timeout=_TIMEOUT)
            resp.raise_for_status()
            body = resp.content
            json.loads(body.decode("utf-8"))  # only cache parseable bodies
        except (OSError, ValueError) as exc:
            log(f"  kev-changelog: skipping capture {timestamp}: {exc!r}")
            return None
        cache.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache.with_name(cache.name + ".part")
        tmp.write_bytes(body)
        tmp.replace(cache)
    try:
        return json.loads(cache.read_text(encoding="utf-8"))
    except ValueError as exc:
        log(f"  kev-changelog: skipping unreadable cached capture "
            f"{timestamp}: {exc!r}")
        return None


def run_backfill(state: dict | None, events: list[dict], *,
                 captures: list[tuple[str, str]],
                 fetch: Callable[[str, str], dict | None],
                 batch: int, log: Callable[[str], None] = print
                 ) -> tuple[dict | None, bool]:
    """Diff up to ``batch`` pending Wayback captures into state/events.

    Returns ``(state, complete)`` — ``complete`` is False while captures
    remain beyond the watermark (the caller must then skip the live diff).
    ``state`` None going in means first ever run: the first usable capture
    becomes the baseline (still None coming out iff no capture was usable —
    the caller then baselines from the live catalog as usual). A state
    that was baselined live (no backfill block) refuses the backfill —
    captures older than the baseline cannot be diffed into a newer state.
    """
    if state is not None and state.get("backfill") is None:
        log("WARNING: kev-changelog state was baselined from a live run; "
            "the Wayback backfill must run before the first live diff — "
            "skipping backfill.")
        return state, True
    if state is not None and state["backfill"].get("complete"):
        log("  kev-changelog: backfill already complete; nothing to do")
        return state, True

    watermark = state["backfill"]["watermark"] if state is not None else ""
    pending = [(ts, orig) for ts, orig in captures if ts > watermark]
    todo, deferred = pending[:max(batch, 0)], pending[max(batch, 0):]
    log(f"  kev-changelog: {len(pending)} capture(s) pending; processing "
        f"{len(todo)} this run (cap {batch})")

    processed = state["backfill"]["captures"] if state is not None else 0
    for timestamp, original in todo:
        observed = f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}"
        doc = fetch(timestamp, original)
        if doc is None:
            watermark = timestamp
            continue
        catalog = fingerprint_catalog(parse_kev(doc).entries)
        if not catalog:
            log(f"  kev-changelog: capture {timestamp} parsed to zero "
                f"entries; skipping")
            watermark = timestamp
            continue
        if state is None:
            state = new_state(observed)  # first capture = baseline
        elif _shrink_guard(len(state["entries"]), len(catalog)):
            log(f"  kev-changelog: capture {timestamp} has "
                f"{len(catalog)} entries vs {len(state['entries'])} in "
                f"state — looks broken; skipping")
            watermark = timestamp
            continue
        else:
            events.extend(diff_catalogs(state["entries"], catalog,
                                        observed, "capture"))
        apply_snapshot(state, catalog, observed)
        processed += 1
        watermark = timestamp
        state["backfill"] = {"captures": processed, "watermark": watermark,
                             "complete": False}

    complete = not deferred
    if state is not None:
        state["backfill"] = {"captures": processed, "watermark": watermark,
                             "complete": complete}
    if not complete:
        log(f"  kev-changelog: backfill incomplete "
            f"({len(deferred)} capture(s) remain) — rerun with "
            f"--kev-changelog-backfill; the live diff waits until then")
    return state, complete


# ----------------------------------------------------------------------- metrics

def _month(day: str) -> str:
    return day[:7]


def _month_range(first: str, last: str) -> list[str]:
    """Contiguous YYYY-MM labels, first..last inclusive — gaps chart at
    zero, the axis never silently skips time."""
    months = []
    y, m = int(first[:4]), int(first[5:7])
    while True:
        months.append(f"{y:04d}-{m:02d}")
        if (f"{y:04d}-{m:02d}") >= last[:7]:
            return months
        m += 1
        if m == 13:
            y, m = y + 1, 1


def _hero_category(event: dict) -> str | None:
    if event["change_type"] == "removed":
        return "removed"
    if event["change_type"] == "text_changed":
        return "text"
    if event["change_type"] == "field_changed":
        return _FIELD_CATEGORY.get(event["field"], "text")
    return None  # added: catalog growth, not an edit


def _is_flip(event: dict) -> bool:
    return (event["change_type"] == "field_changed"
            and event["field"] == "knownRansomwareCampaignUse"
            and event["new"] == "Known")


def build_kev_changelog(state: dict, events: list[dict],
                        generated_at: str, *, min_n: int = 10,
                        board_size: int = 12) -> dict:
    """Assemble the kev_changelog.json object from the full event log
    plus the current state (entry lookups for the boards)."""
    edits = [e for e in events if _hero_category(e) is not None]
    additions = sum(1 for e in events if e["change_type"] == "added")

    # ---- section 1: edits per month, by category ---------------------------
    by_month: dict[str, Counter] = defaultdict(Counter)
    for e in edits:
        by_month[_month(e["observed_date"])][_hero_category(e)] += 1
    months = []
    if by_month:
        for label in _month_range(min(by_month), max(by_month)):
            counts = by_month.get(label, Counter())
            row = {"month": label}
            row.update({cat: counts.get(cat, 0) for cat in HERO_CATEGORIES})
            row["total"] = sum(counts.values())
            months.append(row)

    # ---- section 2: the ransomware flag arrives late ------------------------
    flips = [e for e in events if _is_flip(e)]
    reversals = sum(1 for e in events
                    if e["change_type"] == "field_changed"
                    and e["field"] == "knownRansomwareCampaignUse"
                    and e["new"] != "Known")
    flips_by_month: Counter[str] = Counter(_month(e["observed_date"])
                                           for e in flips)
    cumulative = []
    if flips_by_month:
        running = 0
        for label in _month_range(min(flips_by_month),
                                  max(flips_by_month)):
            running += flips_by_month.get(label, 0)
            cumulative.append({"month": label,
                               "flips": flips_by_month.get(label, 0),
                               "cumulative": running})
    lags: list[float] = []
    entries, removed = state["entries"], state["removed"]
    for e in flips:
        fp = entries.get(e["cve"]) or removed.get(e["cve"])
        added = (fp or {}).get("added", "")
        try:
            delta = (date.fromisoformat(e["observed_date"])
                     - date.fromisoformat(added)).days
        except ValueError:
            continue
        lags.append(float(delta))
    if len(lags) >= min_n:
        p25, median, p75 = _quartiles(lags)
        lag_block = {"n": len(lags), "median_days": _r1(median),
                     "p25_days": _r1(p25), "p75_days": _r1(p75)}
    else:
        # Render honestly when thin: the count ships, the stats do not.
        lag_block = {"n": len(lags), "median_days": None,
                     "p25_days": None, "p75_days": None}
    flips_block = {"total": len(flips), "reversals": reversals,
                   "by_month": cumulative, "lag": lag_block}

    # ---- section 3: the receipts board --------------------------------------
    edit_counts: Counter[str] = Counter()
    last_change: dict[str, str] = {}
    for e in edits:
        if e["change_type"] == "removed":
            continue  # removals get their own list below
        edit_counts[e["cve"]] += 1
        last_change[e["cve"]] = max(last_change.get(e["cve"], ""),
                                    e["observed_date"])
    most_edited = []
    ranked = sorted(edit_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    for cve, n in ranked[:board_size]:
        fp = entries.get(cve) or removed.get(cve) or {}
        most_edited.append({"cve": cve, "vendor": fp.get("vendor", ""),
                            "product": fp.get("product", ""), "edits": n,
                            "last_change": last_change[cve]})
    removals = [{"cve": cve, "vendor": fp.get("vendor", ""),
                 "product": fp.get("product", ""),
                 "listed": fp.get("added", ""),
                 "removed": fp.get("removed_on", "")}
                for cve, fp in sorted(removed.items(),
                                      key=lambda kv:
                                      (kv[1].get("removed_on", ""), kv[0]))]

    catalog = {
        "entries": len(entries),
        "removed_total": len(removed),
        "events_total": len(events),
        "edits_total": len(edits),
        "additions_excluded": additions,
        "first_observed": state["baseline_date"] or None,
        "last_observed": state["last_observed"] or None,
        "backfill_captures": (state.get("backfill") or {}).get("captures",
                                                               0),
    }

    # Headline: edits per catalog entry over the whole record — a scale
    # number, not a trend (the partial-month rule has no purchase here).
    headline = None
    if catalog["entries"] and edits:
        headline = {
            "edits_total": len(edits),
            "edits_per_100_entries": _r1(100.0 * len(edits)
                                         / catalog["entries"]),
            "pct_flag_flips": _pct(len(flips), len(edits)),
        }

    return {
        "generated_at": generated_at,
        "min_n": min_n,
        "months": months,
        "flips": flips_block,
        "board": {"most_edited": most_edited, "removals": removals},
        "catalog": catalog,
        "headline": headline,
    }


def _source(fetched_at: str, obj: dict) -> dict:
    return {"fetched_at": fetched_at,
            "events_total": obj["catalog"]["events_total"],
            "last_observed": obj["catalog"]["last_observed"] or ""}


# --------------------------------------------------------------------- the stage

def run_stage(out_dir: Path, cache_dir: Path, generated_at: str, *,
              kev_entries: list[KevEntry], offline_fixtures: bool,
              backfill_batch: int = 0, min_n: int | None = None,
              session=None, log: Callable[[str], None] = print
              ) -> tuple[dict, dict, PendingWrites]:
    """(kev_changelog.json object, meta.sources.kev_changelog, pending
    writes for run() to persist after validation).

    * ``offline_fixtures`` — when no committed state exists yet, the
      first run seeds its "prior night" from
      fixtures/kev_changelog_state.json instead of baselining, so the
      fixture diff produces adds/edits/removals; the second run then
      exercises the idempotent path. No network either way.
    * ``backfill_batch`` > 0 — run the Wayback backfill first (see module
      docstring). CI never passes the flag, so CI never contacts the
      archive.
    * live — diff the committed state against the fresh catalog, append
      events dated today (granularity ``daily``). First ever run =
      baseline, zero events.
    """
    if min_n is None:
        min_n = 1 if offline_fixtures else 10
    today = generated_at[:10]

    state = load_state(out_dir)
    events = read_events(csv_path(out_dir))
    backfill_complete = True

    if offline_fixtures and state is None:
        state = json.loads((FIXTURES_DIR / "kev_changelog_state.json")
                           .read_text(encoding="utf-8"))
        log("  kev-changelog: seeded prior state from fixtures "
            f"({len(state['entries'])} entries)")

    if backfill_batch > 0 and not offline_fixtures:
        if session is None:
            import requests

            session = requests.Session()
        log("  kev-changelog: Wayback backfill "
            f"(batch cap {backfill_batch}) ...")
        import time

        def _paced_fetch(timestamp: str, original: str) -> dict | None:
            time.sleep(REQUEST_SLEEP)
            return fetch_capture(session, cache_dir, timestamp, original,
                                 log=log)

        state, backfill_complete = run_backfill(
            state, events, captures=cdx_captures(session, log=log),
            fetch=_paced_fetch, batch=backfill_batch, log=log)

    catalog = fingerprint_catalog(kev_entries)
    if not backfill_complete:
        log("  kev-changelog: live diff skipped (backfill incomplete)")
        if state is None:  # every processed capture was unusable
            state = new_state("")
    elif state is None:
        state = new_state(today)
        apply_snapshot(state, catalog, today)
        log(f"  kev-changelog: baseline run — state written for "
            f"{len(catalog)} entries, zero events")
    else:
        if _shrink_guard(len(state["entries"]), len(catalog)):
            raise RuntimeError(
                f"kev-changelog: fresh catalog has {len(catalog)} entries "
                f"vs {len(state['entries'])} in state — refusing to log a "
                f"mass removal from what looks like a broken fetch")
        fresh = diff_catalogs(state["entries"], catalog, today, "daily")
        events.extend(fresh)
        apply_snapshot(state, catalog, today)
        log(f"  kev-changelog: {len(fresh)} event(s) observed "
            f"({len(events)} total on record)")

    obj = build_kev_changelog(state, events, generated_at, min_n=min_n)
    return obj, _source(generated_at, obj), PendingWrites(state=state,
                                                          events=events)
