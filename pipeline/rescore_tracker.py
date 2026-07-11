"""Silent Rescores: nightly diffs of CNA-assigned scores on live records.

Thesis: severity is not just assigned — it is edited after the fact,
quietly, on live CVE records. No upstream publishes that edit history, so
this module keeps it: every night, the corpus pass collects a per-CVE
fingerprint (``Aggregator.rescore_fingerprints`` — the newest-version
CNA-assigned base score, extracted by ``CveFacts.newest_cna_fingerprint``,
the same property the inflation chart's blended series reads, so the two
can never disagree), the previous night's fingerprints are loaded from
cached state, and the differences become events on an append-only log.

Event taxonomy (``CHANGE_TYPES``) — the boundaries are the honesty rules:

* ``rescore`` — same CVSS version, different score. The only type with a
  direction (up/down); the only type the magnitude chart may read.
* ``version_shift`` — the record's newest scored CVSS version changed
  (normally a newer version's score arriving; a newer score being
  withdrawn also lands here). Score comparison across versions is NOT a
  rescore — v2/v3/v4 are different scales — so shifts are logged
  separately and never charted as up/down, even when the number moved.
* ``first_score`` — a record already on last night's log gained its first
  in-record CNA score. That is backfill-scoring, not an edit of an
  existing judgment; counted separately. (Only possible because the
  fingerprint map keeps unscored published records: a scored CVE absent
  from last night's map entirely is a brand-new record and no event.)
* ``score_removed`` — the CNA score disappeared from a still-published
  record.

Records that leave the published corpus (late rejections) simply leave
the fingerprint map; that is a state transition, not a score edit, and
produces no event.

State (``.cache/rescore_state.json.gz``, the nvd_status_state pattern):
``{"release": <corpus tag>, "fingerprints": {cve: [version, score]}}``.
Self-healing: a missing or unreadable state is rebuilt from tonight's
corpus and the night logs zero events — at worst one night's diffs are
lost, and the committed log is never touched by the rebuild. Release-skew
guard: when tonight's corpus release tag equals the state's recorded
release, the diff is skipped entirely, so a re-run can never double-count
the same corpus transition.

The log (``site/data/history/rescore_log.csv``) is committed and
append-only — like nvd_backlog.csv it is an ORIGINAL dataset this repo is
the only copy of; ``rescore_log.json`` is rebuilt from it nightly. State
and CSV writes are deferred to __main__ (after contract validation), so a
failed run records neither tonight's release nor its events.
"""
from __future__ import annotations

import csv
import gzip
import json
import statistics
from collections import Counter
from datetime import date, timedelta
from pathlib import Path
from typing import Callable, Mapping

from .metrics import _r1

CHANGE_TYPES = ("rescore", "version_shift", "first_score", "score_removed")

# Signed score-delta buckets for the magnitude chart (rescore events only;
# a delta of exactly 0 cannot occur — equal scores are not an event).
# Labels are ranges at the scores' own 1-decimal granularity.
DELTA_BUCKETS = ("<=-4.0", "-3.9..-2.0", "-1.9..-0.1",
                 "+0.1..+1.9", "+2.0..+3.9", ">=+4.0")

CSV_COLUMNS = ("observed_date", "cve", "cna", "change_type",
               "version_old", "score_old", "version_new", "score_new")

DEFAULT_MIN_N = 30  # rescore events before the magnitude distribution charts
DEFAULT_MIN_CNA_EVENTS = 3  # rescore events before a CNA joins the board


def delta_bucket(delta: float) -> str:
    """Bucket label for a signed rescore delta (never exactly 0)."""
    if delta <= -4.0:
        return "<=-4.0"
    if delta <= -2.0:
        return "-3.9..-2.0"
    if delta < 0.0:
        return "-1.9..-0.1"
    if delta < 2.0:
        return "+0.1..+1.9"
    if delta < 4.0:
        return "+2.0..+3.9"
    return ">=+4.0"


# ------------------------------------------------------------------ diffing

def diff_events(old: Mapping[str, list],
                new: Mapping[str, tuple[str, str | None, float | None]],
                observed_date: str) -> list[dict]:
    """Diff last night's fingerprints against tonight's into event rows.

    ``old``: cve -> [version|None, score|None] (the persisted state).
    ``new``: cve -> (cna, version|None, score|None) (tonight's corpus).
    CVEs only in ``new`` are brand-new records (no event — first
    assignment is the inflation chart's subject, not an edit); CVEs only
    in ``old`` left the published corpus (no event). Events are sorted by
    CVE id for a deterministic log.
    """
    events: list[dict] = []
    for cve in sorted(new):
        if cve not in old:
            continue
        old_version, old_score = old[cve][0], old[cve][1]
        cna, new_version, new_score = new[cve]
        if old_version is None and new_version is None:
            continue  # unscored then, unscored now
        if old_version is None:
            change = "first_score"
        elif new_version is None:
            change = "score_removed"
        elif old_version != new_version:
            change = "version_shift"
        elif old_score != new_score:
            change = "rescore"
        else:
            continue  # same version, same score
        events.append({
            "observed_date": observed_date,
            "cve": cve,
            "cna": cna,
            "change_type": change,
            "version_old": old_version,
            "score_old": old_score,
            "version_new": new_version,
            "score_new": new_score,
        })
    return events


# -------------------------------------------------------------------- state

def _state_path(cache_dir: Path) -> Path:
    return cache_dir / "rescore_state.json.gz"


def load_state(cache_dir: Path, log: Callable[[str], None] = print
               ) -> dict | None:
    """Cached fingerprint state, or None when absent/unreadable/misshapen
    (the stage then rebuilds from tonight's corpus and logs zero events —
    the state is only ever a cache; the committed log is the record)."""
    path = _state_path(cache_dir)
    if not path.exists():
        return None
    try:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError) as exc:
        log(f"warning: ignoring unreadable rescore state {path}: {exc!r}")
        return None
    if not isinstance(state, dict) or \
            not isinstance(state.get("release"), str) or \
            not isinstance(state.get("fingerprints"), dict):
        log(f"warning: ignoring misshapen rescore state {path}")
        return None
    return state


def save_state(cache_dir: Path, state: dict) -> None:
    path = _state_path(cache_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        json.dump(state, f, separators=(",", ":"))
    tmp.replace(path)


def make_state(release: str,
               fingerprints: Mapping[str, tuple[str, str | None,
                                                float | None]]) -> dict:
    """Tonight's persistable state (the CNA is per-run context, not state:
    every event names the CNA the record carries on the night observed)."""
    return {"release": release,
            "fingerprints": {cve: [version, score]
                             for cve, (_cna, version, score)
                             in fingerprints.items()}}


# ---------------------------------------------------------- the event log

def read_events(path: Path) -> list[dict]:
    """Read the committed event log, file order preserved. Missing file ->
    empty list. Malformed rows fail loudly — this file is the irreplaceable
    historical record and silent loss would be worse than a crash."""
    if not path.exists():
        return []
    rows: list[dict] = []
    with path.open("r", newline="", encoding="utf-8") as f:
        for lineno, raw in enumerate(csv.DictReader(f), start=2):
            try:
                row = {
                    "observed_date": raw["observed_date"],
                    "cve": raw["cve"],
                    "cna": raw["cna"],
                    "change_type": raw["change_type"],
                    "version_old": raw["version_old"] or None,
                    "score_old": float(raw["score_old"])
                    if raw["score_old"] else None,
                    "version_new": raw["version_new"] or None,
                    "score_new": float(raw["score_new"])
                    if raw["score_new"] else None,
                }
                if row["change_type"] not in CHANGE_TYPES or \
                        not row["cve"] or not row["observed_date"]:
                    raise ValueError("bad field values")
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"{path}:{lineno}: malformed rescore event "
                                 f"{raw!r}") from exc
            rows.append(row)
    return rows


def write_events(path: Path, rows: list[dict]) -> None:
    """Rewrite the CSV atomically (temp file, then ``replace``) — same
    pattern as history.write_rows: an interrupted run must leave either
    the old file or the new one, never a truncation. Scores are written at
    their 1-decimal precision; None fields as empty strings."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                **{k: row[k] or "" for k in
                   ("observed_date", "cve", "cna", "change_type")},
                "version_old": row["version_old"] or "",
                "score_old": "" if row["score_old"] is None
                else f"{row['score_old']:.1f}",
                "version_new": row["version_new"] or "",
                "score_new": "" if row["score_new"] is None
                else f"{row['score_new']:.1f}",
            })
    tmp.replace(path)


# ------------------------------------------------------------------ builder

def _week_monday(day: date) -> date:
    return day - timedelta(days=day.isocalendar()[2] - 1)


def _week_label(day: date) -> str:
    iso_year, iso_week, _ = day.isocalendar()
    return f"{iso_year}-W{iso_week:02d}"


def _weekly_rows(rows: list[dict]) -> list[dict]:
    """Per-ISO-week event counts, gap-filled between the first and last
    observed week so the axis never silently skips time. ``rescore_up`` /
    ``rescore_down`` split rescore events by direction; the other three
    change types are direction-free by design and count whole."""
    by_monday: dict[date, Counter[str]] = {}
    for row in rows:
        monday = _week_monday(date.fromisoformat(row["observed_date"]))
        counts = by_monday.setdefault(monday, Counter())
        if row["change_type"] == "rescore":
            counts["rescore_up" if row["score_new"] > row["score_old"]
                   else "rescore_down"] += 1
        else:
            counts[row["change_type"]] += 1
    if not by_monday:
        return []
    weeks = []
    monday, last = min(by_monday), max(by_monday)
    while monday <= last:
        counts = by_monday.get(monday, Counter())
        weeks.append({"week": _week_label(monday),
                      "rescore_up": counts.get("rescore_up", 0),
                      "rescore_down": counts.get("rescore_down", 0),
                      "first_score": counts.get("first_score", 0),
                      "version_shift": counts.get("version_shift", 0),
                      "score_removed": counts.get("score_removed", 0)})
        monday += timedelta(days=7)
    return weeks


def build_rescore_log(rows: list[dict], *, state_size: int, release: str,
                      generated_at: str, min_n: int = DEFAULT_MIN_N,
                      min_cna_events: int = DEFAULT_MIN_CNA_EVENTS) -> dict:
    """Assemble rescore_log.json from the full committed event log.

    Everything is computed over the log, not over tonight alone — the log
    IS the dataset, and it starts at first deploy: the site must render
    the thin early record honestly (``first_observed`` and the totals say
    exactly how much record exists; nothing here fakes depth).

    * ``weeks`` — per-ISO-week counts (see :func:`_weekly_rows`).
    * ``magnitude`` — signed deltas of rescore events only (same-version
      by construction; cross-version deltas never exist as rescores).
      ``buckets``/``median_delta`` are null until at least ``min_n``
      rescore events have accumulated — below that a distribution is an
      anecdote, and the site renders the placeholder from ``n``.
    * ``cna_board`` — CNAs by rescore count with the up/down split; a CNA
      joins with at least ``min_cna_events`` rescore events.
    * ``catalog`` — the audit block: fingerprint-state size, corpus
      release, totals by change type (summing to ``events_total``), and
      the log's first observed date (null exactly when the log is empty).
    """
    totals = Counter(row["change_type"] for row in rows)
    rescores = [row for row in rows if row["change_type"] == "rescore"]
    deltas = [round(row["score_new"] - row["score_old"], 1)
              for row in rescores]
    ups = sum(1 for d in deltas if d > 0)

    magnitude: dict = {"min_n": min_n, "n": len(deltas),
                       "up": ups, "down": len(deltas) - ups,
                       "buckets": None, "median_delta": None}
    if len(deltas) >= min_n:
        counts = Counter(delta_bucket(d) for d in deltas)
        magnitude["buckets"] = [{"bucket": b, "n": counts.get(b, 0)}
                                for b in DELTA_BUCKETS]
        magnitude["median_delta"] = _r1(statistics.median(deltas))

    per_cna: dict[str, Counter[str]] = {}
    for row in rescores:
        counts = per_cna.setdefault(row["cna"], Counter())
        counts["up" if row["score_new"] > row["score_old"] else "down"] += 1
    cnas = [{"cna": cna, "rescores": counts["up"] + counts["down"],
             "up": counts["up"], "down": counts["down"]}
            for cna, counts in per_cna.items()
            if counts["up"] + counts["down"] >= min_cna_events]
    cnas.sort(key=lambda row: (-row["rescores"], row["cna"]))

    return {
        "generated_at": generated_at,
        "weeks": _weekly_rows(rows),
        "magnitude": magnitude,
        "cna_board": {"min_events": min_cna_events, "cnas": cnas},
        "catalog": {
            "state_size": state_size,
            "corpus_release": release,
            "totals": {t: totals.get(t, 0) for t in CHANGE_TYPES},
            "events_total": len(rows),
            "first_observed": min((row["observed_date"] for row in rows),
                                  default=None),
        },
    }


# --------------------------------------------------------------------- stage

def run_stage(out_dir: Path, cache_dir: Path,
              fingerprints: Mapping[str, tuple[str, str | None,
                                               float | None]],
              release: str, generated_at: str, *, offline_fixtures: bool,
              min_n: int | None = None, min_cna_events: int | None = None,
              log: Callable[[str], None] = print
              ) -> tuple[dict, dict, list[dict], dict | None]:
    """(rescore_log.json object, meta.sources.rescores object, merged
    event rows to persist, state to persist or None).

    The CSV rows and the state are RETURNED, not written: __main__ persists
    both only after every output validates (the nvd history-row pattern).
    That ordering is load-bearing for the release guard — a run that fails
    validation must not record tonight's release, or the retry would skip
    the diff and lose the night's events.

    * ``offline_fixtures`` — stateless baseline: no cached state is read
      or produced (state result is None), zero events; the prior log is
      still read from ``out_dir`` so the identical build/validate path
      runs against whatever the fixture out-dir holds (normally nothing).
    * live, no state — self-healing baseline: tonight's corpus becomes the
      new state and the night logs zero events. At worst one night's
      diffs are lost; the committed log is untouched by the rebuild.
    * live, state release == tonight's release — re-run of an already
      diffed corpus: skip the diff so nothing double-counts.
    * live, state release differs — diff and append.
    """
    if min_n is None:
        min_n = 1 if offline_fixtures else DEFAULT_MIN_N
    if min_cna_events is None:
        min_cna_events = 1 if offline_fixtures else DEFAULT_MIN_CNA_EVENTS

    events: list[dict] = []
    state = None if offline_fixtures else load_state(cache_dir, log=log)
    if offline_fixtures:
        pass  # stateless baseline by design (no .cache writes in tests)
    elif state is None:
        log("  rescore: no previous fingerprint state — baseline night, "
            "zero events (at worst one night's diffs are lost; the "
            "committed log is untouched)")
    elif state["release"] == release:
        log(f"  rescore: corpus release {release} already diffed — "
            f"skipping (re-runs never double-count)")
    else:
        events = diff_events(state["fingerprints"], fingerprints,
                             generated_at[:10])
        log(f"  rescore: {len(events)} event(s) "
            f"({state['release']} -> {release})")

    rows = read_events(out_dir / "history" / "rescore_log.csv") + events
    obj = build_rescore_log(rows, state_size=len(fingerprints),
                            release=release, generated_at=generated_at,
                            min_n=min_n, min_cna_events=min_cna_events)
    source = {"events_total": obj["catalog"]["events_total"],
              "state_release": release}
    new_state = None if offline_fixtures else make_state(release,
                                                         fingerprints)
    return obj, source, rows, new_state
