"""EPSS Volatility: the per-CVE EPSS change history nobody keeps.

Thesis: teams triage on the EPSS *percentile*, and that number moves under
almost every CVE every night — not because the model changed its mind, but
because the corpus grows by a few hundred CVEs a day and the whole
population reshuffles ranks. The model's actual *probability*, meanwhile,
holds for ~99% of records. The gap between "the percentile moved" and "the
probability moved" is the whole story, and no upstream publishes it: FIRST
ships the current daily snapshot, so the night-to-night deltas are only a
record if somebody keeps one.

This module keeps one. Each night the pipeline already fetches the EPSS
feed (``fetch_epss`` -> ``EpssData`` with ``.scores`` {cve: prob} and
``.percentiles`` {cve: percentile}); this stage diffs it against a
committed fingerprint of last night's feed and appends ONE aggregate row
per observed EPSS snapshot to an append-only committed CSV
(``site/data/history/epss_volatility.csv``). Like ``nvd_throughput.csv`` it
is one row per date (last run per date wins) — an original dataset this
project accumulates and CANNOT regenerate.

What each daily row records (the diff of the CVEs present on BOTH nights):

* ``prob_moved`` / ``pct_moved`` — how many compared CVEs had their raw
  probability, resp. their percentile, change at all. The GAP chart reads
  these two as shares of ``n_compared``.
* ``crossed_lo`` / ``crossed_mid`` / ``crossed_hi`` — how many crossed a
  material probability threshold (0.001 / 0.01 / 0.05) in either
  direction. The MATERIAL-CHURN chart reads these — a percentile reshuffle
  is not a decision change; a threshold crossing is.
* ``top_cve`` / ``top_old`` / ``top_new`` — the day's single biggest
  absolute probability move, for the MOVERS board (when the model actually
  changes its mind, here is how far).

Three kinds of night are QUARANTINED from every trend (churn weeks, gap,
movers, totals), the way Silent Rescores quarantines its seeding and KEV
Latency its launch batch. All three stay on the log for the audit trail and
are named, with their reason, in ``catalog.quarantined``:

* **reset** — the feed's ``model_version`` changed: a new model rescores
  the entire corpus overnight, so ~everything "moves" for a reason that has
  nothing to do with any one CVE. Flagged on the row at diff time
  (``reset``); its top mover is suppressed.
* **gap** — the row pools more than one snapshot: the previous logged row
  is more than a day older (failed nights in between), so the diff covers
  several nights and cannot sit in a per-night series. Classified at build
  time from the log itself (:func:`classify`).
* **anomaly** — a whole-corpus lurch with no model change: the share of
  compared CVEs whose probability moved exceeds
  :data:`ANOMALY_FACTOR` × the median share of the clean nights (and
  :data:`ANOMALY_MIN_SHARE` in absolute terms). Three such nights in
  August 2026 — 12–16 % of the corpus moved and moved back, the same CVE
  flip-flopping with identical old/new pairs — supplied nine in ten of
  every material crossing on record until this rule existed. A feed
  glitch is not the model changing its mind. Classified at build time, so
  the rule applies to the whole committed log, retroactively and
  reproducibly, with no schema change. Needs :data:`ANOMALY_MIN_NIGHTS`
  clean nights before it judges anything.

State (``{"model_version", "score_date", "last_observed", "fingerprints":
{cve: [prob, percentile|null]}}``) lives in the pipeline CACHE DIRECTORY
(``.cache/epss_volatility_state.json.gz``, actions/cache in CI — the NVD
sync-state pattern), gzipped, atomic tmp+replace. It is a cache, not a
record: the percentile map re-ranks wholesale every night, so committing
it added ~2.6 MB of undeltable history per night (90 % of the repository
after six weeks). A lost state costs at most one night's diff — the next
run is a baseline night — and the committed CSV is never touched by that.
State and log persist together after validation (via :func:`persist`), so
a failed run records neither; CI's cache is saved only when the job
succeeds, which gives the same guarantee across the claims gate. Offline
fixture runs keep the state beside the output instead, so a test run can
never seed or read a live cache. Same-snapshot guard: when tonight's EPSS
``score_date`` equals the state's, the snapshot was already diffed and the
diff is skipped; the merge-by-date write makes a genuine re-run idempotent
regardless (last run per date wins — a repeat diff of the same two
snapshots is the same row, unlike NVD throughput's flow rows).

Honesty caveat, stated in the copy and the docs: the moat here is softer
than the KEV changelog's. FIRST's daily EPSS snapshots ARE publicly
archived (dated files go back years), so CyberMon is the only *maintained*
per-CVE EPSS churn log, not the only possible source. Distinct from the
EPSS Report Card (module 10), which grades the model's ACCURACY; this
module measures its day-to-day STABILITY.

The record starts at first deploy: on the first run there is no prior
state, so the night is a baseline (zero rows), and the committed CSV ships
empty. The JSON renders an honest "not enough data yet" state until enough
diff-nights accumulate (``min_days`` gate).
"""
from __future__ import annotations

import csv
import gzip
import json
from collections import Counter
from datetime import date, timedelta
from pathlib import Path
from typing import Callable, Mapping

from .fetch_epss import EpssData
from .metrics import _pct

# Material probability thresholds (the decision lines teams actually gate
# on). A crossing of any of these — in either direction — is a real change
# in what the model is saying; a percentile reshuffle underneath a static
# probability is not. Contract mirrors these verbatim.
THRESHOLDS = {"lo": 0.001, "mid": 0.01, "hi": 0.05}

CSV_COLUMNS = ("observed_date", "model_version", "n_scored", "n_compared",
               "prob_moved", "pct_moved", "crossed_lo", "crossed_mid",
               "crossed_hi", "top_cve", "top_old", "top_new", "reset")
_INT_COLUMNS = ("n_scored", "n_compared", "prob_moved", "pct_moved",
                "crossed_lo", "crossed_mid", "crossed_hi")

STATE_FILENAME = "epss_volatility_state.json.gz"

# Anomaly quarantine (see the module docstring): a night whose share of
# compared CVEs with a moved probability is more than ANOMALY_FACTOR times
# the median share of the clean nights AND at least ANOMALY_MIN_SHARE
# percent. Clean nights run ~1 %; the August-2026 lurches ran 12–16 %.
# Judged only once ANOMALY_MIN_NIGHTS clean nights exist — a median of two
# is not a baseline. Contract and docs mirror these verbatim.
ANOMALY_FACTOR = 5.0
ANOMALY_MIN_SHARE = 5.0
ANOMALY_MIN_NIGHTS = 5
QUARANTINE_REASONS = ("reset", "gap", "anomaly")
# The offline prior-night seed is a small hand-written fixture, kept
# uncompressed for readability; the committed OUTPUT state is gzipped.
FIXTURE_STATE_FILENAME = "epss_volatility_state.json"
CSV_FILENAME = "epss_volatility.csv"

DEFAULT_MIN_DAYS = 3       # diff-nights before the churn/gap trends chart
DEFAULT_MIN_DELTA = 0.10   # min |prob move| for a mover to make the board
DEFAULT_BOARD_SIZE = 20    # movers board rows


def _r5(x: float) -> float:
    """EPSS probabilities/percentiles are published at 5 decimals — this
    module's documented exception to CyberMon's 1-decimal float rule (the
    EPSS Report Card takes the same exception, for the same reason: the
    difference between 0.04% and 0.4% is exactly what is being measured)."""
    return round(float(x), 5)


# ------------------------------------------------------------------ diffing

def _crossed(old: float, new: float, threshold: float) -> bool:
    """A material crossing: the pair straddles ``threshold`` (>= side flips
    between the two nights), in either direction."""
    return (old >= threshold) != (new >= threshold)


def diff_day(old_fps: Mapping[str, list], new_scores: Mapping[str, float],
             new_pcts: Mapping[str, float], observed_date: str,
             model_version: str, *, reset: bool) -> dict:
    """Diff last night's fingerprints against tonight's feed into one
    aggregate row.

    Only CVEs present on BOTH nights are compared: a CVE new to tonight's
    feed has no prior to move from (it is the corpus growth that drives the
    percentile reshuffle, not an event), and a CVE that dropped out simply
    left. ``reset`` (model_version changed) is recorded on the row and
    disqualifies it from every trend; its top mover is suppressed, because
    a whole-distribution rebaseline is not one CVE changing its mind.
    """
    n_compared = prob_moved = pct_moved = 0
    crossed = Counter()
    top: tuple[float, str, float, float] | None = None  # (|d|, cve, old, new)
    for cve, new_p in new_scores.items():
        fp = old_fps.get(cve)
        if fp is None:
            continue  # brand-new to tonight's feed -> nothing to compare
        old_p = fp[0]
        old_pct = fp[1] if len(fp) > 1 else None
        n_compared += 1
        if _r5(new_p) != _r5(old_p):
            prob_moved += 1
            for band, thr in THRESHOLDS.items():
                if _crossed(old_p, new_p, thr):
                    crossed[band] += 1
            cand = (abs(new_p - old_p), cve, _r5(old_p), _r5(new_p))
            if not reset and (top is None or cand > top):
                top = cand
        new_pct = new_pcts.get(cve)
        if old_pct is not None and new_pct is not None \
                and _r5(new_pct) != _r5(old_pct):
            pct_moved += 1
    return {
        "observed_date": observed_date,
        "model_version": model_version,
        "n_scored": len(new_scores),
        "n_compared": n_compared,
        "prob_moved": prob_moved,
        "pct_moved": pct_moved,
        "crossed_lo": crossed["lo"],
        "crossed_mid": crossed["mid"],
        "crossed_hi": crossed["hi"],
        "top_cve": top[1] if top else None,
        "top_old": top[2] if top else None,
        "top_new": top[3] if top else None,
        "reset": reset,
    }


# -------------------------------------------------------------------- state

def state_path(state_dir: Path) -> Path:
    """The fingerprint state inside ``state_dir`` — the pipeline cache
    directory for live runs (never committed; see the module docstring),
    ``<out>/history`` for offline fixture runs."""
    return state_dir / STATE_FILENAME


def csv_path(out_dir: Path) -> Path:
    return out_dir / "history" / CSV_FILENAME


def load_state(state_dir: Path, log: Callable[[str], None] = print
               ) -> dict | None:
    """Cached EPSS fingerprint state, or None when absent/unreadable/
    misshapen (the stage then treats tonight as a baseline and logs zero
    rows — a lost state costs at most one night's diff; the committed log is
    the record and is never touched by the rebuild)."""
    path = state_path(state_dir)
    if not path.exists():
        return None
    try:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError) as exc:
        log(f"warning: ignoring unreadable EPSS-volatility state {path}: "
            f"{exc!r}")
        return None
    if not isinstance(state, dict) \
            or not isinstance(state.get("score_date"), str) \
            or not isinstance(state.get("model_version"), str) \
            or not isinstance(state.get("fingerprints"), dict):
        log(f"warning: ignoring misshapen EPSS-volatility state {path}")
        return None
    return state


def make_state(epss: EpssData) -> dict:
    """Tonight's persistable state: the per-CVE ``[prob, percentile|null]``
    fingerprint plus the header metadata the guards key on. ``last_observed``
    equals ``score_date`` (a diff row is stamped with the EPSS snapshot date
    it observed, not the wall-clock run date)."""
    fingerprints = {cve: [_r5(prob), _r5(epss.percentiles[cve])
                          if cve in epss.percentiles else None]
                    for cve, prob in epss.scores.items()}
    return {"model_version": epss.model_version,
            "score_date": epss.score_date,
            "last_observed": epss.score_date,
            "fingerprints": fingerprints}


def write_state(path: Path, state: dict) -> None:
    """Atomic tmp+replace (the rescore_state.json pattern); compact
    separators because the fingerprint map covers the whole EPSS corpus.
    Gzipped with a zeroed mtime (identical state -> identical bytes)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    data = (json.dumps(state, sort_keys=True, separators=(",", ":"))
            + "\n").encode("utf-8")
    with open(tmp, "wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
            gz.write(data)
    tmp.replace(path)


# ---------------------------------------------------------- the event log

def read_events(path: Path) -> list[dict]:
    """Read the committed daily log, oldest first, sorted by date. Missing
    file -> empty list. Malformed rows fail loudly — this file is the
    irreplaceable historical record and silent loss would be worse than a
    crash."""
    if not path.exists():
        return []
    rows: list[dict] = []
    with path.open("r", newline="", encoding="utf-8") as f:
        for lineno, raw in enumerate(csv.DictReader(f), start=2):
            try:
                row = {
                    "observed_date": raw["observed_date"],
                    "model_version": raw["model_version"],
                    **{col: int(raw[col]) for col in _INT_COLUMNS},
                    "top_cve": raw["top_cve"] or None,
                    "top_old": float(raw["top_old"])
                    if raw["top_old"] else None,
                    "top_new": float(raw["top_new"])
                    if raw["top_new"] else None,
                    "reset": raw["reset"] == "1",
                }
                if not row["observed_date"] or not row["model_version"]:
                    raise ValueError("empty required field")
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"{path}:{lineno}: malformed EPSS-volatility "
                                 f"row {raw!r}") from exc
            rows.append(row)
    rows.sort(key=lambda r: r["observed_date"])
    return rows


def merge_row(rows: list[dict], row: dict) -> list[dict]:
    """Insert ``row`` (replacing any existing row with the same observed
    date — last run per date wins, the nvd_backlog.csv pattern) and return a
    new list sorted ascending by date. Kept pure (no I/O) so the merged log
    can be built in memory and the disk write deferred until validation."""
    merged = [r for r in rows if r["observed_date"] != row["observed_date"]]
    merged.append(row)
    merged.sort(key=lambda r: r["observed_date"])
    return merged


def write_events(path: Path, rows: list[dict]) -> None:
    """Rewrite the CSV atomically (temp file, then ``replace``) — an
    interrupted run must leave either the old file or the new one, never a
    truncation (the nvd_backlog.csv discipline). Probabilities are written
    at 5-decimal precision; None fields as empty strings; the reset flag as
    ``1`` / empty."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                "observed_date": row["observed_date"],
                "model_version": row["model_version"],
                **{col: row[col] for col in _INT_COLUMNS},
                "top_cve": row["top_cve"] or "",
                "top_old": "" if row["top_old"] is None
                else f"{row['top_old']:.5f}",
                "top_new": "" if row["top_new"] is None
                else f"{row['top_new']:.5f}",
                "reset": "1" if row["reset"] else "",
            })
    tmp.replace(path)


# ------------------------------------------------------------------ builder

def _week_monday(day: date) -> date:
    return day - timedelta(days=day.isocalendar()[2] - 1)


def _week_label(day: date) -> str:
    iso_year, iso_week, _ = day.isocalendar()
    return f"{iso_year}-W{iso_week:02d}"


def _weekly_churn(rows: list[dict]) -> list[dict]:
    """Per-ISO-week material-crossing counts, gap-filled between the first
    and last observed week so the axis never silently skips time. Reset rows
    are already excluded by the caller."""
    by_monday: dict[date, Counter] = {}
    for row in rows:
        monday = _week_monday(date.fromisoformat(row["observed_date"]))
        counts = by_monday.setdefault(monday, Counter())
        counts["lo"] += row["crossed_lo"]
        counts["mid"] += row["crossed_mid"]
        counts["hi"] += row["crossed_hi"]
        counts["days"] += 1
    if not by_monday:
        return []
    weeks = []
    monday, last = min(by_monday), max(by_monday)
    while monday <= last:
        counts = by_monday.get(monday, Counter())
        weeks.append({"week": _week_label(monday),
                      "crossed_lo": counts.get("lo", 0),
                      "crossed_mid": counts.get("mid", 0),
                      "crossed_hi": counts.get("hi", 0),
                      "days": counts.get("days", 0)})
        monday += timedelta(days=7)
    return weeks


def classify(rows: list[dict]) -> list[str | None]:
    """One quarantine reason per row (``None`` = a clean trend night), in
    the rows' (date-sorted) order. Pure function of the log, so the same
    committed CSV always yields the same trend; see the module docstring
    for the three reasons. A row is judged in the order reset > anomaly >
    gap, so a lurch that also pooled nights is named for the lurch."""
    n = len(rows)
    reasons: list[str | None] = [None] * n
    span = [1] * n
    for i in range(1, n):
        span[i] = (date.fromisoformat(rows[i]["observed_date"])
                   - date.fromisoformat(rows[i - 1]["observed_date"])).days
    share = [_pct(r["prob_moved"], r["n_compared"]) for r in rows]
    for i, r in enumerate(rows):
        if r["reset"]:
            reasons[i] = "reset"
    # The baseline for "normal" is the median share of the nights that are
    # neither resets nor pooled — a median, so a handful of lurches cannot
    # drag it up to excuse themselves.
    clean = sorted(share[i] for i in range(n)
                   if reasons[i] is None and span[i] <= 1)
    if clean:
        mid = len(clean) // 2
        median = (clean[mid] if len(clean) % 2
                  else (clean[mid - 1] + clean[mid]) / 2)
        cutoff = max(ANOMALY_FACTOR * median, ANOMALY_MIN_SHARE)
        for i in range(n):
            if reasons[i] is not None:
                continue
            # A night is judged only against at least MIN_NIGHTS OTHER
            # baseline nights (it sits in the pool itself when unpooled).
            others = len(clean) - (1 if span[i] <= 1 else 0)
            if others >= ANOMALY_MIN_NIGHTS and share[i] > cutoff:
                reasons[i] = "anomaly"
    for i in range(n):
        if reasons[i] is None and span[i] > 1:
            reasons[i] = "gap"
    return reasons


def build_epss_volatility(rows: list[dict], *, state: dict | None,
                          generated_at: str, min_days: int = DEFAULT_MIN_DAYS,
                          min_delta: float = DEFAULT_MIN_DELTA,
                          board_size: int = DEFAULT_BOARD_SIZE) -> dict:
    """Assemble epss_volatility.json from the full committed daily log.

    Everything charted is computed over the log, and the log starts at first
    deploy: the file renders the thin early record honestly. ``catalog``
    says exactly how many diff-nights exist; nothing here fakes depth.

    * ``churn.weeks`` — per-ISO-week material-crossing counts (reset rows
      excluded), gap-filled; empty until ``min_days`` trend-nights exist.
    * ``gap`` — the headline: per-day shares of compared CVEs whose
      percentile moved vs. whose probability moved, plus their averages.
      ``days``/averages are null-or-empty until the ``min_days`` gate opens;
      below it the site renders the placeholder from ``trend_days``.
    * ``movers`` — the biggest single-day probability moves on record
      (``>= min_delta``), ranked; fills as the record grows.
    * ``catalog`` — the audit block: state header + size, nights observed,
      the quarantined nights by reason (reset / gap / anomaly, each named
      with its date and share), per-band crossing totals, first observed
      date (null exactly when the log is empty).
    """
    rows = sorted(rows, key=lambda r: r["observed_date"])
    reasons = classify(rows)
    trend = [r for r, why in zip(rows, reasons) if why is None]
    quarantined = [{"date": r["observed_date"], "reason": why,
                    "prob_moved_pct": _pct(r["prob_moved"], r["n_compared"])}
                   for r, why in zip(rows, reasons) if why is not None]
    by_reason = Counter(q["reason"] for q in quarantined)
    gated = len(trend) < min_days

    # ---- section 1: material churn per week --------------------------------
    weeks = [] if gated else _weekly_churn(trend)

    # ---- section 2: the headline gap ---------------------------------------
    days = []
    for row in trend:
        n = row["n_compared"]
        days.append({"date": row["observed_date"],
                     "prob_moved": _pct(row["prob_moved"], n),
                     "pct_moved": _pct(row["pct_moved"], n)})
    total_compared = sum(r["n_compared"] for r in trend)
    gap: dict = {"min_days": min_days, "trend_days": len(trend),
                 "prob_moved_pct": None, "pct_moved_pct": None, "days": []}
    if not gated:
        gap["days"] = days
        gap["prob_moved_pct"] = _pct(sum(r["prob_moved"] for r in trend),
                                     total_compared)
        gap["pct_moved_pct"] = _pct(sum(r["pct_moved"] for r in trend),
                                    total_compared)

    # ---- section 3: biggest single-day movers ------------------------------
    movers = [{"cve": r["top_cve"], "observed_date": r["observed_date"],
               "old": r["top_old"], "new": r["top_new"],
               "delta": _r5(r["top_new"] - r["top_old"])}
              for r in trend
              if r["top_cve"] and r["top_old"] is not None
              and r["top_new"] is not None
              and abs(r["top_new"] - r["top_old"]) >= min_delta]
    movers.sort(key=lambda m: (-abs(m["delta"]), m["observed_date"], m["cve"]))
    movers = movers[:board_size]

    crossed_totals = {band: sum(r[f"crossed_{band}"] for r in trend)
                      for band in ("lo", "mid", "hi")}

    return {
        "generated_at": generated_at,
        "thresholds": dict(THRESHOLDS),
        "churn": {"weeks": weeks},
        "gap": gap,
        "movers": {"min_delta": _r5(min_delta), "entries": movers},
        "catalog": {
            "state_model_version": (state or {}).get("model_version", ""),
            "state_score_date": (state or {}).get("score_date", ""),
            "state_size": len((state or {}).get("fingerprints", {})),
            "days_observed": len(rows),
            "trend_days": len(trend),
            "resets_quarantined": by_reason["reset"],
            "gaps_quarantined": by_reason["gap"],
            "anomalies_quarantined": by_reason["anomaly"],
            "anomaly_rule": {"factor": ANOMALY_FACTOR,
                             "min_share_pct": ANOMALY_MIN_SHARE,
                             "min_nights": ANOMALY_MIN_NIGHTS},
            "quarantined": quarantined,
            "crossed_totals": crossed_totals,
            "first_observed": min((r["observed_date"] for r in rows),
                                  default=None),
        },
    }


# --------------------------------------------------------------------- stage

def persist(out_dir: Path, rows: list[dict], state: dict | None, *,
            state_dir: Path, log: Callable[[str], None] = print) -> None:
    """Write the daily log and the fingerprint state — called by
    ``__main__.run()`` only after every pipeline output has validated (the
    rescore_tracker.persist discipline). State None means the log alone is
    written; state and log otherwise land in the same deferred phase and
    travel in the same nightly data commit."""
    write_events(csv_path(out_dir), rows)
    log(f"  history: {len(rows)} EPSS-volatility day(s) in "
        f"{csv_path(out_dir)}")
    if state is not None:
        write_state(state_path(state_dir), state)
        log(f"  epssvol: state covers {len(state['fingerprints'])} "
            f"EPSS fingerprint(s) in {state_path(state_dir)}")


def run_stage(out_dir: Path, epss: EpssData, generated_at: str, *,
              state_dir: Path, offline_fixtures: bool,
              fixtures_dir: Path | None = None,
              min_days: int | None = None, min_delta: float | None = None,
              log: Callable[[str], None] = print
              ) -> tuple[dict, dict, list[dict], dict | None]:
    """(epss_volatility.json object, meta.sources.epssvol object, merged
    daily rows to persist, state to persist or None).

    The CSV rows and the state are RETURNED, not written: __main__ persists
    both via :func:`persist` only after every output validates (the
    rescore_tracker pattern). That ordering is load-bearing — a run that
    fails validation must not record tonight's snapshot as diffed, or the
    retry would skip the diff and lose the night.

    * live, no committed state — baseline night: tonight's feed becomes the
      new state and zero rows are logged (the record starts here). At worst
      one night's diff is lost; the committed log is untouched.
    * ``offline_fixtures`` with no committed state — seed the prior night
      from ``fixtures/epss_volatility_state.json`` (the kev_changelog
      offline pattern) so the fixture diff produces a real row, then the
      identical build/validate path runs; a re-run loads the committed state
      and is idempotent.
    * state score_date == tonight's — the same EPSS snapshot was already
      diffed: skip. (The merge-by-date write makes a re-run idempotent even
      if this guard is bypassed.)
    * model_version changed — a whole-distribution reset: the row is written
      flagged and every trend excludes it (the Silent-Rescores seeding
      quarantine, applied to EPSS).
    """
    if min_days is None:
        min_days = 1 if offline_fixtures else DEFAULT_MIN_DAYS
    if min_delta is None:
        min_delta = 0.0 if offline_fixtures else DEFAULT_MIN_DELTA
    fixtures_dir = fixtures_dir or (Path(__file__).resolve().parent
                                    / "tests" / "fixtures")

    rows = read_events(csv_path(out_dir))
    state = load_state(state_dir, log=log)
    if offline_fixtures and state is None:
        state = json.loads((fixtures_dir / FIXTURE_STATE_FILENAME)
                           .read_text(encoding="utf-8"))
        log(f"  epssvol: seeded prior EPSS state from fixtures "
            f"({len(state['fingerprints'])} fingerprints, "
            f"score_date {state['score_date']})")

    if state is None:
        log("  epssvol: no previous EPSS state — baseline night, zero rows "
            "(the record starts now; at worst one night's diff is lost)")
    elif state["score_date"] == epss.score_date:
        log(f"  epssvol: EPSS snapshot {epss.score_date} already diffed — "
            f"skipping (re-runs never double-count)")
    else:
        reset = state["model_version"] != epss.model_version
        row = diff_day(state["fingerprints"], epss.scores, epss.percentiles,
                       epss.score_date, epss.model_version, reset=reset)
        rows = merge_row(rows, row)
        if reset:
            log(f"  epssvol: model_version {state['model_version']} -> "
                f"{epss.model_version} — reset night quarantined from the "
                f"trend ({row['n_compared']} CVEs rebaselined)")
        else:
            log(f"  epssvol: {row['prob_moved']}/{row['n_compared']} probs "
                f"moved, {row['pct_moved']} percentiles moved, "
                f"{row['crossed_lo'] + row['crossed_mid'] + row['crossed_hi']}"
                f" material crossing(s) ({state['score_date']} -> "
                f"{epss.score_date})")

    new_state = make_state(epss)
    obj = build_epss_volatility(rows, state=new_state,
                                generated_at=generated_at, min_days=min_days,
                                min_delta=min_delta)
    source = {"score_date": epss.score_date,
              "days_observed": obj["catalog"]["days_observed"]}
    return obj, source, rows, new_state
