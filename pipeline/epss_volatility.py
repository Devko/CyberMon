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

Model-version reset shocks are QUARANTINED, the way Silent Rescores
quarantines its seeding and KEV Latency quarantines its launch batch: when
the feed's ``model_version`` changes, a new model rescores the entire
corpus overnight, so ~everything "moves" for a reason that has nothing to
do with any one CVE. That night's row is written for the audit trail with
``reset`` set, and every trend (churn weeks, gap, movers, totals) excludes
reset rows. Only ``catalog.resets_quarantined`` counts them.

State (``site/data/history/epss_volatility_state.json``, COMMITTED next to
the log — the rescore_state.json / kev_state.json pattern, plain JSON,
atomic tmp+replace): ``{"model_version", "score_date", "last_observed",
"fingerprints": {cve: [prob, percentile|null]}}``. State and log persist
together after validation (via :func:`persist`), so a failed run records
neither, and the two can never diverge. Same-snapshot guard: when tonight's
EPSS ``score_date`` equals the state's, the snapshot was already diffed and
the diff is skipped; the merge-by-date write makes a genuine re-run
idempotent regardless (last run per date wins).

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

STATE_FILENAME = "epss_volatility_state.json"
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

def state_path(out_dir: Path) -> Path:
    """Committed next to the log (the rescore_state.json pattern): state and
    log travel in the same nightly data commit and cannot diverge."""
    return out_dir / "history" / STATE_FILENAME


def csv_path(out_dir: Path) -> Path:
    return out_dir / "history" / CSV_FILENAME


def load_state(out_dir: Path, log: Callable[[str], None] = print
               ) -> dict | None:
    """Committed EPSS fingerprint state, or None when absent/unreadable/
    misshapen (the stage then treats tonight as a baseline and logs zero
    rows — a lost state costs at most one night's diff; the committed log is
    the record and is never touched by the rebuild)."""
    path = state_path(out_dir)
    if not path.exists():
        return None
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
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
    separators because the fingerprint map covers the whole EPSS corpus."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, sort_keys=True,
                              separators=(",", ":")) + "\n",
                   encoding="utf-8")
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
      reset nights quarantined, per-band crossing totals, first observed
      date (null exactly when the log is empty).
    """
    trend = [r for r in rows if not r["reset"]]
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
            "resets_quarantined": len(rows) - len(trend),
            "crossed_totals": crossed_totals,
            "first_observed": min((r["observed_date"] for r in rows),
                                  default=None),
        },
    }


# --------------------------------------------------------------------- stage

def persist(out_dir: Path, rows: list[dict], state: dict | None,
            log: Callable[[str], None] = print) -> None:
    """Write the daily log and the fingerprint state — called by
    ``__main__.run()`` only after every pipeline output has validated (the
    rescore_tracker.persist discipline). State None means the log alone is
    written; state and log otherwise land in the same deferred phase and
    travel in the same nightly data commit."""
    write_events(csv_path(out_dir), rows)
    log(f"  history: {len(rows)} EPSS-volatility day(s) in "
        f"{csv_path(out_dir)}")
    if state is not None:
        write_state(state_path(out_dir), state)
        log(f"  epssvol: state covers {len(state['fingerprints'])} "
            f"EPSS fingerprint(s) in {state_path(out_dir)}")


def run_stage(out_dir: Path, epss: EpssData, generated_at: str, *,
              offline_fixtures: bool, fixtures_dir: Path | None = None,
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
    state = load_state(out_dir, log=log)
    if offline_fixtures and state is None:
        state = json.loads((fixtures_dir / STATE_FILENAME)
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
