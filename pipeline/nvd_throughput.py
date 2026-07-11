"""NVD throughput: turn our per-CVE status snapshots into flow.

``fetch_nvd`` keeps a ``{cve_id: vulnStatus}`` sync state; NVD itself
publishes only the current totals, never the flow — how many CVEs move
between statuses per day, or how long a CVE waits in the queue. This
module derives that flow by diffing yesterday's synced state against
today's, and persists it in an append-only committed CSV
(``site/data/history/nvd_throughput.csv``). Like ``nvd_backlog.csv``,
that CSV is the IRREPLACEABLE historical record: no upstream source can
regenerate it, so a lost file is lost history.

State extension (additive, owned here — ``fetch_nvd`` never reads it):

* ``status_since``: ``{cve_id: "YYYY-MM-DD"}`` — the date *CyberMon first
  observed* the CVE in its current status. NVD exposes no such date, so
  this is by construction observed-by-us: assigned only when a diff sees
  the status change (or a CVE appear), and lower-bounded by our nightly
  snapshot cadence. It is NEVER bulk-initialized — an old-format state
  (plain ``{cve: status}``) loads cleanly with every since-date unknown,
  and durations only accumulate for transitions observed after this
  tracker shipped. A since-date is never faked.
* ``queue_durations``: accumulated observed queue days (ints) for
  queue→Analyzed transitions whose since-date was known. Lives in the
  state (a cache): if the state is ever lost, accumulation restarts, but
  the CSV keeps every row already measured.

``fetch_nvd.sync_status_state`` returns a fresh dict without these keys;
the pipeline re-attaches them via :func:`attach_tracking` after every
sync, computing them from the *previous* state it loaded.

Transition semantics (per nightly diff, previous state vs synced state):

* ``received_new``      — entered "Received" (including CVEs newly seen).
* ``entered_awaiting``  — entered "Awaiting Analysis" (ditto).
* ``analyzed_from_awaiting`` — left "Awaiting Analysis" or "Undergoing
  Analysis" for "Analyzed"; when the since-date of the status it left is
  known, the observed days spent there join ``queue_durations``. Every
  duration is a lower bound: the clock starts at our first observation
  of that status, and an Awaiting→Undergoing hop restarts it.
* ``deferred_from_awaiting`` — left a live-queue status for "Deferred".
* ``modified_re``       — re-entered "Modified" (logged, not persisted).

Weekly full resweeps (see ``fetch_nvd.FULL_RESYNC_DAYS``) heal any drift
the incremental syncs missed, so a resweep day can legitimately register
catch-up transitions in one lump — most visibly re-Modified spikes;
analyzed/deferred transitions are real regardless of which sync path saw
them. Resweep days are detectable (``last_full_sync`` changed) and are
flagged in the CSV so readers can tell a lump from a trend.

The CSV keeps one row per run date, last run per date wins, sorted
ascending — the same rules as ``pipeline.history``. ``median_queue_days``
and ``n_known_duration`` are cumulative over the whole record (the median
of every known duration observed so far); the median stays null until
``MIN_KNOWN_DURATIONS`` transitions have a known duration, because a
median of a handful of observations is noise wearing a unit.
"""
from __future__ import annotations

import csv
import re
import statistics
from datetime import date as date_cls
from pathlib import Path

# Median publishes only past this many known-duration transitions; below
# it the stat card shows the accumulating count instead. Documented in
# docs/data-contracts.md and surfaced in the JSON as min_known_duration.
MIN_KNOWN_DURATIONS = 30

QUEUE_STATUSES = ("Received", "Awaiting Analysis", "Undergoing Analysis")
_PRE_ANALYZED = ("Awaiting Analysis", "Undergoing Analysis")

COLUMNS = ("date", "received_new", "entered_awaiting",
           "analyzed_from_awaiting", "deferred_from_awaiting",
           "median_queue_days", "n_known_duration", "resweep")
_COUNT_COLUMNS = ("received_new", "entered_awaiting",
                  "analyzed_from_awaiting", "deferred_from_awaiting")

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _parse_date(value: str) -> date_cls | None:
    if isinstance(value, str) and _DATE_RE.match(value):
        try:
            return date_cls.fromisoformat(value)
        except ValueError:
            return None
    return None


# ------------------------------------------------------------- state diff --

def diff_transitions(prev_state: dict | None, new_state: dict,
                     today: str) -> dict | None:
    """Diff two sync states into one day's transition record, or None when
    there is no usable previous state to diff against.

    Returns ``{"counts": {...}, "durations": [int...], "status_since":
    {...}, "resweep": bool}``. ``status_since`` is the map to persist on
    the new state: carried forward for unchanged statuses, set to
    ``today`` for observed changes, absent (unknown) everywhere else.

    Never crashes on an old-format state: a missing/foreign
    ``status_since`` reads as "all since-dates unknown", and durations
    simply do not accumulate for those CVEs. With no previous state at
    all (first run, wiped cache) the answer is None — diffing against
    nothing would count the entire corpus as one day's transitions.
    """
    if not isinstance(prev_state, dict):
        return None
    prev_statuses = prev_state.get("statuses")
    if not isinstance(prev_statuses, dict) or not prev_statuses:
        return None
    new_statuses = new_state.get("statuses") or {}

    prev_since = prev_state.get("status_since")
    if not isinstance(prev_since, dict):
        prev_since = {}

    today_date = _parse_date(today)
    counts = {"received_new": 0, "entered_awaiting": 0,
              "analyzed_from_awaiting": 0, "deferred_from_awaiting": 0,
              "modified_re": 0}
    durations: list[int] = []
    status_since: dict[str, str] = {}

    for cve_id, status in new_statuses.items():
        prev = prev_statuses.get(cve_id)
        if prev == status:
            carried = prev_since.get(cve_id)
            if isinstance(carried, str):
                status_since[cve_id] = carried
            continue
        # observed change (or first appearance): the one honest moment to
        # stamp a since-date.
        status_since[cve_id] = today
        if status == "Received":
            counts["received_new"] += 1
        elif status == "Awaiting Analysis":
            counts["entered_awaiting"] += 1
        elif status == "Analyzed" and prev in _PRE_ANALYZED:
            counts["analyzed_from_awaiting"] += 1
            since = _parse_date(prev_since.get(cve_id, ""))
            if since is not None and today_date is not None \
                    and since <= today_date:
                durations.append((today_date - since).days)
        elif status == "Deferred" and prev in QUEUE_STATUSES:
            counts["deferred_from_awaiting"] += 1
        elif status == "Modified" and prev is not None:
            counts["modified_re"] += 1

    resweep = (new_state.get("last_full_sync")
               != prev_state.get("last_full_sync"))
    return {"counts": counts, "durations": durations,
            "status_since": status_since, "resweep": bool(resweep)}


def attach_tracking(new_state: dict, prev_state: dict | None,
                    transitions: dict | None) -> list[int]:
    """Attach the tracking keys to a freshly synced state (which
    ``fetch_nvd`` returns bare) and return the accumulated durations.

    With no transitions (no previous state) the new state carries no
    tracking keys — since-dates are never bulk-initialized — and the
    accumulated durations are whatever the previous state had (nothing).
    """
    prev_durations = (prev_state or {}).get("queue_durations")
    if not isinstance(prev_durations, list):
        prev_durations = []
    prev_durations = [d for d in prev_durations
                      if isinstance(d, int) and not isinstance(d, bool)
                      and d >= 0]
    if transitions is None:
        return prev_durations
    accumulated = prev_durations + list(transitions["durations"])
    new_state["status_since"] = transitions["status_since"]
    new_state["queue_durations"] = accumulated
    return accumulated


# ---------------------------------------------------------------- CSV I/O --
# Mirrors pipeline.history (the nvd_backlog.csv helpers) but with this
# file's columns: median_queue_days may be empty (null), resweep is 0/1.

def read_rows(path: Path) -> list[dict]:
    """Read throughput history rows, oldest first. Missing file -> empty
    list; malformed rows fail loudly — this file is the historical record
    and silent data loss would be worse than a crash."""
    if not path.exists():
        return []
    rows: list[dict] = []
    with path.open("r", newline="", encoding="utf-8") as f:
        for lineno, raw in enumerate(csv.DictReader(f), start=2):
            try:
                row: dict = {"date": raw["date"]}
                if not _DATE_RE.match(row["date"]):
                    raise ValueError(f"bad date {row['date']!r}")
                for col in _COUNT_COLUMNS:
                    row[col] = int(raw[col])
                median = raw["median_queue_days"]
                row["median_queue_days"] = float(median) if median else None
                row["n_known_duration"] = int(raw["n_known_duration"])
                row["resweep"] = int(raw["resweep"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"{path}:{lineno}: malformed throughput "
                                 f"row {raw!r}") from exc
            rows.append(row)
    rows.sort(key=lambda r: r["date"])
    return rows


def merge_row(rows: list[dict], row: dict) -> list[dict]:
    """Pure merge, no I/O: insert ``row`` (replacing any existing row with
    the same date — last run per date wins) sorted ascending by date."""
    merged = [r for r in rows if r["date"] != row["date"]]
    merged.append(dict(row))
    merged.sort(key=lambda r: r["date"])
    return merged


def write_rows(path: Path, rows: list[dict]) -> None:
    """Rewrite the CSV atomically (temp file, then ``replace``) — an
    interrupted run must leave the old file or the new one, never a
    truncation. Null medians are written as empty cells."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        for row in rows:
            out = dict(row)
            if out.get("median_queue_days") is None:
                out["median_queue_days"] = ""
            writer.writerow(out)
    tmp.replace(path)


# ------------------------------------------------------------ row + build --

def throughput_row(counts: dict, accumulated_durations: list[int],
                   date: str, resweep: bool) -> dict:
    """One nvd_throughput.csv row for ``date``. The median/count pair is
    cumulative over the whole record; the median stays None below
    ``MIN_KNOWN_DURATIONS`` known durations."""
    n_known = len(accumulated_durations)
    median = round(float(statistics.median(accumulated_durations)), 1) \
        if n_known >= MIN_KNOWN_DURATIONS else None
    return {"date": date,
            "received_new": int(counts["received_new"]),
            "entered_awaiting": int(counts["entered_awaiting"]),
            "analyzed_from_awaiting": int(counts["analyzed_from_awaiting"]),
            "deferred_from_awaiting": int(counts["deferred_from_awaiting"]),
            "median_queue_days": median,
            "n_known_duration": n_known,
            "resweep": 1 if resweep else 0}


def build_nvd_throughput(history_rows: list[dict], generated_at: str) -> dict:
    """nvd_throughput.json: the daily flow series plus the cumulative
    queue-days stat (docs/data-contracts.md). An empty history is legal —
    the record starts at first deploy and this object says so honestly."""
    latest = history_rows[-1] if history_rows else None
    return {
        "generated_at": generated_at,
        "min_known_duration": MIN_KNOWN_DURATIONS,
        "queue": {
            "median_days": latest["median_queue_days"] if latest else None,
            "n_known_duration": latest["n_known_duration"] if latest else 0,
        },
        "history": [{"date": r["date"],
                     "received_new": int(r["received_new"]),
                     "entered_awaiting": int(r["entered_awaiting"]),
                     "analyzed_from_awaiting":
                         int(r["analyzed_from_awaiting"]),
                     "deferred_from_awaiting":
                         int(r["deferred_from_awaiting"]),
                     "resweep": bool(r["resweep"])}
                    for r in history_rows],
    }
