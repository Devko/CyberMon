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
* ``queue_log_start`` / ``queue_exits``: the exit log behind the queue
  survival curve (:func:`build_queue_survival`). ``queue_log_start`` is
  the run date of the first snapshot the log watched from; it is set on
  the first run that finds tracking keys but no log, and that run logs
  nothing. From the next run on, EVERY end of a timed queue episode
  (Awaiting/Undergoing with a known since-date) is logged as
  ``[wait_days, entry_days, code]``: ``wait_days`` from the since-date to
  tonight's run date, ``entry_days`` = the episode's age when the log
  started watching it (0 for episodes first seen after the start), and
  ``code`` A (Analyzed), D (Deferred), O (any other status outside the
  live queue: Rejected, Modified, ...) or R (back to Received; the
  episode ends without leaving the queue, so it is censored, not an
  exit). The median above times Analyzed exits only, and only waits that
  have ended; the log also keeps the Deferred and other exits, so the
  curve can count every way out of the queue and every CVE still in it.

``fetch_nvd.sync_status_state`` returns a fresh dict without these keys;
the pipeline re-attaches them via :func:`attach_tracking` after every
sync, computing them from the *previous* state it loaded.

Transition semantics (per nightly diff, previous state vs synced state):

* ``received_new``      — entered "Received" (including CVEs newly seen).
* ``entered_awaiting``  — entered "Awaiting Analysis" (ditto).
* ``analyzed_from_awaiting`` — left "Awaiting Analysis" or "Undergoing
  Analysis" for "Analyzed"; when the since-date of the status it left is
  known, the observed days spent there join ``queue_durations``. Every
  duration is a lower bound: the clock starts at our first sighting of
  the CVE in the queue. "Awaiting Analysis" and "Undergoing Analysis"
  are one queue episode — a hop between them carries the since-date
  forward instead of restarting it — so the measured wait spans the
  whole visible stay in the queue, not just its last status segment.
  Any other transition (a fresh entry, a Received→Awaiting step, a
  Deferred→Awaiting return) stamps a new since-date.
* ``deferred_from_awaiting`` — left a live-queue status for "Deferred".
* ``modified_re``       — re-entered "Modified" (logged, not persisted).

Weekly full resweeps (see ``fetch_nvd.FULL_RESYNC_DAYS``) heal any drift
the incremental syncs missed, so a resweep can legitimately register
catch-up transitions in one lump — most visibly re-Modified spikes;
analyzed/deferred transitions are real regardless of which sync path saw
them. Resweep days are detectable (``last_full_sync`` changed) and are
flagged in the CSV (``resweep``) so readers can tell a lump from a trend.

The lump does not land on the resweep day itself. A full sweep reads
NVD's yearly feeds, which regenerate nightly and can be ~24 h stale, so
the resweep diff sees a FROZEN snapshot (typically few transitions);
``fetch_nvd`` back-dates ``last_sync`` by ``FEED_STALENESS`` (~25 h) and
the next incremental pull re-covers the gap — the catch-up arrives in
the diff AFTER the resweep. The published JSON therefore carries a second
flag, ``after_resweep``, DERIVED at build time from the record (true on
the row that follows a ``resweep`` row); the CSV keeps its committed
shape, one ``resweep`` column, and no row's meaning changes.

The CSV keeps one row per run date, sorted ascending. Unlike
``pipeline.history`` (last run per date wins), a second run on the same
date ADDS its flow counts to that date's row (see ``merge_row``). ``median_queue_days``
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

# Queue survival curve (build_queue_survival). The curve publishes only
# once the exit log is MIN_LOG_DAYS old (four weekly resweep cycles, so one
# lumpy night cannot shape it) and holds MIN_KNOWN_DURATIONS exits; it is
# cut at the first day where fewer than MIN_AT_RISK episodes are under
# watch, because past that point each step rests on a handful of CVEs.
MIN_LOG_DAYS = 28
MIN_AT_RISK = 30
# Days the survival block reports the share still waiting at, when the
# curve reaches them. 30 feeds the section headline.
CHECKPOINT_DAYS = (7, 30, 90)
# Exit-log codes -> the survival block's exit kinds. R (back to Received)
# is censoring, not an exit; see the module docstring.
EXIT_CODES = {"A": "analyzed", "D": "deferred", "O": "other"}
CENSOR_CODES = {"R": "requeued"}

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
    {...}, "queue_exits": [(since, wait_days, code)...], "resweep": bool,
    "date": today}``. ``queue_exits`` lists every timed queue episode
    (Awaiting/Undergoing, since-date known) that ended between the two
    snapshots, with the exit-log code of where it went (module
    docstring); :func:`attach_tracking` decides whether the log is
    running. ``status_since`` is the map to persist on
    the new state: carried forward for unchanged statuses and for hops
    between the two ``_PRE_ANALYZED`` statuses (one queue episode, one
    clock), set to ``today`` for every other observed change, absent
    (unknown) everywhere else.

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
    queue_exits: list[tuple[str, int, str]] = []

    for cve_id, status in new_statuses.items():
        prev = prev_statuses.get(cve_id)
        if prev == status:
            carried = prev_since.get(cve_id)
            if isinstance(carried, str):
                status_since[cve_id] = carried
            continue
        # observed change (or first appearance): the one honest moment to
        # stamp a since-date — except inside the queue episode. An
        # Awaiting↔Undergoing hop is the same wait continuing, so the
        # since-date of the episode's first sighting is carried forward
        # (when known; an unknown one is stamped today, still a lower
        # bound). Everything else restarts the clock.
        carried = prev_since.get(cve_id)
        if prev in _PRE_ANALYZED and status in _PRE_ANALYZED \
                and isinstance(carried, str):
            status_since[cve_id] = carried
        else:
            status_since[cve_id] = today
        if prev in _PRE_ANALYZED and status not in _PRE_ANALYZED:
            # A timed queue episode ended: log where it went, for the
            # survival curve. Untimed episodes (since-date unknown) cannot
            # be placed on the curve's day axis and are left out.
            since = _parse_date(carried) if isinstance(carried, str) else None
            if since is not None and today_date is not None \
                    and since <= today_date:
                code = ("A" if status == "Analyzed"
                        else "D" if status == "Deferred"
                        else "R" if status == "Received" else "O")
                queue_exits.append((carried, (today_date - since).days, code))
        if status == "Received":
            counts["received_new"] += 1
        elif status == "Awaiting Analysis":
            counts["entered_awaiting"] += 1
        elif status == "Analyzed" and prev in QUEUE_STATUSES:
            # Symmetric with Deferred: any live-queue status (Received
            # included, as on the decay chart) leaving for Analyzed is an
            # exit. Only waits that began awaiting analysis are timed — the
            # clock the stat note describes; a Received -> Analyzed hop
            # between two snapshots has no awaiting sighting to time from.
            # (Rows before 2026-09-23 counted exits from Awaiting /
            # Undergoing only; committed rows are not rewritten.)
            counts["analyzed_from_awaiting"] += 1
            since = _parse_date(prev_since.get(cve_id, ""))
            if prev in _PRE_ANALYZED and since is not None \
                    and today_date is not None and since <= today_date:
                durations.append((today_date - since).days)
        elif status == "Deferred" and prev in QUEUE_STATUSES:
            counts["deferred_from_awaiting"] += 1
        elif status == "Modified" and prev is not None:
            counts["modified_re"] += 1

    resweep = (new_state.get("last_full_sync")
               != prev_state.get("last_full_sync"))
    return {"counts": counts, "durations": durations,
            "status_since": status_since, "queue_exits": queue_exits,
            "resweep": bool(resweep), "date": today}


def attach_tracking(new_state: dict, prev_state: dict | None,
                    transitions: dict | None) -> list[int]:
    """Attach the tracking keys to a freshly synced state (which
    ``fetch_nvd`` returns bare) and return the accumulated durations.

    With no transitions (no previous state) the new state carries no
    tracking keys — since-dates are never bulk-initialized — and the
    accumulated durations are whatever the previous state had (nothing).

    The exit log (module docstring) is carried and extended here: a
    previous state without a readable ``queue_log_start`` starts the log
    at this run's date and logs nothing tonight (the episodes open in
    tonight's snapshot are where the log starts watching); otherwise
    tonight's ended episodes are appended with their entry age.
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

    today = transitions.get("date")
    log_start = _parse_date((prev_state or {}).get("queue_log_start"))
    if log_start is None:
        if _parse_date(today) is not None:
            new_state["queue_log_start"] = today
            new_state["queue_exits"] = []
        return accumulated
    log = _clean_exit_log((prev_state or {}).get("queue_exits"))
    for since, wait, code in transitions.get("queue_exits", ()):
        since_date = _parse_date(since)
        if since_date is None:
            continue
        entry = max(0, (log_start - since_date).days)
        # wait <= entry: the episode ended no later than the log's first
        # snapshot (a same-date re-run), so the log never watched it.
        if wait > entry:
            log.append([wait, entry, code])
    new_state["queue_log_start"] = log_start.isoformat()
    new_state["queue_exits"] = log
    return accumulated


def _clean_exit_log(raw) -> list[list]:
    """The persisted exit log, with any malformed entry dropped (the state
    is a cache; a corrupt row must not take the curve down with it)."""
    if not isinstance(raw, list):
        return []
    clean = []
    for item in raw:
        if not (isinstance(item, list) and len(item) == 3):
            continue
        wait, entry, code = item
        if not all(isinstance(v, int) and not isinstance(v, bool)
                   for v in (wait, entry)):
            continue
        if entry < 0 or wait <= entry:
            continue
        if code not in EXIT_CODES and code not in CENSOR_CODES:
            continue
        clean.append([wait, entry, code])
    return clean


# ------------------------------------------------------- queue survival --

def kaplan_meier(observations, *, min_at_risk: int = 1) -> dict:
    """Kaplan–Meier survival with delayed entry, on whole days.

    ``observations`` yields ``(entry, time, event)``: the subject is known
    to be in the queue at age ``entry`` (when observation began), and at
    age ``time`` it either left (``event`` true) or was last seen still in
    (censored). Ages are whole days with ``0 <= entry < time``; anything
    else is skipped. A subject is at risk at day ``u`` when ``entry < u
    <= time``, so a censored subject counts at its own last day, and a
    subject picked up late (delayed entry) counts only from its entry age
    on.

    Returns ``{"steps": [(day, at_risk, events, survival)...],
    "horizon": int, "at_risk": [n(0)..n(horizon)]}``. ``steps`` holds the
    days with at least one event, up to the horizon; ``horizon`` is the
    last day before the first day whose risk set falls below
    ``min_at_risk`` (0 when day 1 already does; the curve is then empty).
    """
    entered: dict[int, int] = {}
    left: dict[int, int] = {}
    events: dict[int, int] = {}
    last = 0
    for entry, time, event in observations:
        if not (isinstance(entry, int) and isinstance(time, int)) \
                or entry < 0 or time <= entry:
            continue
        entered[entry] = entered.get(entry, 0) + 1
        left[time] = left.get(time, 0) + 1
        if event:
            events[time] = events.get(time, 0) + 1
        last = max(last, time)

    at_risk = [0]
    steps = []
    survival = 1.0
    in_count = out_count = 0
    horizon = 0
    for day in range(1, last + 1):
        in_count += entered.get(day - 1, 0)   # entry <= day - 1
        out_count += left.get(day - 1, 0)     # time  <= day - 1
        n = in_count - out_count
        if n < max(1, min_at_risk):
            break
        at_risk.append(n)
        d = events.get(day, 0)
        if d:
            survival *= 1.0 - d / n
            steps.append((day, n, d, survival))
        horizon = day
    return {"steps": steps, "horizon": horizon, "at_risk": at_risk}


def build_queue_survival(state: dict | None, today: str, *,
                         min_exits: int = MIN_KNOWN_DURATIONS,
                         min_log_days: int = MIN_LOG_DAYS,
                         min_at_risk: int = MIN_AT_RISK) -> dict:
    """The ``queue_survival`` block of nvd_throughput.json, from a synced
    state carrying the tracking keys (docs/data-contracts.md).

    Subjects are timed queue episodes the exit log has watched: the
    logged ends (exits as events, returns to Received as censored) plus
    every episode still open tonight, censored at its current wait. An
    episode first seen before the log started enters at its age on the
    start date (delayed entry), so the curve never counts days the log did
    not watch. An empty or young record is legal: ``ready`` stays false
    until the log is ``min_log_days`` old with ``min_exits`` exits, and
    the curve is empty until something has left the queue.
    """
    state = state if isinstance(state, dict) else {}
    today_date = _parse_date(today)
    log_start = _parse_date(state.get("queue_log_start"))
    block = {
        "log_start": log_start.isoformat() if log_start else None,
        "log_days": 0,
        "min_exits": min_exits,
        "min_log_days": min_log_days,
        "min_at_risk": min_at_risk,
        "ready": False,
        "exits": {kind: 0 for kind in EXIT_CODES.values()},
        "censored": {"waiting": 0, "requeued": 0},
        "horizon_days": 0,
        "median_days": None,
        "checkpoints": [],
        "curve": [],
    }
    if log_start is None or today_date is None or today_date < log_start:
        return block
    block["log_days"] = (today_date - log_start).days

    observations: list[tuple[int, int, bool]] = []
    for wait, entry, code in _clean_exit_log(state.get("queue_exits")):
        if code in EXIT_CODES:
            block["exits"][EXIT_CODES[code]] += 1
            observations.append((entry, wait, True))
        else:
            block["censored"][CENSOR_CODES[code]] += 1
            observations.append((entry, wait, False))

    statuses = state.get("statuses")
    since_map = state.get("status_since")
    if isinstance(statuses, dict) and isinstance(since_map, dict):
        for cve_id, status in statuses.items():
            if status not in _PRE_ANALYZED:
                continue
            since = _parse_date(since_map.get(cve_id))
            if since is None or since > today_date:
                continue
            wait = (today_date - since).days
            entry = max(0, (log_start - since).days)
            if wait > entry:  # watched for at least one night
                block["censored"]["waiting"] += 1
                observations.append((entry, wait, False))

    km = kaplan_meier(observations, min_at_risk=min_at_risk)
    horizon = km["horizon"]
    at_risk = km["at_risk"]
    curve = [{"day": day, "pct_waiting": round(100.0 * s, 1),
              "at_risk": n, "exits": d}
             for day, n, d, s in km["steps"]]
    if curve and curve[-1]["day"] < horizon:
        # Carry the last step to the horizon so the chart shows how far
        # the record reaches, not just where the last exit fell.
        curve.append({"day": horizon,
                      "pct_waiting": curve[-1]["pct_waiting"],
                      "at_risk": at_risk[horizon], "exits": 0})

    def survival_at(day: int) -> float:
        s = 1.0
        for step_day, _n, _d, step_s in km["steps"]:
            if step_day > day:
                break
            s = step_s
        return s

    n_exits = sum(block["exits"].values())
    block["horizon_days"] = horizon if curve else 0
    block["curve"] = curve
    if curve:
        block["checkpoints"] = [
            {"day": day, "pct_waiting": round(100.0 * survival_at(day), 1),
             "at_risk": at_risk[day]}
            for day in CHECKPOINT_DAYS if day <= horizon]
        block["median_days"] = next(
            (day for day, _n, _d, s in km["steps"] if s <= 0.5), None)
    block["ready"] = bool(curve) and n_exits >= min_exits \
        and block["log_days"] >= min_log_days
    return block


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
    """Pure merge, no I/O: insert ``row`` sorted ascending by date.

    Unlike ``nvd_backlog.csv`` (absolute snapshots, where the last run per
    date rightly wins), every throughput row is a DIFF between two states.
    A second successful run on the same date diffs against the state the
    first run already advanced, so it sees only the flow since that run —
    replacing the earlier row would erase the transitions it recorded (it
    did, on 2026-08-30: 617/584/336/256 became 2/0/0/0 after a manual
    re-dispatch). Same-date rows therefore SUM their four flow counts; the
    cumulative fields (median, n_known) and the resweep flag come from the
    newer run, which by construction has seen everything the older one did.
    """
    merged = [r for r in rows if r["date"] != row["date"]]
    new = dict(row)
    for prev in rows:
        if prev["date"] == row["date"]:
            for col in _COUNT_COLUMNS:
                new[col] = prev[col] + row[col]
            new["resweep"] = int(prev["resweep"] or row["resweep"])
    merged.append(new)
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


def build_nvd_throughput(history_rows: list[dict], generated_at: str,
                         survival: dict | None = None) -> dict:
    """nvd_throughput.json: the daily flow series plus the cumulative
    queue-days stat (docs/data-contracts.md). An empty history is legal —
    the record starts at first deploy and this object says so honestly.
    ``survival`` (:func:`build_queue_survival`) is published as
    ``queue_survival`` when given; editions built before it lack the key.

    ``after_resweep`` is derived here, not stored: it marks the row that
    follows a ``resweep`` row, which is where the catch-up lump lands
    (module docstring). The first row can never be one."""
    latest = history_rows[-1] if history_rows else None
    history = []
    previous_resweep = False
    for r in history_rows:
        resweep = bool(r["resweep"])
        history.append({"date": r["date"],
                        "received_new": int(r["received_new"]),
                        "entered_awaiting": int(r["entered_awaiting"]),
                        "analyzed_from_awaiting":
                            int(r["analyzed_from_awaiting"]),
                        "deferred_from_awaiting":
                            int(r["deferred_from_awaiting"]),
                        "resweep": resweep,
                        "after_resweep": previous_resweep})
        previous_resweep = resweep
    obj = {
        "generated_at": generated_at,
        "min_known_duration": MIN_KNOWN_DURATIONS,
        "queue": {
            "median_days": latest["median_queue_days"] if latest else None,
            "n_known_duration": latest["n_known_duration"] if latest else 0,
        },
        "history": history,
    }
    if survival is not None:
        obj["queue_survival"] = survival
    return obj
