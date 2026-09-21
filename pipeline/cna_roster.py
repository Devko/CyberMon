"""CNA Roster History: the CVE federation's growth and churn (cna_roster.json).

The CVE Program publishes its current roster of CNAs and roots and no
accreditation dates. The roster file carries no changelog of its own; it
lives in the CVEProject/cve-website git repository, whose commit history
is the upstream record of every edit and importable roster history for
anyone who replays it. This stage keeps a normalized nightly ledger
instead, starting at CyberMon's first snapshot. Every night it
fingerprints today's roster (from ``fetch_cna_roster``), diffs it against
the committed state, appends events to an append-only committed CSV, and
emits three sections:

* ``roster_size`` — roster size over time, from the committed size history.
  It starts as a single point (tonight's count) and deepens one nightly
  snapshot at a time; ``net_change`` stays null until the record holds at
  least ``min_n`` observations (the thin-start honesty rule).
* ``roster_flux`` — onboardings vs departures (and scope changes) per month,
  from the event log. Empty at launch: **onboarding = first observed in our
  snapshots**, because no accreditation date is published, so the very first
  run logs ZERO events (there is no prior snapshot to diff against).
* ``roster_mix`` — the CURRENT roster composition (by type, top-level root,
  reporting root, country, and — since 2026-09-20 — by program role, with
  the count of orgs holding an assigning role, CNA or CNA-LR, reported
  beside the total of orgs listed). Fully populated from tonight's fetch
  on day one — the one section that is real immediately.

Event taxonomy (``CHANGE_TYPES``):

* ``onboarded`` — a ``shortName`` observed for the first time. First-observed,
  not accredited-on: the date is when CyberMon first saw the org, and the
  methodology says so.
* ``departed`` — a ``shortName`` present last snapshot, gone this one.
* ``renamed`` — a departed ``shortName`` and an onboarded one that are the
  same organization: their ``cnaID`` matches, that ``cnaID`` is unique in
  both snapshots (the roster occasionally shares one between orgs, so a
  shared id proves nothing), and the identity agrees on at least one more
  axis — organization name, scope text, or country plus type. One event
  (``from_short_name`` -> ``short_name``) replaces the departed/onboarded
  pair. Fingerprints stored before 2026-09-20 carry no ``cnaID``, so a
  rename straddling that first night still logs as the pair.
* ``scope_changed`` — an org present in both whose stated ``scope`` text
  changed (compared by a short stable hash, like the KEV changelog's
  text fields; the event records that the scope moved, not the prose).

Committed history (both under ``site/data/history/``, the nvd_backlog.csv
discipline — an original dataset this project accumulates and does not
regenerate; the raw edits could be replayed from the roster file's git
history, this normalized ledger exists nowhere else):

* ``cna_roster.csv`` — the append-only event log (columns
  ``observed_date,short_name,change_type,org,country,type,from_short_name``;
  the last column, added 2026-09-20, is filled for ``renamed`` rows only
  and read as empty from files written before it existed).
* ``cna_roster_state.json`` — the compact state: the per-org fingerprint
  (org name, country, type label, scope hash, and since 2026-09-20 the
  ``cnaID``) as of the last snapshot, the
  ``size_history`` series (one ``[date, size]`` per observed date), and the
  baseline/last-observed dates.

Write discipline: this module never touches disk itself. It returns the
merged CSV rows and the advanced state as pending writes; ``__main__.run()``
persists them (via :func:`persist`) only after every output validates — the
KEV-changelog pattern, applied to a file that is just as irreplaceable. A
fresh catalog that lost more than half the roster is refused as a broken
fetch rather than mass-logging departures.
"""
from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .fetch_cna_roster import ASSIGNING_ROLES, RosterOrg, RosterSnapshot  # noqa: F401

FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures"

STATE_VERSION = 1
STATE_FILENAME = "cna_roster_state.json"
CSV_FILENAME = "cna_roster.csv"

CSV_COLUMNS = ("observed_date", "short_name", "change_type",
               "org", "country", "type", "from_short_name")
# Columns a committed log may lack (added later); read as "" when absent.
_OPTIONAL_CSV_COLUMNS = {"from_short_name": ""}
CHANGE_TYPES = ("onboarded", "departed", "renamed", "scope_changed")

DEFAULT_MIN_N = 2  # roster-size observations before a net-change is reported

# A fresh roster that lost more than half of the known orgs is a broken
# fetch, not churn — mass-logging departures from it would poison the log.
_SHRINK_GUARD = 0.5
_SHRINK_MIN_PREV = 50


# ------------------------------------------------------------- fingerprints

def scope_hash(scope: str) -> str:
    """Short stable fingerprint of an org's scope text: sha256 of the
    whitespace-normalized string, first 12 hex chars. A whitespace-only
    reflow is not a scope change (the KEV-changelog text-field rule)."""
    normalized = " ".join((scope or "").split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]


def fingerprint(org: RosterOrg) -> dict:
    """One compact state record for an org: enough to render it after it
    departs (name, country, type label) plus the scope hash used to detect
    scope changes and the ``cnaID`` used to recognise a rename."""
    return {"org": org.org_name, "country": org.country,
            "type": org.type_label, "scope": scope_hash(org.scope),
            "cna_id": org.cna_id}


def fingerprint_roster(snapshot: RosterSnapshot) -> dict[str, dict]:
    """shortName -> fingerprint for a whole roster snapshot."""
    return {o.short_name: fingerprint(o) for o in snapshot.orgs}


# ------------------------------------------------------------------- diffing

def _norm_name(name: str) -> str:
    return " ".join((name or "").split()).casefold()


def _identity_agrees(prev_fp: dict, curr_fp: dict) -> bool:
    """Whether two fingerprints look like one organization beyond the
    shared ``cnaID``: same organization name, same scope text (hash), or
    same country and type label. One agreeing axis is enough — a rename
    usually changes the display name too (The Qt Company -> Qt Group),
    while country, type and scope stay put."""
    if _norm_name(prev_fp.get("org", "")) == _norm_name(curr_fp.get("org", "")):
        return True
    if prev_fp.get("scope") and prev_fp.get("scope") == curr_fp.get("scope"):
        return True
    return (prev_fp.get("country", "") == curr_fp.get("country", "")
            and prev_fp.get("type", "") == curr_fp.get("type", ""))


def rename_pairs(prev: dict[str, dict], curr: dict[str, dict]
                 ) -> list[tuple[str, str]]:
    """``(old_short, new_short)`` pairs among the shortNames that left and
    arrived between ``prev`` and ``curr`` that are the same organization
    under a new key. The rule (all three must hold): the ``cnaID`` matches
    and is non-empty; that ``cnaID`` is unique within ``prev`` AND within
    ``curr`` (the roster occasionally shares an id between orgs — a shared
    id identifies nobody); and :func:`_identity_agrees`. Fingerprints
    without a ``cna_id`` (state written before 2026-09-20) never pair.
    Sorted by the new shortName, deterministic."""
    departed = set(prev) - set(curr)
    onboarded = set(curr) - set(prev)
    if not departed or not onboarded:
        return []
    prev_ids = Counter(fp.get("cna_id") for fp in prev.values())
    curr_ids = Counter(fp.get("cna_id") for fp in curr.values())
    by_id = {curr[s].get("cna_id"): s for s in onboarded
             if curr[s].get("cna_id")}
    pairs: list[tuple[str, str]] = []
    for old in departed:
        cna_id = prev[old].get("cna_id")
        new = by_id.get(cna_id) if cna_id else None
        if new is None or prev_ids[cna_id] != 1 or curr_ids[cna_id] != 1:
            continue
        if _identity_agrees(prev[old], curr[new]):
            pairs.append((old, new))
    pairs.sort(key=lambda p: p[1])
    return pairs


def diff_orgs(prev: dict[str, dict], snapshot: RosterSnapshot,
              curr: dict[str, dict], observed_date: str) -> list[dict]:
    """Events turning ``prev`` into ``curr``, dated ``observed_date``.

    Deterministic order: onboardings, departures, renames, then scope
    changes, each block sorted by shortName (renames by the new one).
    Re-running the same diff yields the same rows. Onboarded / renamed /
    scope-changed rows carry today's org profile; departed rows carry the
    profile from the state (the org is gone from today's roster). A
    rename (see :func:`rename_pairs`) is one row, with the previous
    shortName in ``from_short_name``, in place of a departed/onboarded
    pair; a renamed org whose scope also changed logs the scope change
    too, under the new shortName.
    """
    by_short = {o.short_name: o for o in snapshot.orgs}
    events: list[dict] = []

    def _row(short: str, change: str, org: str, country: str,
             type_label: str, from_short: str = "") -> dict:
        return {"observed_date": observed_date, "short_name": short,
                "change_type": change, "org": org, "country": country,
                "type": type_label, "from_short_name": from_short}

    renames = rename_pairs(prev, curr)
    renamed_old = {old for old, _new in renames}
    renamed_new = {new for _old, new in renames}

    for short in sorted(set(curr) - set(prev) - renamed_new):
        o = by_short[short]
        events.append(_row(short, "onboarded", o.org_name, o.country,
                           o.type_label))
    for short in sorted(set(prev) - set(curr) - renamed_old):
        fp = prev[short]
        events.append(_row(short, "departed", fp.get("org", short),
                           fp.get("country", ""), fp.get("type", "")))
    for old, new in renames:
        o = by_short[new]
        events.append(_row(new, "renamed", o.org_name, o.country,
                           o.type_label, from_short=old))
        if prev[old].get("scope", "") != curr[new].get("scope", ""):
            events.append(_row(new, "scope_changed", o.org_name, o.country,
                               o.type_label))
    for short in sorted(set(prev) & set(curr)):
        if prev[short].get("scope", "") != curr[short].get("scope", ""):
            o = by_short[short]
            events.append(_row(short, "scope_changed", o.org_name, o.country,
                               o.type_label))
    return events


# --------------------------------------------------------------------- state

def new_state(baseline_date: str) -> dict:
    return {"version": STATE_VERSION, "baseline_date": baseline_date,
            "last_observed": baseline_date, "size_history": [], "orgs": {}}


def advance_state(state: dict, curr: dict[str, dict], observed_date: str
                  ) -> None:
    """Advance ``state`` to today's snapshot (in place): store the fresh
    fingerprints, stamp the observed date, and record today's size in the
    ``size_history`` series (last run of a given date wins — a same-day
    re-run replaces the row rather than appending a duplicate)."""
    state["orgs"] = dict(curr)
    state["last_observed"] = observed_date
    history = state["size_history"]
    size = len(curr)
    if history and history[-1][0] == observed_date:
        history[-1][1] = size
    else:
        history.append([observed_date, size])


def _shrink_guard(prev_n: int, curr_n: int) -> bool:
    """True when a snapshot lost enough of the roster to look like a broken
    fetch rather than churn."""
    return prev_n >= _SHRINK_MIN_PREV and curr_n < prev_n * _SHRINK_GUARD


# --------------------------------------------------------------------- state I/O

def state_path(out_dir: Path) -> Path:
    return out_dir / "history" / STATE_FILENAME


def csv_path(out_dir: Path) -> Path:
    return out_dir / "history" / CSV_FILENAME


def load_state(out_dir: Path, log: Callable[[str], None] = print) -> dict | None:
    """The committed roster state, or None on the first ever run. Malformed
    state fails loudly — it is half of the historical record, and silently
    rebaselining would re-onboard the whole roster on the next diff."""
    path = state_path(out_dir)
    if not path.exists():
        return None
    state = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION \
            or not isinstance(state.get("orgs"), dict) \
            or not isinstance(state.get("size_history"), list):
        raise ValueError(f"{path}: unrecognized cna-roster state")
    return state


def write_state(path: Path, state: dict) -> None:
    """Atomic tmp+replace (the kev_state.json pattern)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True) + "\n",
                   encoding="utf-8")
    tmp.replace(path)


def read_events(path: Path) -> list[dict]:
    """Read the event log, oldest first (file order — append-only, appended
    chronologically). Missing file -> empty. Malformed rows fail loudly: this
    file is the irreplaceable historical record, and silent data loss would
    be worse than a crash."""
    if not path.exists():
        return []
    rows: list[dict] = []
    with path.open("r", newline="", encoding="utf-8") as f:
        for lineno, raw in enumerate(csv.DictReader(f), start=2):
            try:
                row = {col: (raw[col] if col not in _OPTIONAL_CSV_COLUMNS
                             else raw.get(col) or _OPTIONAL_CSV_COLUMNS[col])
                       for col in CSV_COLUMNS}
            except KeyError as exc:
                raise ValueError(f"{path}:{lineno}: malformed roster row "
                                 f"{raw!r}") from exc
            if None in row.values() or \
                    row["change_type"] not in CHANGE_TYPES or \
                    not row["short_name"] or not row["observed_date"]:
                raise ValueError(f"{path}:{lineno}: malformed roster row "
                                 f"{raw!r}")
            rows.append(row)
    return rows


def write_events(path: Path, rows: list[dict]) -> None:
    """Rewrite the CSV atomically (temp file, then ``replace``) — an
    interrupted run must leave either the old file or the new one, never a
    truncation (the nvd_backlog.csv pattern)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows({**_OPTIONAL_CSV_COLUMNS, **row} for row in rows)
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
    log(f"  cna-roster: {len(pending.events)} event(s) in "
        f"{csv_path(out_dir)}; state covers {len(pending.state['orgs'])} orgs")


# ----------------------------------------------------------------------- metrics

def _month(day: str) -> str:
    return day[:7]


def _month_range(first: str, last: str) -> list[str]:
    """Contiguous YYYY-MM labels, first..last inclusive — gap months chart at
    zero, the axis never silently skips time."""
    months = []
    y, m = int(first[:4]), int(first[5:7])
    while True:
        months.append(f"{y:04d}-{m:02d}")
        if f"{y:04d}-{m:02d}" >= last[:7]:
            return months
        m += 1
        if m == 13:
            y, m = y + 1, 1


def _breakdown(counter: Counter) -> list[dict]:
    """A ``[{label, n}]`` list sorted by count descending, ties by label
    ascending — the uniform shape every roster_mix dimension uses."""
    items = [{"label": label, "n": n} for label, n in counter.items()]
    items.sort(key=lambda d: (-d["n"], d["label"]))
    return items


def build_roster_mix(snapshot: RosterSnapshot) -> tuple[dict, dict]:
    """(roster_mix section, headline block) from today's snapshot — the one
    section that is real from day one. ``by_type`` and ``by_role`` are
    flattened tallies (an org counts once per type / role it holds, so
    they may sum above the total); ``by_tlr`` / ``by_root`` /
    ``by_country`` are clean partitions that sum to the total. ``total``
    is every org LISTED; ``headline.assigning_n`` is how many of them hold
    an assigning role (CNA or CNA-LR) — roots, ADPs and the secretariat
    sit on the same list without one."""
    orgs = snapshot.orgs
    total = len(orgs)

    type_counts: Counter = Counter()
    for o in orgs:
        for t in (o.types or ("N/A",)):
            type_counts[t] += 1
    by_type = _breakdown(type_counts)
    role_counts: Counter = Counter()
    for o in orgs:
        for r in (o.roles or ("N/A",)):
            role_counts[r] += 1
    by_role = _breakdown(role_counts)
    assigning_n = sum(1 for o in orgs if o.is_assigner)
    by_tlr = _breakdown(Counter(o.tlr for o in orgs))
    by_root = _breakdown(Counter(o.root for o in orgs))
    by_country = _breakdown(Counter(o.country for o in orgs))

    tlr_counts = Counter(o.tlr for o in orgs)
    mitre_n = sum(n for k, n in tlr_counts.items() if k.lower() == "mitre")
    cisa_n = sum(n for k, n in tlr_counts.items() if k.lower() == "cisa")
    root_count = sum(1 for k in by_root if k["label"].lower() != "n/a")

    mix = {"total": total, "by_type": by_type, "by_role": by_role,
           "by_tlr": by_tlr, "by_root": by_root, "by_country": by_country}
    headline = {
        "roster_total": total,
        "top_type": by_type[0]["label"],
        "top_type_n": by_type[0]["n"],
        # real countries only: the "n/a" bucket (orgs listing none) stays
        # visible in by_country but is not a country
        "country_count": len([k for k in by_country
                              if k["label"].lower() != "n/a"]),
        "root_count": root_count,
        "mitre_n": mitre_n,
        "cisa_n": cisa_n,
        # orgs holding an assigning role (CNA / CNA-LR), out of `total` listed
        "assigning_n": assigning_n,
    }
    return mix, headline


def build_cna_roster(state: dict, events: list[dict], snapshot: RosterSnapshot,
                     generated_at: str, *, min_n: int = DEFAULT_MIN_N) -> dict:
    """Assemble cna_roster.json from the advanced state, the full event log,
    and today's snapshot."""
    # ---- roster_size: the committed size history -----------------------------
    series = [{"date": d, "size": n} for d, n in state["size_history"]]
    net_change = None
    if len(series) >= min_n:
        net_change = series[-1]["size"] - series[0]["size"]
    roster_size = {
        "min_n": min_n,
        "current": series[-1]["size"] if series else 0,
        "net_change": net_change,
        "first_observed": series[0]["date"] if series else None,
        "series": series,
    }

    # ---- roster_flux: onboardings vs departures per month --------------------
    by_month: dict[str, Counter] = {}
    for e in events:
        by_month.setdefault(_month(e["observed_date"]),
                            Counter())[e["change_type"]] += 1
    months = []
    if by_month:
        for label in _month_range(min(by_month), max(by_month)):
            counts = by_month.get(label, Counter())
            months.append({"month": label,
                           **{t: counts.get(t, 0) for t in CHANGE_TYPES}})
    totals = {t: sum(1 for e in events if e["change_type"] == t)
              for t in CHANGE_TYPES}
    roster_flux = {
        "months": months,
        "totals": totals,
        "events_total": len(events),
        "first_observed": min((e["observed_date"] for e in events),
                              default=None),
    }

    # ---- roster_mix: today's composition (real from day one) -----------------
    roster_mix, headline = build_roster_mix(snapshot)

    return {
        "generated_at": generated_at,
        "roster_size": roster_size,
        "roster_flux": roster_flux,
        "roster_mix": roster_mix,
        "headline": headline,
    }


def _source(fetched_at: str, obj: dict) -> dict:
    return {"fetched_at": fetched_at,
            "org_count": obj["roster_mix"]["total"],
            "events_total": obj["roster_flux"]["events_total"]}


# --------------------------------------------------------------------- the stage

def run_stage(out_dir: Path, generated_at: str, *, snapshot: RosterSnapshot,
              offline_fixtures: bool, min_n: int | None = None,
              log: Callable[[str], None] = print
              ) -> tuple[dict, dict, PendingWrites]:
    """(cna_roster.json object, meta.sources.roster, pending writes for
    run() to persist after validation).

    * ``offline_fixtures`` — when no committed state exists yet, the first
      run seeds its "prior snapshot" from fixtures/cna_roster_state.json
      instead of baselining, so the fixture diff produces a couple of
      onboarded/departed/scope-changed events; a second run then exercises
      the idempotent path. No network either way.
    * live — diff the committed state against the fresh roster, append events
      dated today. First ever run = baseline: the state is written, size
      history gets its first point, and ZERO events are logged (there is no
      prior snapshot to diff — the churn record starts now).
    """
    if min_n is None:
        min_n = DEFAULT_MIN_N
    today = generated_at[:10]

    state = load_state(out_dir, log=log)
    events = read_events(csv_path(out_dir))

    if offline_fixtures and state is None:
        state = json.loads((FIXTURES_DIR / STATE_FILENAME)
                           .read_text(encoding="utf-8"))
        log(f"  cna-roster: seeded prior state from fixtures "
            f"({len(state['orgs'])} orgs)")

    curr = fingerprint_roster(snapshot)
    if state is None:
        state = new_state(today)
        advance_state(state, curr, today)
        log(f"  cna-roster: baseline run — state written for {len(curr)} "
            f"orgs, zero events (the churn record starts now)")
    else:
        if _shrink_guard(len(state["orgs"]), len(curr)):
            raise RuntimeError(
                f"cna-roster: fresh roster has {len(curr)} orgs vs "
                f"{len(state['orgs'])} in state — refusing to log a mass "
                f"departure from what looks like a broken fetch")
        fresh = diff_orgs(state["orgs"], snapshot, curr, today)
        events.extend(fresh)
        advance_state(state, curr, today)
        log(f"  cna-roster: {len(fresh)} event(s) observed "
            f"({len(events)} total on record)")

    obj = build_cna_roster(state, events, snapshot, generated_at, min_n=min_n)
    return obj, _source(generated_at, obj), PendingWrites(state=state,
                                                          events=events)
