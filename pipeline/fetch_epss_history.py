"""Historical day-before EPSS scores for KEV entries (FIRST.org API).

The EPSS Report Card module grades the industry's only public exploitation
forecast against the outcome it exists to predict: for every CVE that CISA
later confirmed exploited (a KEV listing), what did EPSS say **the day
before** the listing? Historical scores never change, so each
``(cve_id, date_added)`` pair is looked up **exactly once** and kept in a
sync-state file (``.cache/epss_report_state.json`` — the attack-state
pattern):

* **Normal night** — only KEV entries missing from the state are looked up
  (a few per week; grouped by date, that is 1–2 API requests).
* **Backfill** — the one-time historical pull (~440 distinct ``dateAdded``
  dates since November 2021) is deliberately batch-capped
  (``--epss-backfill-batch``, default 30 lookups/run) so CI can never
  accidentally do the whole pull; the integrator runs it once with a large
  batch. Partial state is saved after every date, so an interrupted
  backfill never loses progress.
* **Lost cache** — the state is reconstructed losslessly from the
  previously published ``site/data/epss_report.json``: the output's
  ``entries[]`` are exactly the state's per-entry records plus the key
  fields (:func:`reconstruct_state`; the output format is designed for
  this round-trip). Only pairs absent from both are ever re-fetched.

Source behavior (verified live 2026-07-10, documented here because it
decided the architecture):

* ``GET https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B&date=YYYY-MM-DD``
  returns each listed CVE's score **as of that date** — one row per CVE
  that had a score that day, with ``epss``, ``percentile`` and ``date``
  as strings. CVEs unpublished/unscored on that date simply return no row.
* The request is GET-only and capped by URL length (~2 KB: 130 CVEs
  worked, 140 returned an empty envelope) — :data:`MAX_CVES_PER_REQUEST`
  stays safely at 100, and ``limit`` is raised above the default 100 so a
  full chunk can never be silently paginated.
* Dates before EPSS existed (first daily scores: 2021-04-14) return
  HTTP 422 "No records available" — treated as an authoritative empty
  answer, like a 200 with no rows.
* The API does NOT return the model version. Model eras are therefore
  encoded here (:data:`MODEL_ERAS`), verified empirically from the daily
  CSV headers at epss.cyentia.com (the transition-day files were checked
  one by one): v1 (headerless CSVs) through 2022-02-03; v2
  (``v2022.01.01``) from 2022-02-04; v3 (``v2023.03.01``) from
  2023-03-07; v4 (``v2025.03.14``) from 2025-03-17; v5 (``v2026.06.15``)
  from 2026-06-15. When FIRST ships a model this table does not know, the
  nightly's current-CSV ``model_version`` is the tripwire — see
  :func:`known_model_version`.

The bulk daily CSVs were evaluated and rejected as the primary source:
per KEV date only a handful of CVEs are needed (a whole ~400 KB CSV per
date is waste), pre-2022-02-04 files carry no model-version header, and
the earliest (2021-04-14) lacks even the percentile column.

State entries record a **fact per (cve_id, date_added)**, never a maybe:

* scored — ``{score_date, epss, percentile, model, reason: None}``
  (probability/percentile rounded to 5 decimals at fetch time; the state
  and the published file carry identical values, which is what makes the
  round-trip lossless);
* no score existed that day — ``epss``/``percentile``/``model`` are None
  and ``reason`` says what is known at fetch time: ``"pre_epss"`` (the
  score date predates EPSS itself) or ``"no_score_for_date"`` (the API had
  no row — CVE unpublished, or simply unscored that day). The
  CVE-corpus-aware refinement (listed before publication vs. genuinely
  unscored) happens in ``epss_report_metrics``, not here.

A failed request (after retries) raises — the nightly treats a broken
stage as "deploy nothing" — but the state accumulated so far is saved
first, so no successful lookup is ever repeated.
"""
from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path
from typing import Callable

API_URL = "https://api.first.org/data/v1/epss"
USER_AGENT = "CyberMon/1.0 (+https://github.com/Devko/CyberMon)"
STATE_VERSION = 1
STATE_FILENAME = "epss_report_state.json"

# First day with published daily EPSS scores (epss_scores-2021-04-13.csv.gz
# is a 403; 2021-04-14 exists). KEV starts 2021-11-03, so in practice every
# needed score date falls inside EPSS coverage — the branch is kept because
# recording "pre-EPSS" as a miss would be a lie if it ever triggered.
EPSS_FIRST_DAY = "2021-04-14"

# (label, upstream model_version string, first score_date) — ascending.
# Verified from the daily CSV comment headers (see module docstring).
# v1-era CSVs carry no header; the label/version follow FIRST's own
# numbering (v4 = v2025.03.14 per first.org, v5 = v2026.06.15 per the
# EPSS SIG's June 2026 release notes).
MODEL_ERAS = [
    ("v1", "v1 (pre-header daily CSVs)", "2021-04-14"),
    ("v2", "v2022.01.01", "2022-02-04"),
    ("v3", "v2023.03.01", "2023-03-07"),
    ("v4", "v2025.03.14", "2025-03-17"),
    ("v5", "v2026.06.15", "2026-06-15"),
]
MODEL_LABELS = tuple(era[0] for era in MODEL_ERAS)

REASON_PRE_EPSS = "pre_epss"
REASON_NO_SCORE = "no_score_for_date"
REASONS = (REASON_PRE_EPSS, REASON_NO_SCORE)

# Requests are URL-length-bound (~2 KB); 100 CVE ids stay well under it.
# limit > chunk size so a full chunk can never be silently paginated.
MAX_CVES_PER_REQUEST = 100
_REQUEST_LIMIT = 200

_TIMEOUT = 60.0
_RETRY_STATUSES = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 3
# Courtesy pacing between API requests (the backfill makes ~450 of them).
REQUEST_SLEEP = 0.5


# ------------------------------------------------------------------ model eras

def model_label(score_date: str) -> str | None:
    """The model-era label ("v1".."v5") whose date range covers
    ``score_date``, or None before EPSS existed. The last era is
    open-ended: a score date past the table's knowledge gets the newest
    label (see :func:`known_model_version` for the tripwire)."""
    if score_date < EPSS_FIRST_DAY:
        return None
    label = MODEL_ERAS[0][0]
    for lbl, _version, start in MODEL_ERAS:
        if score_date >= start:
            label = lbl
    return label


def known_model_version(current: str) -> bool:
    """Whether the CURRENT feed's model_version string (from the nightly
    EPSS CSV header) is one this module's era table knows. False means
    FIRST shipped a new model and :data:`MODEL_ERAS` needs a new row —
    the caller logs a loud warning so freshly graded entries are not
    silently labeled with the previous era."""
    return any(current == version for _lbl, version, _start in MODEL_ERAS)


def model_eras_block() -> list[dict]:
    """The published ``model_eras`` metadata: label, upstream version
    string, and each era's inclusive score-date range (``to`` = day before
    the next era; None for the open-ended newest era)."""
    block = []
    for i, (label, version, start) in enumerate(MODEL_ERAS):
        if i + 1 < len(MODEL_ERAS):
            nxt = date.fromisoformat(MODEL_ERAS[i + 1][2])
            to = (nxt - timedelta(days=1)).isoformat()
        else:
            to = None
        block.append({"label": label, "model_version": version,
                      "from": start, "to": to})
    return block


# ------------------------------------------------------------------- key utils

def entry_key(cve_id: str, date_added: str) -> str:
    """State key for one KEV (cve_id, dateAdded) pair."""
    return f"{cve_id}|{date_added}"


def score_date_for(date_added: str) -> str:
    """The day before a KEV ``dateAdded`` — the score date this module
    grades. Raises ValueError on an unparseable date (the caller skips
    undated KEV entries before ever building a key)."""
    return (date.fromisoformat(date_added) - timedelta(days=1)).isoformat()


# ------------------------------------------------------------------- state I/O

def _state_path(cache_dir: Path) -> Path:
    return cache_dir / STATE_FILENAME


def load_state(cache_dir: Path,
               log: Callable[[str], None] = print) -> dict | None:
    """Cached EPSS-report sync state, or None when absent/unreadable (the
    sync then reconstructs from the published output, or backfills — the
    state is only ever a cache)."""
    path = _state_path(cache_dir)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log(f"warning: ignoring unreadable epss-report state {path}: {exc!r}")
        return None


def save_state(cache_dir: Path, state: dict) -> None:
    """Write the state atomically (temp file, then ``replace``) so an
    interrupted run leaves either the old file or the new one."""
    path = _state_path(cache_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, separators=(",", ":")),
                   encoding="utf-8")
    tmp.replace(path)


def _entry_from(obj: dict) -> dict:
    """One state entry from a mapping carrying the per-entry fact fields
    (a published ``entries[]`` element or a cached state value). Raises
    on any malformed field — callers decide how loudly to fail."""
    score_date = str(obj["score_date"])
    date.fromisoformat(score_date)  # fail loudly on a bad date
    epss, percentile = obj["epss"], obj["percentile"]
    model, reason = obj["model"], obj["reason"]
    if epss is None:
        if percentile is not None or model is not None:
            raise ValueError("null epss with non-null percentile/model")
        if reason not in REASONS:
            raise ValueError(f"null epss with reason {reason!r}")
    else:
        epss = float(epss)
        if not 0.0 <= epss <= 1.0:
            raise ValueError(f"epss {epss} outside [0, 1]")
        if percentile is not None:
            percentile = float(percentile)
            if not 0.0 <= percentile <= 1.0:
                raise ValueError(f"percentile {percentile} outside [0, 1]")
        if model not in MODEL_LABELS:
            raise ValueError(f"unknown model label {model!r}")
        if reason is not None:
            raise ValueError("scored entry with a non-null reason")
    return {"score_date": score_date, "epss": epss,
            "percentile": percentile, "model": model, "reason": reason}


def reconstruct_state(out_dir: Path,
                      log: Callable[[str], None] = print) -> dict | None:
    """Best-effort sync state rebuilt from a previously published
    ``out_dir/epss_report.json``, for when the cached state is lost (fresh
    CI cache, actions/cache eviction). The output's ``entries[]`` are
    exactly the state's per-entry records — the output format guarantees
    the round-trip — so a lost cache never re-triggers the historical
    backfill. None when the file is absent or unusable; the sync then
    backfills from the API, batch-capped, exactly as on the first run."""
    path = out_dir / "epss_report.json"
    if not path.exists():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        last_sync = str(obj["generated_at"])
        entries = {entry_key(str(e["cve"]), str(e["date_added"])):
                   _entry_from(e) for e in obj["entries"]}
    except (OSError, KeyError, TypeError, ValueError) as exc:
        log(f"warning: cannot reconstruct epss-report state from {path}: "
            f"{exc!r}")
        return None
    log("  epss-report: reconstructed sync state from published "
        f"epss_report.json ({len(entries)} entrie(s))")
    return {"version": STATE_VERSION, "last_sync": last_sync,
            "entries": entries}


def _pruned_entries(state: dict | None, wanted_keys: set[str],
                    log: Callable[[str], None]) -> dict[str, dict]:
    """Carry prior entries forward, keeping only pairs the current KEV
    catalog still lists (CISA occasionally withdraws entries; the catalog
    is authoritative) and dropping malformed entries (they will simply be
    re-fetched)."""
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
        if state:
            log("  epss-report: discarding unrecognized cached state")
        return {}
    kept: dict[str, dict] = {}
    dropped = 0
    for key, entry in (state.get("entries") or {}).items():
        if key not in wanted_keys:
            dropped += 1
            continue
        try:
            kept[key] = _entry_from(entry)
        except (KeyError, TypeError, ValueError):
            log(f"  epss-report: dropping malformed cached entry {key}")
    if dropped:
        log(f"  epss-report: dropped {dropped} cached entrie(s) no longer "
            f"in the KEV catalog")
    return kept


# ------------------------------------------------------------------ API lookup

def parse_response(payload: dict, cves: list[str],
                   score_date: str) -> dict[str, dict]:
    """State entries for one API response covering ``cves`` at
    ``score_date``. Every requested CVE gets an entry: scored ones carry
    the 5-decimal-rounded probability/percentile and the era label;
    missing ones are recorded as the fact "no score existed that day".
    Raises ValueError when the envelope shape is wrong (defense against
    an upstream format change being read as "nothing scored")."""
    data = payload.get("data")
    if not isinstance(data, list):
        raise ValueError(f"EPSS API envelope has no data list: "
                         f"{str(payload)[:200]}")
    rows: dict[str, dict] = {}
    for row in data:
        if not isinstance(row, dict) or "cve" not in row:
            raise ValueError(f"malformed EPSS API row: {row!r}")
        rows[str(row["cve"])] = row
    label = model_label(score_date)
    entries: dict[str, dict] = {}
    for cve in cves:
        row = rows.get(cve)
        if row is None:
            reason = REASON_PRE_EPSS if score_date < EPSS_FIRST_DAY \
                else REASON_NO_SCORE
            entries[cve] = {"score_date": score_date, "epss": None,
                            "percentile": None, "model": None,
                            "reason": reason}
            continue
        epss = round(float(row["epss"]), 5)
        pct = row.get("percentile")
        percentile = round(float(pct), 5) if pct is not None else None
        entries[cve] = {"score_date": score_date, "epss": epss,
                        "percentile": percentile, "model": label,
                        "reason": None}
    return entries


def fetch_scores(session, cves: list[str], score_date: str,
                 log: Callable[[str], None] = print) -> dict:
    """One API request: up to :data:`MAX_CVES_PER_REQUEST` CVE ids at one
    date. Returns the raw envelope. HTTP 422 ("No records available") is
    an authoritative empty answer, not an error. Fails loudly after the
    retry budget — the nightly workflow treats a failed pipeline as
    'deploy nothing'."""
    import time

    if len(cves) > MAX_CVES_PER_REQUEST:
        raise ValueError(f"{len(cves)} CVEs in one request (max "
                         f"{MAX_CVES_PER_REQUEST}; the API is "
                         f"URL-length-bound)")
    params = {"cve": ",".join(cves), "date": score_date,
              "limit": _REQUEST_LIMIT}
    message = "no attempt made"
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            resp = session.get(API_URL, params=params,
                               headers={"User-Agent": USER_AGENT},
                               timeout=_TIMEOUT)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 422:
                # "No records available" — none of these CVEs had a score
                # that day (or the date predates EPSS). A fact, not a fault.
                return {"data": []}
            retryable = resp.status_code in _RETRY_STATUSES
            message = f"HTTP {resp.status_code}"
        except (OSError, ValueError) as exc:
            retryable = True
            message = f"request failed: {exc!r}"
        if not retryable or attempt == _MAX_ATTEMPTS:
            break
        backoff = 15.0 * attempt
        log(f"  epss-report: {message} for {score_date}; retrying in "
            f"{backoff:.0f}s (attempt {attempt}/{_MAX_ATTEMPTS})")
        time.sleep(backoff)
    raise RuntimeError(f"EPSS history fetch failed for {score_date}: "
                       f"{message}")


# ----------------------------------------------------------------------- sync

def sync_state(state: dict | None, kev_pairs: list[tuple[str, str]],
               fetch: Callable[[list[str], str], dict],
               *, backfill_batch: int, last_sync: str = "",
               save: Callable[[dict], None] | None = None,
               log: Callable[[str], None] = print) -> dict:
    """Return up-to-date sync state ``{version, last_sync, entries}``.

    ``kev_pairs`` is the current catalog's ``(cve_id, date_added)`` list
    (undated entries already excluded by the caller); ``fetch`` maps
    ``(cves, score_date) -> API envelope`` (injected so fixtures and tests
    never need the network). Prior entries are pruned against the catalog,
    then at most ``backfill_batch`` missing pairs are looked up — grouped
    by score date, chunked at :data:`MAX_CVES_PER_REQUEST` — oldest dates
    first, so a partial backfill fills history front-to-back and the
    published per-year pending counts shrink deterministically. Pairs
    beyond the batch stay missing (published as pending-backfill counts).

    ``save`` (when given) persists the state after each completed date, so
    an interrupted backfill or a failed request never loses progress; on a
    fetch error the accumulated state is saved and the error re-raised.
    """
    wanted: dict[str, tuple[str, str, str]] = {}
    for cve_id, date_added in kev_pairs:
        try:
            score_date = score_date_for(date_added)
        except ValueError:
            log(f"  epss-report: skipping undated KEV entry {cve_id} "
                f"({date_added!r})")
            continue
        wanted[entry_key(cve_id, date_added)] = (cve_id, date_added,
                                                 score_date)
    entries = _pruned_entries(state, set(wanted), log)
    missing = [key for key in wanted if key not in entries]

    result = {"version": STATE_VERSION, "last_sync": last_sync,
              "entries": entries}
    if not missing:
        return result

    # Oldest score dates first: deterministic front-to-back backfill. A
    # non-positive batch looks up nothing (everything stays pending).
    missing.sort(key=lambda k: (wanted[k][2], wanted[k][0]))
    batch = missing[:max(backfill_batch, 0)]
    log(f"  epss-report: {len(missing)} pair(s) missing from state; "
        f"looking up {len(batch)} this run "
        f"(batch cap {backfill_batch})")
    if not batch:
        return result

    by_date: dict[str, list[str]] = {}
    for key in batch:
        cve_id, _added, score_date = wanted[key]
        by_date.setdefault(score_date, []).append(cve_id)

    try:
        for score_date in sorted(by_date):
            cves = sorted(by_date[score_date])
            fetched: dict[str, dict] = {}
            for i in range(0, len(cves), MAX_CVES_PER_REQUEST):
                chunk = cves[i:i + MAX_CVES_PER_REQUEST]
                fetched.update(parse_response(fetch(chunk, score_date),
                                              chunk, score_date))
            for key in batch:
                cve_id, _added, sd = wanted[key]
                if sd == score_date and cve_id in fetched:
                    entries[key] = fetched[cve_id]
            if save is not None:
                save(result)
    except Exception:
        if save is not None:
            save(result)  # keep every completed lookup
        raise
    scored = sum(1 for key in batch
                 if key in entries and entries[key]["epss"] is not None)
    log(f"  epss-report: looked up {len(batch)} pair(s) over "
        f"{len(by_date)} date(s); {scored} had a day-before score")
    return result


def live_fetcher(session, log: Callable[[str], None] = print
                 ) -> Callable[[list[str], str], dict]:
    """The production ``fetch`` for :func:`sync_state`: paced API calls."""
    import time

    state = {"first": True}

    def fetch(cves: list[str], score_date: str) -> dict:
        if not state["first"]:
            time.sleep(REQUEST_SLEEP)
        state["first"] = False
        return fetch_scores(session, cves, score_date, log=log)

    return fetch
