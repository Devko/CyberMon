"""Detection Rules (module 28): SigmaHQ rule churn and ATT&CK coverage
(sigma_coverage.json).

Three measurements, joined to the ATT&CK enterprise release list and dates
the ATT&CK Releases stage publishes (``attack_churn.json``) and to the
technique timeline in ``attack_techniques``:

* **churn** — rules added and deprecated per calendar quarter. "Added"
  counts every rule in the repository today (active or in ``deprecated/``)
  by its own ``date`` field; "deprecated" counts the rules in
  ``deprecated/`` by their ``modified`` date. Both are the rule authors'
  dates, not commit dates, so they are approximate; rules deleted outright
  (never moved to ``deprecated/``) are invisible, so older quarters are
  lower bounds.
* **coverage** — at each quarter end, the share of today's ATT&CK
  enterprise techniques (sub-technique tags rolled up to the parent,
  revoked ids followed to their replacement) that had debuted by then and
  had at least one rule alive then: dated on or before the quarter end and
  not yet deprecated (a deprecated rule counts until its ``modified``
  date). Only rules carrying an ``attack.tNNNN`` tag can cover anything;
  tags are read as they stand today. The current quarter is computed to
  the edition date and marked partial.
* **lag** — for techniques that debuted after ATT&CK's first indexed
  release: days from the debut release date to the date of the first rule
  tagged with the technique. A first rule dated before the debut (written
  before ATT&CK named the behaviour, or relabelled later) counts as zero.
  The median is taken over techniques with at least
  :data:`LAG_FOLLOW_UP_DAYS` of follow-up, counting techniques with no
  rule as longer than any observed wait; it is exact when every such
  technique has been followed for longer than the median, and published as
  a lower bound otherwise. Per debut year, techniques are also split into
  "rule dated before the debut", "within a year", "later" and "no rule".

The stage carries the previous edition forward (stale) when SigmaHQ or an
ATT&CK bundle cannot be read: :func:`run_stage` raises, and ``__main__``
handles the degrade like every other single-upstream module.
"""
from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from datetime import date as _date, timedelta
from pathlib import Path
from statistics import median
from typing import Callable

from . import attack_techniques, fetch_sigma
from .fetch_sigma import ACTIVE, DEPRECATED, Rule, RuleSet

FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures"
OUTPUT_NAME = "sigma_coverage.json"

LAG_FOLLOW_UP_DAYS = 730      # two years of follow-up for the median cohort
WITHIN_DAYS = 365             # the "within a year" bucket of the cohort chart
LAG_BUCKETS = ("before_debut", "within_year", "later", "none")


# ----------------------------------------------------------------- helpers

def _d(day: str) -> _date:
    return _date.fromisoformat(day)


def quarter_of(day: _date) -> tuple[int, int]:
    return day.year, (day.month - 1) // 3 + 1


def quarter_label(year: int, q: int) -> str:
    return f"{year}Q{q}"


def quarter_bounds(year: int, q: int) -> tuple[_date, _date]:
    start = _date(year, 3 * q - 2, 1)
    nxt = _date(year + 1, 1, 1) if q == 4 else _date(year, 3 * q + 1, 1)
    return start, nxt - timedelta(days=1)


def _quarters(first: _date, last: _date) -> list[tuple[int, int]]:
    out = []
    y, q = quarter_of(first)
    end = quarter_of(last)
    while (y, q) <= end:
        out.append((y, q))
        y, q = (y + 1, 1) if q == 4 else (y, q + 1)
    return out


def _round_half_up(x: float) -> int:
    return math.floor(x + 0.5)


def _pct(n: int, d: int) -> float | None:
    """Percent, 1 decimal (the house rounding); None for an empty base."""
    return round(100.0 * n / d, 1) if d else None


def rule_techniques(rule: Rule, revoked_to: dict[str, str],
                    active: set[str]) -> set[str]:
    """The active parent techniques one rule's tags name."""
    out = set()
    for tid in rule.techniques:
        parent = attack_techniques.resolve(tid, revoked_to)
        if parent in active:
            out.add(parent)
    return out


def _alive(rule: Rule, end: _date) -> bool:
    if _d(rule.date) > end:
        return False
    if rule.cls == DEPRECATED:
        # A deprecated rule covered its techniques until its last edit
        # (normally the deprecation); without one, from its date on it is
        # treated as gone the day it was written — never as still active.
        gone = _d(rule.modified) if rule.modified else _d(rule.date)
        return gone > end
    return True


# ------------------------------------------------------------------ builder

def build_sigma_coverage(rule_set: RuleSet, timeline: dict,
                         releases: dict[str, str], generated_at: str) -> dict:
    """Assemble sigma_coverage.json. ``releases`` maps every ATT&CK
    version in the timeline to its release date (from attack_churn.json)."""
    today = _d(generated_at[:10])
    latest = timeline["latest"]
    synced = timeline["synced"]
    first_version = synced[0]
    revoked_to = latest["revoked_to"]
    tech_table = timeline["techniques"]
    active = {t for t, e in tech_table.items() if e.get("retired") is None}
    missing = [v for v in synced if v not in releases]
    if missing:
        raise ValueError(f"sigma: ATT&CK releases {missing} have no "
                         f"release date in attack_churn.json")
    debut_date = {t: _d(releases[tech_table[t]["debut"]]) for t in active}

    # Rules dated after the edition (upstream typos) are left out entirely.
    rules = [r for r in rule_set.rules if _d(r.date) <= today]
    future_dated = len(rule_set.rules) - len(rules)
    covers = [rule_techniques(r, revoked_to, active) for r in rules]

    # ---- churn per quarter and per year --------------------------------------
    added_q: Counter = Counter(quarter_of(_d(r.date)) for r in rules)
    dep_q: Counter = Counter(quarter_of(_d(r.modified)) for r in rules
                             if r.cls == DEPRECATED and r.modified
                             and _d(r.modified) <= today)
    first_rule = min(_d(r.date) for r in rules)
    quarter_rows = []
    for (y, q) in _quarters(first_rule, today):
        start, end = quarter_bounds(y, q)
        cut = min(end, today)
        debuted = {t for t in active if debut_date[t] <= cut}
        covered = set()
        for r, techs in zip(rules, covers):
            if techs and _alive(r, cut):
                covered |= techs
        covered &= debuted
        quarter_rows.append({
            "quarter": quarter_label(y, q),
            "start": start.isoformat(), "end": end.isoformat(),
            "partial": end > today,
            "added": added_q.get((y, q), 0),
            "deprecated": dep_q.get((y, q), 0),
            "techniques": len(debuted),
            "covered": len(covered),
            "pct": _pct(len(covered), len(debuted)),
        })
    year_rows = []
    for year in range(first_rule.year, today.year + 1):
        year_rows.append({
            "year": year,
            "partial": year == today.year,
            "added": sum(n for (y, _q), n in added_q.items() if y == year),
            "deprecated": sum(n for (y, _q), n in dep_q.items()
                              if y == year),
        })

    # ---- coverage today ------------------------------------------------------
    active_rules = [(r, t) for r, t in zip(rules, covers) if r.cls == ACTIVE]
    rule_counts: Counter = Counter()
    for _r, techs in active_rules:
        rule_counts.update(techs)
    covered_now = {t for t in active if rule_counts[t] > 0}
    with_share = [row for row in quarter_rows if row["pct"] is not None]
    peak = max(with_share, key=lambda row: row["pct"]) if with_share \
        else None

    # ---- first rule per technique, lag ---------------------------------------
    first_rule_date: dict[str, _date] = {}
    for r, techs in zip(rules, covers):
        day = _d(r.date)
        for t in techs:
            if t not in first_rule_date or day < first_rule_date[t]:
                first_rule_date[t] = day

    def lag_of(t: str) -> int | None:
        f = first_rule_date.get(t)
        return None if f is None else (f - debut_date[t]).days

    def bucket(t: str) -> str:
        lag = lag_of(t)
        if lag is None:
            return "none"
        if lag <= 0:
            return "before_debut"
        return "within_year" if lag <= WITHIN_DAYS else "later"

    later_debuts = sorted((t for t in active
                           if tech_table[t]["debut"] != first_version),
                          key=lambda t: (debut_date[t], t))
    cohorts = defaultdict(list)
    for t in later_debuts:
        cohorts[debut_date[t].year].append(t)
    cohort_rows = []
    for year in sorted(cohorts):
        ts = cohorts[year]
        counts = Counter(bucket(t) for t in ts)
        follow = min((today - debut_date[t]).days for t in ts)
        cohort_rows.append({
            "year": year, "techniques": len(ts),
            **{k: counts.get(k, 0) for k in LAG_BUCKETS},
            "min_follow_up_days": follow,
            "full_year": follow >= WITHIN_DAYS,
        })

    cutoff = today - timedelta(days=LAG_FOLLOW_UP_DAYS)
    cohort = [t for t in later_debuts if debut_date[t] <= cutoff]
    lag = {"follow_up_days": LAG_FOLLOW_UP_DAYS,
           "debut_after": first_version,
           "debut_through": cutoff.isoformat(),
           "n": len(cohort),
           **{k: sum(1 for t in cohort if bucket(t) == k)
              for k in LAG_BUCKETS},
           "median_days": None, "median_at_least_days": None,
           "median_exact": False}
    if cohort:
        waits = sorted(max(0, lag_of(t)) if lag_of(t) is not None
                       else math.inf for t in cohort)
        mid = median(waits)
        open_follow = [(today - debut_date[t]).days for t in cohort
                       if lag_of(t) is None]
        if math.isfinite(mid) and all(f > mid for f in open_follow):
            lag["median_days"] = _round_half_up(mid)
            lag["median_exact"] = True
        else:
            # Lower bound: each open technique at the wait it has already
            # served (its true wait can only be longer).
            served = sorted(max(0, lag_of(t)) if lag_of(t) is not None
                            else (today - debut_date[t]).days
                            for t in cohort)
            lag["median_at_least_days"] = _round_half_up(median(served))

    # ---- by tactic (today) ---------------------------------------------------
    tactic_rows = []
    for tactic in latest["tactic_order"]:
        ts = [t for t in active if tactic in latest["tactics"].get(t, [])]
        if not ts:
            continue
        n_cov = sum(1 for t in ts if t in covered_now)
        tactic_rows.append({"id": tactic,
                            "name": latest["tactic_names"].get(tactic,
                                                               tactic),
                            "techniques": len(ts), "covered": n_cov,
                            "pct": _pct(n_cov, len(ts))})

    techniques = [{
        "id": t,
        "name": latest["names"].get(t, t),
        "tactics": list(latest["tactics"].get(t, [])),
        "debut": tech_table[t]["debut"],
        "debut_date": debut_date[t].isoformat(),
        "first_rule": (first_rule_date[t].isoformat()
                       if t in first_rule_date else None),
        "rules": rule_counts.get(t, 0),
    } for t in sorted(active, key=lambda t: (int(t[1:]) if t[1:].isdigit()
                                              else 0, t))]
    retired = [{"id": t, "debut": e["debut"], "retired": e["retired"]}
               for t, e in sorted(tech_table.items()) if e.get("retired")]

    tagged = sum(1 for r in rules if r.techniques)
    mapped = sum(1 for techs in covers if techs)
    return {
        "generated_at": generated_at,
        # The date every partial flag and follow-up is measured to. A
        # carried-forward edition is restamped with a new generated_at
        # but keeps this, so it stays self-consistent across a quarter
        # or year boundary.
        "as_of": today.isoformat(),
        "source": {"commit": rule_set.head,
                   "commit_date": rule_set.commit_date},
        "catalog": {
            "rules": len(rules),
            "active": sum(1 for r in rules if r.cls == ACTIVE),
            "deprecated": sum(1 for r in rules if r.cls == DEPRECATED),
            "technique_tagged": tagged,
            "mapped": mapped,
            "active_mapped": sum(1 for _r, t in active_rules if t),
            "files": rule_set.files,
            "skipped": rule_set.skipped,
            "future_dated": future_dated,
            "first_rule_date": first_rule.isoformat(),
            "first_quarter": quarter_rows[0]["quarter"],
        },
        "quarters": quarter_rows,
        "years": year_rows,
        "coverage": {
            "techniques": len(active),
            "covered": len(covered_now),
            "pct": _pct(len(covered_now), len(active)),
            "peak": ({"quarter": peak["quarter"], "pct": peak["pct"],
                      "covered": peak["covered"],
                      "techniques": peak["techniques"]} if peak else None),
        },
        "lag": lag,
        "cohorts": cohort_rows,
        "tactics": tactic_rows,
        "attack": {
            "version": latest["version"],
            "released": releases[latest["version"]],
            "first_version": first_version,
            "first_released": releases[first_version],
            "synced": list(synced),
            "tactics": [{"id": t, "name": latest["tactic_names"].get(t, t)}
                        for t in latest["tactic_order"]],
            "revoked_to": dict(sorted(revoked_to.items())),
        },
        "techniques": techniques,
        "retired_techniques": retired,
    }


def source_block(obj: dict, fetched_at: str) -> dict:
    """meta.sources.sigma for a freshly built edition."""
    return {"fetched_at": fetched_at, "commit": obj["source"]["commit"],
            "commit_date": obj["source"]["commit_date"],
            "rules": obj["catalog"]["rules"],
            "attack_version": obj["attack"]["version"]}


# -------------------------------------------------------------------- stage

def _releases_from(attack_churn: dict | None) -> tuple[list[str],
                                                       dict[str, str]]:
    versions = (attack_churn or {}).get("versions") or []
    if not versions:
        raise ValueError("sigma: attack_churn.json lists no ATT&CK "
                         "releases to join against")
    order = [str(v["version"]) for v in versions]
    return order, {str(v["version"]): str(v["released"]) for v in versions}


def _published(out_dir: Path) -> dict | None:
    path = out_dir / OUTPUT_NAME
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def run_stage(out_dir: Path, cache_dir: Path, generated_at: str, *,
              attack_churn: dict | None, offline_fixtures: bool,
              session=None, git_run=None,
              log: Callable[[str], None] = print) -> tuple[dict, dict]:
    """(sigma_coverage.json object, meta.sources.sigma block).

    * ``offline_fixtures`` — rules from pipeline/tests/fixtures/sigma/repo/
      (a tiny tree in the upstream layout) and ATT&CK bundles from
      fixtures/sigma/attack/, keyed by the versions the fixture ATT&CK
      stage emitted. No network, no cache writes.
    * live — ``git ls-remote``; a shallow clone only when the head moved
      (fetch_sigma); the technique timeline synced against the ATT&CK
      release list (one bundle per new release, none on a normal night);
      the cache saved; the edition built.

    Raises OSError / ValueError when an upstream cannot be read or the
    snapshot fails its structural floor — the caller carries the previous
    edition forward, marked stale.
    """
    versions, releases = _releases_from(attack_churn)

    if offline_fixtures:
        fixture_dir = FIXTURES_DIR / "sigma"
        rule_set = fetch_sigma.parse_files(
            fetch_sigma.read_tree(fixture_dir / "repo"), head="0" * 40,
            commit_date=generated_at[:10], min_rules=1)

        def _local_bundle(version: str) -> dict:
            name = f"enterprise-attack-{version}.json"
            return json.loads((fixture_dir / "attack" / name)
                              .read_text(encoding="utf-8"))

        timeline, _reads = attack_techniques.sync(None, versions,
                                                  _local_bundle, log=log)
        obj = build_sigma_coverage(rule_set, timeline, releases,
                                   generated_at)
        return obj, source_block(obj, generated_at)

    state = fetch_sigma.load_state(cache_dir, log=log)
    kwargs = {"log": log}
    if git_run is not None:
        kwargs["run"] = git_run
    rule_set, fetched = fetch_sigma.current_rules(state, **kwargs)

    timeline_state = state.get("attack")
    if not attack_techniques._valid(timeline_state):
        timeline_state = attack_techniques.reconstruct(_published(out_dir))
        if timeline_state is not None:
            log("  sigma: technique timeline reconstructed from published "
                f"{OUTPUT_NAME} (ATT&CK v{timeline_state['synced'][-1]})")

    urls: dict[str, str] = {}

    def _live_bundle(version: str) -> dict:
        from .fetch_attack import fetch_bundle, fetch_index, parse_index

        nonlocal session
        if session is None:
            import requests

            session = requests.Session()
        # fetch_attack fails loudly with RuntimeError after its retries;
        # here an unreadable bundle is an upstream outage like any other,
        # so it surfaces as OSError and the module degrades to stale.
        try:
            if not urls:
                urls.update({iv["version"]: iv["url"] for iv in
                             parse_index(fetch_index(session, log=log))})
            if version not in urls:
                raise ValueError(f"sigma: ATT&CK v{version} is not in "
                                 f"index.json")
            log(f"  sigma: reading ATT&CK v{version} bundle")
            return fetch_bundle(session, urls[version], log=log)
        except RuntimeError as exc:
            raise OSError(str(exc)) from exc

    timeline, reads = attack_techniques.sync(timeline_state, versions,
                                             _live_bundle, log=log)
    if reads:
        log(f"  sigma: {reads} ATT&CK bundle read(s) this run")
    fetch_sigma.save_state(cache_dir, {
        "rules": fetch_sigma.rules_to_state(rule_set),
        "attack": timeline})
    obj = build_sigma_coverage(rule_set, timeline, releases, generated_at)
    cov = obj["coverage"]
    log(f"  sigma: {obj['catalog']['rules']} rules at "
        f"{rule_set.head[:12]}{' (fetched)' if fetched else ''}; "
        f"{cov['covered']}/{cov['techniques']} ATT&CK techniques covered")
    return obj, source_block(obj, generated_at)
