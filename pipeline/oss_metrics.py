"""Open-Source Maintainers (module 30): oss_maintainers.json.

For the frozen package list in :mod:`pipeline.oss_universe` (the 250
most-depended-on packages in each of npm, PyPI, crates.io and RubyGems),
this stage keeps one observation per package (who can publish it, per its
registry; see :mod:`pipeline.fetch_oss`) and one per source repository
(its OpenSSF Scorecard result), and publishes aggregates per registry:

* ``accounts`` — how many accounts can publish each package, bucketed,
  and the share that a single account can publish with no team or
  organisation behind it (``single_account``);
* ``shared`` — how many distinct accounts hold those rights, and how many
  packages the accounts with the most rights can publish between them;
* ``scorecard`` — Scorecard's overall score and four checks for the
  distinct GitHub repositories behind the packages.

Registries are never pooled: "maintainer" is defined per registry, so
every number is per registry.

Rolling refresh, not a nightly sweep. Publish rights and Scorecard results
move slowly (Scorecard rescans weekly), so each package and repository has
a fixed night in a :data:`REFRESH_DAYS`-night cycle and is re-read only
then (plus anything never read or overdue), oldest first, spread across
hosts and capped at ``batch`` lookups (``--oss-batch``,
default :data:`DEFAULT_BATCH`). A steady night is about a seventh of the
universe (some 270 lookups, about a minute). The observations live in a
cache (``.cache/oss_state.json.gz``, never committed: it holds per-package
rights the site deliberately does not publish). Losing it costs one full
sweep of about 1,870 lookups (seven minutes on 2026-11-05), which the
default batch covers in one night; a smaller batch spreads it over several
nights, carrying the previous edition forward stale meanwhile.

Scorecard results carry their own scan date. A result older than
:data:`SCORECARD_MAX_AGE_DAYS` at the edition date (Scorecard rescans the
repositories it tracks weekly; a handful of results date from 2022) is
counted as ``old_results``, not scored: its Maintained check would
describe activity long past.

Publishing rule: the edition is built only when every package and every
repository has an observation at most :data:`MAX_AGE_DAYS` old. Otherwise
the stage reports why and ``__main__`` carries the previous edition
forward (stale), as for any single-upstream module. A failed lookup keeps
the previous observation; a host that fails :data:`fetch_oss`-bounded
retries :data:`FAIL_LIMIT` times in a row is skipped for the night.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import statistics
import time
from collections import Counter, defaultdict
from datetime import date as _date
from pathlib import Path
from typing import Callable

from . import fetch_oss
from .oss_universe import ECOSYSTEMS, Universe, load_universe, parse_universe

FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures" / "oss"
STATE_FILENAME = "oss_state.json.gz"

REFRESH_DAYS = 7
MAX_AGE_DAYS = 14
DEFAULT_BATCH = 2000
FAIL_LIMIT = 3
SCORECARD_MAX_AGE_DAYS = 45

# (label, min accounts, max accounts or None). "0" is a package published
# only through a team (crates.io) or an organisation (PyPI, RubyGems).
ACCOUNT_BUCKETS = (("0", 0, 0), ("1", 1, 1), ("2", 2, 2), ("3", 3, 3),
                   ("4–5", 4, 5), ("6–10", 6, 10), ("11+", 11, None))
ACCOUNT_BUCKET_LABELS = tuple(b[0] for b in ACCOUNT_BUCKETS)
SCORE_BUCKETS = ("inconclusive", "0", "1–4", "5–7", "8–10")
TOP_K = (1, 5, 10, 25)


def _pct(n: int, d: int) -> float | None:
    return round(100.0 * n / d, 1) if d else None


def _age(observed: str, today: str) -> int:
    return (_date.fromisoformat(today) - _date.fromisoformat(observed)).days


def _repo_key(repo: str) -> str:
    return repo.lower()


# ------------------------------------------------------------------ state

def state_path(state_dir: Path) -> Path:
    return Path(state_dir) / STATE_FILENAME


def empty_state(universe: Universe) -> dict:
    return {"edition": universe.edition, "rule_version": universe.rule_version,
            "packages": {}, "repos": {}}


def load_state(state_dir: Path, universe: Universe,
               log: Callable[[str], None] = print) -> dict:
    """The cached observations, or an empty state when the cache is
    missing, unreadable or belongs to another universe edition. The state
    is only a cache: an empty one means more lookups, never wrong data."""
    path = state_path(state_dir)
    if not path.exists():
        return empty_state(universe)
    try:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError) as exc:
        log(f"  oss: ignoring unreadable state {path}: {exc!r}")
        return empty_state(universe)
    if not isinstance(state, dict) or state.get("edition") != \
            universe.edition or state.get("rule_version") != \
            universe.rule_version or not isinstance(
                state.get("packages"), dict) or not isinstance(
                state.get("repos"), dict):
        log(f"  oss: state in {path} is for another universe edition; "
            f"starting a fresh observation cycle")
        return empty_state(universe)
    return state


def persist(state_dir: Path, state: dict,
            log: Callable[[str], None] = print) -> None:
    """Write the observation cache atomically. Called by ``__main__``
    after every output validated (it holds no history, so a failed night
    loses only that night's lookups)."""
    path = state_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        json.dump(state, f, separators=(",", ":"), sort_keys=True)
    tmp.replace(path)
    log(f"  oss: {len(state['packages'])} package and "
        f"{len(state['repos'])} repository observation(s) in {path}")


# ---------------------------------------------------------------- refresh

def _repos(universe: Universe) -> dict[str, str]:
    """Distinct repositories behind the universe: lowercase key -> the
    spelling first seen (universe order)."""
    out: dict[str, str] = {}
    for p in universe.packages:
        if p.repo:
            out.setdefault(_repo_key(p.repo), p.repo)
    return out


def _slot(key: str, refresh_days: int) -> int:
    """The night of the cycle on which ``key`` is refreshed: a stable hash,
    so the universe spreads over the cycle instead of falling due at once."""
    return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) % refresh_days


def _due(obs: dict | None, key: str, today: str, refresh_days: int) -> bool:
    """Never observed; overdue (a missed slot night); or tonight is the
    key's slot night and it was not already read today."""
    if obs is None:
        return True
    age = _age(obs["observed"], today)
    if age > refresh_days:
        return True
    return age >= 1 and _slot(key, refresh_days) == \
        _date.fromisoformat(today).toordinal() % refresh_days


def due_lookups(universe: Universe, state: dict, today: str, *,
                refresh_days: int = REFRESH_DAYS) -> list[tuple]:
    """Lookups due tonight as ``(host, kind, key, target)``.

    Each package and repository has a fixed slot night in the
    ``refresh_days`` cycle (:func:`_slot`), so a steady night reads about
    1/``refresh_days`` of the universe and every observation is renewed
    within ``refresh_days`` days. Never-observed and overdue keys (after a
    lost cache or a missed night) are due at once. Oldest first within a
    host, then interleaved across hosts, so a capped batch shares its budget
    and the per-host pacing overlaps."""
    by_host: dict[str, list[tuple]] = defaultdict(list)
    for i, p in enumerate(universe.packages):
        obs = state["packages"].get(p.key)
        if _due(obs, p.key, today, refresh_days):
            by_host[p.ecosystem].append(
                ((obs or {}).get("observed", ""), i,
                 (p.ecosystem, "package", p.key, p)))
    for i, (key, repo) in enumerate(_repos(universe).items()):
        obs = state["repos"].get(key)
        if _due(obs, key, today, refresh_days):
            by_host["scorecard"].append(
                ((obs or {}).get("observed", ""), i,
                 ("scorecard", "repo", key, repo)))
    queues = [[t for _o, _i, t in sorted(by_host[h], key=lambda x: x[:2])]
              for h in (*ECOSYSTEMS, "scorecard") if by_host.get(h)]
    out: list[tuple] = []
    while any(queues):
        for q in queues:
            if q:
                out.append(q.pop(0))
    return out


def refresh(universe: Universe, state: dict, today: str, *, session,
            batch: int = DEFAULT_BATCH, sleep=time.sleep,
            clock=time.monotonic, log: Callable[[str], None] = print
            ) -> fetch_oss.FetchStats:
    """Run tonight's due lookups (at most ``batch``) and write each result
    into ``state`` in place. Returns the night's counters."""
    stats = fetch_oss.FetchStats()
    due = due_lookups(universe, state, today)
    todo = due[:max(0, batch)]
    log(f"  oss: {len(due)} lookup(s) due, {len(todo)} tonight "
        f"(batch {batch})")
    consecutive: Counter = Counter()
    last: dict[str, float] = {}
    for host, kind, key, target in todo:
        if host in stats.skipped_hosts:
            continue
        gap = fetch_oss.PACE[host] - (clock() - last.get(host, -1e9))
        if gap > 0:
            sleep(gap)
        last[host] = clock()
        stats.lookups += 1
        try:
            if kind == "package":
                result = fetch_oss.fetch_publishers(
                    session, target.ecosystem, target.name, sleep=sleep,
                    log=log)
                state["packages"][key] = result.to_state(today)
            else:
                card = fetch_oss.fetch_scorecard(session, target, sleep=sleep,
                                                 log=log)
                state["repos"][key] = (
                    {"observed": today, "status": "none"} if card is None
                    else {"observed": today, "status": "ok", **card})
        except (OSError, ValueError) as exc:
            stats.failed += 1
            log(f"  oss: {host} lookup for {key} failed ({exc!r}); "
                f"keeping the previous observation")
            # Only transport failures (already retried) count toward the
            # breaker: an unparseable answer is about one package, and it
            # costs no retries.
            if not isinstance(exc, OSError):
                continue
            consecutive[host] += 1
            if consecutive[host] >= FAIL_LIMIT:
                stats.skipped_hosts.add(host)
                log(f"  oss: {host} failed {FAIL_LIMIT} lookups in a row; "
                    f"skipping it for the rest of the night")
            continue
        consecutive[host] = 0
    return stats


def coverage_gap(universe: Universe, state: dict, today: str, *,
                 max_age: int = MAX_AGE_DAYS) -> str | None:
    """Why tonight's observations cannot be published, or None. Every
    package and repository needs an observation at most ``max_age`` days
    old: a partial universe would change the denominator, not the world."""
    def stale(obs) -> bool:
        return obs is None or _age(obs["observed"], today) > max_age

    pkgs = [p for p in universe.packages if stale(state["packages"].get(p.key))]
    repos = [k for k in _repos(universe) if stale(state["repos"].get(k))]
    if not pkgs and not repos:
        return None
    return (f"{len(pkgs)} of {len(universe.packages)} packages and "
            f"{len(repos)} of {len(_repos(universe))} repositories have no "
            f"observation from the last {max_age} days")


# ------------------------------------------------------------------ build

def _bucket_accounts(n: int) -> str:
    for label, lo, hi in ACCOUNT_BUCKETS:
        if n >= lo and (hi is None or n <= hi):
            return label
    raise AssertionError(n)  # pragma: no cover


def _bucket_score(s: int | None) -> str | None:
    if s is None:
        return None
    if s < 0:
        return "inconclusive"
    if s == 0:
        return "0"
    if s <= 4:
        return "1–4"
    if s <= 7:
        return "5–7"
    return "8–10"


def _median(values: list[float]) -> float | None:
    return round(float(statistics.median(values)), 1) if values else None


def _recent(result: dict, today: str) -> bool:
    return _age(result["date"], today) <= SCORECARD_MAX_AGE_DAYS


def build_ecosystem(eco: str, universe: Universe, state: dict,
                    today: str) -> dict:
    pkgs = universe.by_ecosystem(eco)
    measured = [(p, state["packages"][p.key]) for p in pkgs
                if state["packages"][p.key]["status"] == "ok"]
    missing = len(pkgs) - len(measured)

    counts = Counter(_bucket_accounts(len(o["accounts"])) for _p, o in measured)
    # Single-account packages, and how concentrated those sole accounts
    # are: one account can be the only publisher of many packages.
    sole = Counter(o["accounts"][0] for _p, o in measured
                   if len(o["accounts"]) == 1 and not o["teams"]
                   and not o["org"])
    single = sum(sole.values())
    team_org = sum(1 for _p, o in measured if o["teams"] or o["org"])

    # Accounts shared across packages: rank accounts by how many of the
    # measured packages they can publish (ties: by id, which is arbitrary
    # but stable), then count the packages the top k reach between them.
    reach: dict[str, set[str]] = defaultdict(set)
    for p, o in measured:
        for acct in o["accounts"]:
            reach[acct].add(p.key)
    ranked = sorted(reach.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    top = []
    for k in TOP_K:
        covered: set[str] = set()
        for _acct, keys in ranked[:k]:
            covered |= keys
        top.append({"k": k, "n": len(covered),
                    "pct": _pct(len(covered), len(measured))})

    # Scorecard: each distinct repository once per registry.
    gh = [p for p, _o in measured if p.repo]
    repo_keys = sorted({_repo_key(p.repo) for p in gh})
    results = [state["repos"][k] for k in repo_keys
               if state["repos"][k]["status"] == "ok"]
    scored = [r for r in results if _recent(r, today)]
    checks = {}
    not_reported = {}
    for check in fetch_oss.CHECKS:
        c = Counter(_bucket_score(r["checks"].get(check)) for r in scored)
        not_reported[check] = c.pop(None, 0)
        checks[check] = [{"label": b, "n": c.get(b, 0)} for b in SCORE_BUCKETS]
    return {
        "id": eco,
        "packages": len(pkgs),
        "measured": len(measured),
        "missing": missing,
        "accounts": {
            "buckets": [{"label": b, "n": counts.get(b, 0)}
                        for b in ACCOUNT_BUCKET_LABELS],
            "median": _median([len(o["accounts"]) for _p, o in measured]),
        },
        "single_account": {"n": single, "pct": _pct(single, len(measured)),
                           "accounts": len(sole),
                           "largest": max(sole.values(), default=0)},
        "team_or_org": {"n": team_org, "pct": _pct(team_org, len(measured))},
        "shared": {
            "distinct_accounts": len(reach),
            "top": top,
        },
        "scorecard": {
            "github_packages": len(gh),
            "repos": len(repo_keys),
            "scored": len(scored),
            "old_results": len(results) - len(scored),
            "median_score": _median([r["score"] for r in scored]),
            "checks": checks,
            "not_reported": not_reported,
        },
    }


def build_oss_maintainers(universe: Universe, state: dict,
                          generated_at: str) -> dict:
    """Assemble oss_maintainers.json from a fully covered state (call
    :func:`coverage_gap` first)."""
    observed = [o["observed"] for p in universe.packages
                for o in (state["packages"][p.key],)]
    observed += [state["repos"][k]["observed"] for k in _repos(universe)]
    today = generated_at[:10]
    # Scorecard's own result dates (when Scorecard scanned), for the
    # results the edition scores: recent results for repositories of
    # packages still on their registry.
    counted = {_repo_key(p.repo) for p in universe.packages
               if p.repo and state["packages"][p.key]["status"] == "ok"}
    result_dates = [state["repos"][k]["date"] for k in sorted(counted)
                    if state["repos"][k]["status"] == "ok"
                    and _recent(state["repos"][k], today)]
    return {
        "generated_at": generated_at,
        "universe": {
            "edition": universe.edition,
            "rule_version": universe.rule_version,
            "selected_at": universe.selected_at,
            "per_ecosystem": universe.per_ecosystem,
            "download_floor": universe.download_floor,
        },
        "observed": {"first": min(observed), "last": max(observed),
                     "refresh_days": REFRESH_DAYS,
                     "max_age_days": MAX_AGE_DAYS},
        "scorecard_dates": {
            "max_age_days": SCORECARD_MAX_AGE_DAYS,
            "first": min(result_dates) if result_dates else None,
            "last": max(result_dates) if result_dates else None,
        },
        "ecosystems": [build_ecosystem(eco, universe, state, today)
                       for eco in ECOSYSTEMS],
    }


def source_block(obj: dict | None, generated_at: str, universe: Universe,
                 stats: fetch_oss.FetchStats, state: dict) -> dict:
    observed = [o["observed"] for o in state["packages"].values()]
    return {
        "fetched_at": generated_at,
        "edition": universe.edition,
        "packages": len(universe.packages),
        "lookups": stats.lookups,
        "failed": stats.failed,
        "oldest_observation": (obj["observed"]["first"] if obj
                               else min(observed, default=generated_at[:10])),
    }


# ------------------------------------------------------------------ stage

def run_stage(out_dir: Path, cache_dir: Path, generated_at: str, *,
              offline_fixtures: bool, batch: int = DEFAULT_BATCH,
              session=None, sleep=time.sleep,
              log: Callable[[str], None] = print
              ) -> tuple[dict | None, dict | None, dict, Path, str | None]:
    """(oss_maintainers.json or None, meta.sources.oss or None, state to
    persist, state directory, why the edition could not be built or None).

    The state is returned even when the edition is not built: tonight's
    lookups still count toward the next night's coverage. Offline fixture
    runs read pipeline/tests/fixtures/oss (universe + recorded responses)
    and keep their state beside the output, never in the live cache.
    """
    today = generated_at[:10]
    if offline_fixtures:
        universe = parse_universe(json.loads(
            (FIXTURES_DIR / "universe.json").read_text(encoding="utf-8")))
        session = fetch_oss.FixtureSession(FIXTURES_DIR / "responses.json")
        state_dir = Path(out_dir) / "history"
        sleep = (lambda _s: None)  # noqa: E731
    else:
        import requests

        universe = load_universe()
        session = session or requests.Session()
        state_dir = Path(cache_dir)
    state = load_state(state_dir, universe, log=log)
    stats = refresh(universe, state, today, session=session, batch=batch,
                    sleep=sleep, log=log)
    gap = coverage_gap(universe, state, today)
    if gap is not None:
        reason = f"Open-Source Maintainers not built: {gap}"
        log(f"  oss: {reason}")
        return None, None, state, state_dir, reason
    obj = build_oss_maintainers(universe, state, generated_at)
    source = source_block(obj, generated_at, universe, stats, state)
    singles = ", ".join(f"{e['id']} {e['single_account']['n']}"
                        for e in obj["ecosystems"])
    log(f"  oss: {stats.lookups} lookup(s), {stats.failed} failed; "
        f"single-account packages: {singles}")
    return obj, source, state, state_dir, None
