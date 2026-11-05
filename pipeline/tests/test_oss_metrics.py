"""oss_metrics: the rolling refresh (what is due, the batch cap, the
per-host breaker), the publishing rule, the per-registry aggregates on the
fixture universe, and the observation cache. No network."""
from __future__ import annotations

import json

import pytest

from pipeline import contracts, fetch_oss, oss_metrics
from pipeline.oss_universe import parse_universe

FIX = oss_metrics.FIXTURES_DIR
TODAY = "2026-11-05"
GEN = f"{TODAY}T03:00:00Z"


def universe():
    return parse_universe(json.loads((FIX / "universe.json").read_text("utf-8")))


def session():
    return fetch_oss.FixtureSession(FIX / "responses.json")


def full_state():
    u = universe()
    state = oss_metrics.empty_state(u)
    stats = oss_metrics.refresh(u, state, TODAY, session=session(),
                                sleep=lambda _s: None, log=lambda _m: None)
    return u, state, stats


def test_everything_is_due_on_an_empty_state():
    u = universe()
    due = oss_metrics.due_lookups(u, oss_metrics.empty_state(u), TODAY)
    # 12 packages + 9 distinct repos (two npm packages share one, case
    # folded; two packages have none).
    assert len(due) == 21
    # Interleaved across hosts: the first five lookups hit five hosts.
    assert [d[0] for d in due[:5]] == ["npm", "pypi", "crates", "rubygems",
                                       "scorecard"]


def test_first_spelling_of_a_shared_repo_is_the_one_looked_up():
    u = universe()
    repos = [d[3] for d in oss_metrics.due_lookups(
        u, oss_metrics.empty_state(u), TODAY) if d[1] == "repo"]
    assert "git" + "hub.com/example/big-framework" in repos
    assert not any(r.startswith("git" + "hub.com/Example") for r in repos)


def test_refresh_fills_the_state_and_counts_lookups():
    u, state, stats = full_state()
    assert stats.lookups == 21 and stats.failed == 0
    assert state["packages"]["pypi/gone-pkg"]["status"] == "missing"
    assert state["repos"]["git" + "hub.com/example/requests-lite"] == {
        "observed": TODAY, "status": "none"}
    assert oss_metrics.coverage_gap(u, state, TODAY) is None


def _advance(state, due, day):
    for _host, kind, key, _target in due:
        bucket = state["packages"] if kind == "package" else state["repos"]
        bucket[key] = {**bucket[key], "observed": day}


def test_steady_nights_read_a_rolling_slice():
    """After one full sweep, each night reads only the keys whose slot it
    is: over any seven nights every key is read exactly once, no night
    reads everything, and no observation ever ages past a week."""
    from datetime import date, timedelta

    u, state, _ = full_state()
    assert oss_metrics.due_lookups(u, state, TODAY) == []  # read today
    start = date.fromisoformat(TODAY)
    reads: dict[str, int] = {}
    for d in range(1, 22):
        day = (start + timedelta(days=d)).isoformat()
        due = oss_metrics.due_lookups(u, state, day)
        assert len(due) < 21, f"{day}: the whole universe fell due at once"
        for _h, _k, key, _t in due:
            reads[key] = reads.get(key, 0) + 1
        _advance(state, due, day)
        for obs in [*state["packages"].values(), *state["repos"].values()]:
            assert oss_metrics._age(obs["observed"], day) <= 7
    # 21 nights = three cycles: every key read three times.
    assert len(reads) == 21 and set(reads.values()) == {3}


def test_never_read_and_overdue_keys_are_due_at_once():
    u, state, _ = full_state()
    repo = "git" + "hub.com/example/numcalc"
    state["packages"]["npm/left-pad"]["observed"] = "2026-10-01"
    del state["repos"][repo]
    keys = {d[2] for d in oss_metrics.due_lookups(u, state, "2026-11-06")}
    assert {"npm/left-pad", repo} <= keys


def test_batch_caps_lookups_and_coverage_then_withholds_the_edition():
    u = universe()
    state = oss_metrics.empty_state(u)
    stats = oss_metrics.refresh(u, state, TODAY, session=session(), batch=7,
                                sleep=lambda _s: None, log=lambda _m: None)
    assert stats.lookups == 7
    gap = oss_metrics.coverage_gap(u, state, TODAY)
    assert gap is not None and "of 12 packages" in gap


def test_observations_older_than_max_age_block_publication():
    u, state, _ = full_state()
    state["repos"]["git" + "hub.com/example/numcalc"]["observed"] = "2026-10-01"
    assert "1 of 9 repositories" in oss_metrics.coverage_gap(u, state, TODAY)


class _Down:
    def __init__(self):
        self.calls = 0

    def get(self, url, **kwargs):
        self.calls += 1
        raise OSError("connection refused")


def test_breaker_skips_a_dead_host_and_keeps_old_observations():
    u, state, _ = full_state()
    before = json.loads(json.dumps(state))
    later = "2026-11-13"  # every observation overdue
    down = _Down()
    stats = oss_metrics.refresh(u, state, later, session=down,
                                sleep=lambda _s: None, log=lambda _m: None)
    # Each host fails FAIL_LIMIT lookups (each retried ATTEMPTS times) and
    # is then skipped; nothing in the state changes.
    hosts = {"npm", "pypi", "crates", "rubygems", "scorecard"}
    assert stats.skipped_hosts == hosts
    assert stats.failed == oss_metrics.FAIL_LIMIT * len(hosts)
    assert down.calls == stats.failed * fetch_oss.ATTEMPTS
    assert state == before


def test_unparseable_answer_does_not_trip_the_breaker(tmp_path):
    u = universe()
    recorded = json.loads((FIX / "responses.json").read_text("utf-8"))
    for url in list(recorded):
        if "rubygems.org" in url:
            recorded[url] = {"status": 200, "body": {"not": "a list"}}
    path = tmp_path / "r.json"
    path.write_text(json.dumps(recorded))
    state = oss_metrics.empty_state(u)
    stats = oss_metrics.refresh(u, state, TODAY,
                                session=fetch_oss.FixtureSession(path),
                                sleep=lambda _s: None, log=lambda _m: None)
    assert stats.failed == 3 and "rubygems" not in stats.skipped_hosts


def test_pacing_waits_only_the_remaining_gap():
    u = universe()
    waits = []
    now = [0.0]

    def clock():
        return now[0]

    def sleep(s):
        waits.append(round(s, 2))
        now[0] += s

    oss_metrics.refresh(u, oss_metrics.empty_state(u), TODAY,
                        session=session(), sleep=sleep, clock=clock,
                        log=lambda _m: None)
    # With a frozen clock every repeat request to a host waits its full
    # pace; the first request to each host never waits.
    assert waits and max(waits) <= max(fetch_oss.PACE.values())


def by_eco(obj):
    return {e["id"]: e for e in obj["ecosystems"]}


def test_build_on_the_fixture_universe():
    u, state, _ = full_state()
    obj = oss_metrics.build_oss_maintainers(u, state, GEN)
    contracts.validate("oss_maintainers.json", obj)
    e = by_eco(obj)
    # npm: left-pad and @scope/tool have one account (alice), big-framework
    # three writers (dave is read-only).
    # Both are alice's: one sole account, holding two packages.
    assert e["npm"]["single_account"] == {"n": 2, "pct": 66.7,
                                          "accounts": 1, "largest": 2}
    assert e["npm"]["shared"]["distinct_accounts"] == 3
    assert e["npm"]["shared"]["top"][0] == {"k": 1, "n": 3, "pct": 100.0}
    assert e["npm"]["scorecard"]["repos"] == 2  # case-folded monorepo
    # PyPI: gone-pkg is missing from the registry and leaves the
    # denominator; numcalc has an organisation and is never single.
    assert (e["pypi"]["measured"], e["pypi"]["missing"]) == (2, 1)
    assert e["pypi"]["single_account"]["n"] == 1
    assert e["pypi"]["team_or_org"]["n"] == 1
    assert e["pypi"]["scorecard"] == {
        **e["pypi"]["scorecard"], "github_packages": 2, "repos": 2,
        "scored": 1}
    # crates.io: serde-lite has one user plus a team; tokio-lite one user.
    assert e["crates"]["single_account"]["n"] == 1
    assert e["crates"]["team_or_org"]["n"] == 1
    # RubyGems: aws-lite is organisation-managed with no listed owner.
    buckets = {b["label"]: b["n"] for b in e["rubygems"]["accounts"]["buckets"]}
    assert buckets["0"] == 1 and buckets["1"] == 1 and buckets["6–10"] == 1
    assert e["rubygems"]["accounts"]["median"] == 1.0
    # rake-lite's only Scorecard result dates from 2022: counted as an old
    # result, not scored.
    assert (e["rubygems"]["scorecard"]["scored"],
            e["rubygems"]["scorecard"]["old_results"]) == (2, 1)
    sr = {b["label"]: b["n"]
          for b in e["rubygems"]["scorecard"]["checks"]["Signed-Releases"]}
    assert sr == {"inconclusive": 1, "0": 0, "1–4": 0, "5–7": 0, "8–10": 1}
    # left-pad's result lacks Signed-Releases: not reported, not zero.
    assert e["npm"]["scorecard"]["not_reported"]["Signed-Releases"] == 1
    assert obj["scorecard_dates"] == {"max_age_days": 45,
                                      "first": "2026-10-19",
                                      "last": "2026-11-02"}
    assert obj["observed"]["first"] == obj["observed"]["last"] == TODAY


def test_output_names_no_package_account_or_repository():
    u, state, _ = full_state()
    text = json.dumps(oss_metrics.build_oss_maintainers(u, state, GEN))
    for p in u.packages:
        assert f'"{p.name}"' not in text
    assert "example" not in text and "alice" not in text


def test_state_round_trip_and_edition_reset(tmp_path):
    u, state, _ = full_state()
    oss_metrics.persist(tmp_path, state, log=lambda _m: None)
    assert oss_metrics.load_state(tmp_path, u, log=lambda _m: None) == state
    state["edition"] = "2025-11"
    oss_metrics.persist(tmp_path, state, log=lambda _m: None)
    fresh = oss_metrics.load_state(tmp_path, u, log=lambda _m: None)
    assert fresh == oss_metrics.empty_state(u)
    oss_metrics.state_path(tmp_path).write_bytes(b"not gzip")
    assert oss_metrics.load_state(tmp_path, u, log=lambda _m: None) == \
        oss_metrics.empty_state(u)


def test_run_stage_offline(tmp_path):
    obj, source, state, state_dir, reason = oss_metrics.run_stage(
        tmp_path, tmp_path / "cache", GEN, offline_fixtures=True,
        log=lambda _m: None)
    assert reason is None
    assert state_dir == tmp_path / "history"
    contracts.validate("oss_maintainers.json", obj)
    assert source == {"fetched_at": GEN, "edition": "2026-11", "packages": 12,
                      "lookups": 21, "failed": 0,
                      "oldest_observation": TODAY}


@pytest.mark.parametrize("n,label", [(0, "0"), (1, "1"), (3, "3"), (4, "4–5"),
                                     (10, "6–10"), (11, "11+"), (40, "11+")])
def test_account_buckets(n, label):
    assert oss_metrics._bucket_accounts(n) == label


@pytest.mark.parametrize("s,label", [(None, None), (-1, "inconclusive"),
                                     (0, "0"), (4, "1–4"), (5, "5–7"),
                                     (8, "8–10"), (10, "8–10")])
def test_score_buckets(s, label):
    assert oss_metrics._bucket_score(s) == label
