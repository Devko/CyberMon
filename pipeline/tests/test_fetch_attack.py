"""fetch_attack unit tests: index parsing, STIX stat extraction, churn
diffing, sync bookkeeping (what gets fetched when), and the state
round-trips (save/load, reconstruct-from-published-output). All offline —
the fixture index resolves its bundle URLs against local files."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import fetch_attack
from pipeline.fetch_attack import (churn_counts, load_state, parse_index,
                                   reconstruct_state, save_state, sync_state,
                                   technique_flags, version_key,
                                   version_stats)

FIXTURES = Path(__file__).parent / "fixtures" / "attack"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def local_bundle(url: str) -> dict:
    return load_fixture(url.rsplit("/", 1)[-1])


def fixture_index_versions() -> list[dict]:
    return parse_index(load_fixture("index.json"))


def synced_state() -> dict:
    return sync_state(None, fixture_index_versions(), local_bundle,
                      last_sync="2026-07-09T00:00:00Z", log=lambda _: None)


# ------------------------------------------------------------- index parsing

def test_parse_index_selects_enterprise_and_sorts_ascending():
    versions = fixture_index_versions()
    # The mobile decoy collection is listed first in the fixture and must
    # never win; the enterprise versions are listed newest-first and must
    # come out oldest-first.
    assert [v["version"] for v in versions] == ["1.0", "2.0"]
    assert versions[0]["released"] == "2018-01-17"  # date part of modified
    assert versions[1]["released"] == "2018-10-17"
    assert versions[1]["url"].endswith("enterprise-attack-2.0.json")


def test_parse_index_fails_loudly_without_enterprise_collection():
    with pytest.raises(ValueError, match="Enterprise ATT&CK"):
        parse_index({"collections": [{"name": "Mobile ATT&CK",
                                      "versions": []}]})


def test_parse_index_fails_loudly_on_unparsable_version():
    index = {"collections": [{"name": "Enterprise ATT&CK", "versions": [
        {"version": "v1-beta", "url": "u",
         "modified": "2018-01-17T00:00:00Z"}]}]}
    with pytest.raises(ValueError):
        parse_index(index)


def test_version_key_orders_numerically_not_lexically():
    assert version_key("10.1") > version_key("9.2")
    assert sorted(["10.0", "2.0", "9.1"], key=version_key) == \
        ["2.0", "9.1", "10.0"]


# ------------------------------------------------------------ stat extraction

def test_version_stats_counts_only_active_objects():
    # v1.0: t0 is deprecated, tl1 is revoked — neither is active; the
    # relationship and x-mitre-tactic objects are out of scope entirely.
    assert version_stats(load_fixture("enterprise-attack-1.0.json")) == {
        "techniques": 3, "subtechniques": 1, "groups": 1, "software": 1}


def test_version_stats_missing_subtechnique_flag_means_technique():
    # v2.0's t5 has no x_mitre_is_subtechnique key at all -> technique.
    assert version_stats(load_fixture("enterprise-attack-2.0.json")) == {
        "techniques": 2, "subtechniques": 2, "groups": 2, "software": 2}


def test_technique_flags_covers_all_attack_patterns_active_or_not():
    flags = technique_flags(load_fixture("enterprise-attack-1.0.json"))
    assert len(flags) == 5  # t0, t1, t2, t3, s1 — deprecated t0 included
    assert flags["attack-pattern--00000000-0000-0000-0000-0000000000t0"] == \
        {"deprecated": True, "revoked": False}
    assert not any(k.startswith(("intrusion-set", "malware", "tool"))
                   for k in flags)


# --------------------------------------------------------------- churn diffs

def test_churn_counts_fixture_release_pair():
    prev = technique_flags(load_fixture("enterprise-attack-1.0.json"))
    cur = technique_flags(load_fixture("enterprise-attack-2.0.json"))
    # added: s2, t4, t5 (t4 arrives already deprecated -> added only);
    # deprecated: t2 (t0 was already deprecated in 1.0 — never re-counted);
    # revoked: t3.
    assert churn_counts(prev, cur) == {"added": 3, "deprecated": 1,
                                       "revoked": 1}


def test_churn_counts_empty_diff():
    flags = technique_flags(load_fixture("enterprise-attack-1.0.json"))
    assert churn_counts(flags, flags) == {"added": 0, "deprecated": 0,
                                          "revoked": 0}


# ----------------------------------------------------------------------- sync

def test_sync_from_empty_state_backfills_every_version():
    state = synced_state()
    assert state["version"] == fetch_attack.STATE_VERSION
    assert state["last_sync"] == "2026-07-09T00:00:00Z"
    assert state["versions"]["1.0"] == {
        "released": "2018-01-17", "techniques": 3, "subtechniques": 1,
        "groups": 1, "software": 1, "churn": None}
    assert state["versions"]["2.0"] == {
        "released": "2018-10-17", "techniques": 2, "subtechniques": 2,
        "groups": 2, "software": 2, "churn": {"added": 3, "deprecated": 1,
                                              "revoked": 1}}


def test_sync_with_complete_state_fetches_nothing():
    state = synced_state()

    def _explode(url):
        raise AssertionError(f"unexpected bundle fetch: {url}")

    resynced = sync_state(state, fixture_index_versions(), _explode,
                          last_sync="2026-07-10T00:00:00Z",
                          log=lambda _: None)
    assert resynced["versions"] == state["versions"]
    assert resynced["last_sync"] == "2026-07-10T00:00:00Z"


def test_sync_new_version_fetches_it_plus_predecessor_for_the_diff():
    # State knows only 1.0 (its technique ids are deliberately NOT kept),
    # the index also lists 2.0: the sync must fetch 2.0 AND re-fetch 1.0
    # to diff by STIX id — and nothing more.
    state = synced_state()
    del state["versions"]["2.0"]
    fetched: list[str] = []

    def _tracking(url):
        fetched.append(url.rsplit("/", 1)[-1])
        return local_bundle(url)

    resynced = sync_state(state, fixture_index_versions(), _tracking,
                          last_sync="x", log=lambda _: None)
    assert sorted(fetched) == ["enterprise-attack-1.0.json",
                               "enterprise-attack-2.0.json"]
    assert resynced["versions"] == synced_state()["versions"]


def test_sync_drops_versions_the_index_no_longer_lists():
    state = synced_state()
    state["versions"]["99.0"] = state["versions"]["1.0"]
    resynced = sync_state(state, fixture_index_versions(),
                          local_bundle, last_sync="x", log=lambda _: None)
    assert "99.0" not in resynced["versions"]


def test_sync_discards_unrecognized_state_version():
    state = synced_state()
    state["version"] = 999
    fetched: list[str] = []

    def _tracking(url):
        fetched.append(url)
        return local_bundle(url)

    resynced = sync_state(state, fixture_index_versions(), _tracking,
                          last_sync="x", log=lambda _: None)
    assert len(fetched) == 2  # full backfill: the old state was unusable
    assert resynced["versions"] == synced_state()["versions"]


def test_sync_refetches_malformed_cached_entry():
    state = synced_state()
    state["versions"]["2.0"]["techniques"] = "lots"  # malformed -> dropped
    resynced = sync_state(state, fixture_index_versions(), local_bundle,
                          last_sync="x", log=lambda _: None)
    assert resynced["versions"]["2.0"]["techniques"] == 2


def test_sync_refreshes_released_dates_from_the_index():
    state = synced_state()
    index_versions = fixture_index_versions()
    index_versions[0]["released"] = "2018-02-02"  # upstream corrected it

    def _explode(url):
        raise AssertionError("date refresh must not cost a fetch")

    resynced = sync_state(state, index_versions, _explode, last_sync="x",
                          log=lambda _: None)
    assert resynced["versions"]["1.0"]["released"] == "2018-02-02"


# ------------------------------------------------------------------ state I/O

def test_save_and_load_state_round_trip(tmp_path):
    state = synced_state()
    save_state(tmp_path, state)
    assert load_state(tmp_path, log=lambda _: None) == state


def test_load_state_absent_or_unreadable_returns_none(tmp_path):
    assert load_state(tmp_path, log=lambda _: None) is None
    (tmp_path / fetch_attack.STATE_FILENAME).write_text("{nope",
                                                        encoding="utf-8")
    assert load_state(tmp_path, log=lambda _: None) is None


def test_reconstruct_state_round_trips_the_published_output(tmp_path):
    # THE lossless-reconstruction guarantee (docs/data-contracts.md):
    # state -> build_attack_churn -> reconstruct_state == same versions.
    from pipeline.attack_metrics import build_attack_churn

    state = synced_state()
    obj = build_attack_churn(state, "2026-07-09T00:00:00Z")
    (tmp_path / "attack_churn.json").write_text(json.dumps(obj),
                                                encoding="utf-8")
    rebuilt = reconstruct_state(tmp_path, log=lambda _: None)
    assert rebuilt is not None
    assert rebuilt["versions"] == state["versions"]
    assert rebuilt["last_sync"] == "2026-07-09T00:00:00Z"
    # ... and a sync against the same index needs zero fetches afterwards.
    resynced = sync_state(rebuilt, fixture_index_versions(),
                          lambda url: (_ for _ in ()).throw(AssertionError),
                          last_sync="x", log=lambda _: None)
    assert resynced["versions"] == state["versions"]


def test_reconstruct_state_absent_or_unusable_returns_none(tmp_path):
    assert reconstruct_state(tmp_path, log=lambda _: None) is None
    (tmp_path / "attack_churn.json").write_text('{"versions": "nope"}',
                                                encoding="utf-8")
    assert reconstruct_state(tmp_path, log=lambda _: None) is None
