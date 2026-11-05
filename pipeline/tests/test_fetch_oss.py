"""fetch_oss + oss_universe: per-registry publish-rights parsers, the
Scorecard parser, the fixture session and the universe file's strictness.
No network."""
from __future__ import annotations

import json

import pytest

from pipeline import fetch_oss, oss_universe
from pipeline.fetch_oss import (FixtureSession, Publishers, account_id,
                                parse_crates_owners, parse_npm_collaborators,
                                parse_pypi_project, parse_rubygems_owners,
                                parse_scorecard)

GH = "git" + "hub.com"


# ------------------------------------------------------------ registries

def test_npm_counts_write_accounts_only():
    p = parse_npm_collaborators({"a": "write", "b": "write", "c": "read"})
    assert p.status == "ok" and len(p.accounts) == 2
    assert p.teams == 0 and p.org is False


@pytest.mark.parametrize("body", [[], {"a": 1}, {"a": "admin"}, {"a": "read"}])
def test_npm_rejects_malformed_or_writerless(body):
    with pytest.raises(ValueError):
        parse_npm_collaborators(body)


def test_pypi_roles_and_organization():
    p = parse_pypi_project({"ownership": {
        "organization": "psf",
        "roles": [{"role": "Owner", "user": "x"},
                  {"role": "Maintainer", "user": "y"},
                  {"role": "Owner", "user": "x"}]}})
    assert len(p.accounts) == 2 and p.org is True
    solo = parse_pypi_project({"ownership": {
        "organization": None, "roles": [{"role": "Owner", "user": "z"}]}})
    assert len(solo.accounts) == 1 and solo.org is False


@pytest.mark.parametrize("body", [
    {"info": {}},                                         # no ownership
    {"ownership": {"roles": [{"role": "Admin", "user": "x"}]}},
    {"ownership": {"organization": None, "roles": []}},  # nobody at all
])
def test_pypi_rejects_unusable_ownership(body):
    with pytest.raises(ValueError):
        parse_pypi_project(body)


def test_crates_separates_users_and_teams():
    p = parse_crates_owners({"users": [
        {"login": "u1", "kind": "user"},
        {"login": "github:org:team", "kind": "team"}]})
    assert len(p.accounts) == 1 and p.teams == 1


def test_crates_rejects_unknown_kind():
    with pytest.raises(ValueError):
        parse_crates_owners({"users": [{"login": "x", "kind": "group"}]})


def test_rubygems_owners_and_organisation_managed():
    p = parse_rubygems_owners([{"id": 1, "handle": "a"}, {"id": 2, "handle": None}])
    assert len(p.accounts) == 2 and p.org is False
    # An organisation-managed gem lists no individual owner.
    org = parse_rubygems_owners([])
    assert org.accounts == () and org.org is True


def test_account_ids_are_per_registry_and_case_folded():
    assert account_id("npm", "Alice") == account_id("npm", "alice")
    assert account_id("npm", "alice") != account_id("pypi", "alice")
    assert len(account_id("npm", "alice")) == 16


# ------------------------------------------------------------ scorecard

def test_scorecard_keeps_four_checks_and_inconclusive():
    card = parse_scorecard({"date": "2026-11-03T07:21:52Z", "score": 6.54,
                            "checks": [{"name": "Maintained", "score": 2},
                                       {"name": "Branch-Protection", "score": -1},
                                       {"name": "License", "score": 10}]})
    assert card["date"] == "2026-11-03"
    assert card["score"] == 6.5
    assert card["checks"] == {"Maintained": 2, "Code-Review": None,
                              "Branch-Protection": -1,
                              "Signed-Releases": None}


@pytest.mark.parametrize("body", [
    {"date": "2026-11-03", "score": 11, "checks": []},
    {"date": "2026-11-03", "score": 5, "checks": [{"name": "Maintained",
                                                   "score": 12}]},
    {"score": 5, "checks": []},
])
def test_scorecard_rejects_out_of_range(body):
    with pytest.raises(ValueError):
        parse_scorecard(body)


# ------------------------------------------------------------ fetch path

class _Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body
        self.headers = {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise OSError(f"HTTP {self.status_code}")


class _Session:
    def __init__(self, answers):
        self.answers = answers
        self.urls = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        return self.answers[url]


def test_fetch_publishers_404_is_missing_not_error():
    url = fetch_oss.publishers_url("npm", "@scope/pkg")
    assert url.endswith("/-/package/%40scope%2Fpkg/collaborators")
    s = _Session({url: _Resp(404)})
    assert fetch_oss.fetch_publishers(s, "npm", "@scope/pkg",
                                      sleep=lambda _: None) == fetch_oss.MISSING


def test_fetch_scorecard_404_is_no_result():
    url = fetch_oss.scorecard_url(f"{GH}/a/b")
    s = _Session({url: _Resp(404)})
    assert fetch_oss.fetch_scorecard(s, f"{GH}/a/b",
                                     sleep=lambda _: None) is None


def test_fetch_retries_then_raises_on_5xx():
    url = fetch_oss.publishers_url("crates", "serde")
    s = _Session({url: _Resp(503)})
    with pytest.raises(OSError):
        fetch_oss.fetch_publishers(s, "crates", "serde",
                                   sleep=lambda _: None, log=lambda _: None)
    assert len(s.urls) == fetch_oss.ATTEMPTS


def test_fixture_session_answers_recorded_urls(tmp_path):
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"https://x/a": {"status": 200, "body": [1]}}))
    s = FixtureSession(path)
    assert s.get("https://x/a").json() == [1]
    assert s.get("https://x/unknown").status_code == 404


def test_publishers_state_round_trip():
    p = Publishers("ok", ("a", "b"), teams=1, org=False)
    assert p.to_state("2026-11-05") == {
        "observed": "2026-11-05", "status": "ok", "accounts": ["a", "b"],
        "teams": 1, "org": False}


# ------------------------------------------------------------ universe

def test_normalize_repo_spellings():
    n = oss_universe.normalize_repo
    assert n(f"git+https://{GH}/x/y.git") == f"{GH}/x/y"
    assert n(f"git@{GH}:x/socket.io.git") == f"{GH}/x/socket.io"
    assert n(f"https://{GH}/a/b/tree/main/pkg") == f"{GH}/a/b"
    assert n(f"http://www.{GH}/A/B#readme") == f"{GH}/A/B"
    assert n("https://gitlab.com/a/b") is None
    assert n(f"https://{GH}/a") is None
    assert n(None) is None


def test_committed_universe_is_valid_and_frozen():
    u = oss_universe.load_universe()
    assert u.edition == oss_universe.EDITION
    assert u.rule_version == oss_universe.RULE_VERSION
    assert u.per_ecosystem == oss_universe.PER_ECOSYSTEM
    for eco in oss_universe.ECOSYSTEMS:
        assert len(u.by_ecosystem(eco)) == oss_universe.PER_ECOSYSTEM


def _doc():
    return json.loads(oss_universe.UNIVERSE_PATH.read_text("utf-8"))


@pytest.mark.parametrize("mutate", [
    lambda d: d["ecosystems"]["npm"].pop(),
    lambda d: d["ecosystems"].pop("rubygems"),
    lambda d: d["ecosystems"]["pypi"].append(dict(d["ecosystems"]["pypi"][0])),
    lambda d: d["ecosystems"]["crates"][0].update(repo="gitlab.com/a/b"),
    lambda d: d["ecosystems"]["npm"][1].update(name=d["ecosystems"]["npm"][0]["name"]),
])
def test_universe_rejects_a_changed_denominator(mutate):
    d = _doc()
    mutate(d)
    with pytest.raises(ValueError):
        oss_universe.parse_universe(d)
