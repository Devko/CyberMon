"""Who can publish each package, and how its repository scores: the reads
behind Open-Source Maintainers (module 30).

Two kinds of lookup, both for the fixed package list in
:mod:`pipeline.oss_universe`:

**Publish rights, from each registry's own records.** "Maintainer" means
something different in every registry, so each one is read and defined on
its own terms and never pooled:

* **npm** — accounts with write access, from
  ``registry.npmjs.org/-/package/<name>/collaborators`` (the list ``npm
  access list collaborators`` prints). It matched the package document's
  ``maintainers`` field for all 24 packages compared on 2026-11-05 and is
  a few hundred bytes where the document is up to 16 MB. Organisation
  teams are expanded into their member accounts by the registry.
* **PyPI** — the project's role holders (Owner or Maintainer) from the
  JSON API's ``ownership.roles``, plus ``ownership.organization``. Members
  of an owning organisation's teams are not listed per project, so a
  project with an organisation is flagged and never counted as
  single-account.
* **crates.io** — the crate's owners from ``/api/v1/crates/<name>/owners``:
  user accounts, and GitHub teams (``kind: team``), which are counted
  separately because a team's size is not published.
* **RubyGems** — the gem's owners from ``/api/v1/gems/<name>/owners.json``.
  A gem that a RubyGems organisation manages comes back with an empty
  owner list (aws-sdk, whose page reads "Managed By AWS", on 2026-11-05);
  it is recorded as organisation-managed with no individual owner.

Accounts are counted, not people: a bot or shared organisation account is
one account. Account names never leave this module — each is reduced to a
short unsalted hash (``sha256("<eco>:<login>")[:16]``) so the stage can
tell when one account holds rights on several packages; the output carries
counts only.

**OpenSSF Scorecard results** for the package's GitHub repository, from
``api.scorecard.dev/projects/github.com/<owner>/<repo>``: the overall
score and four checks (:data:`CHECKS`). A 404 means Scorecard has no
result for that repository; it is recorded as such, never as a zero.

Terms (checked 2026-11-05): npm's crawler policy allows metadata access at
up to one request per second (the stage paces npm at that rate); PyPI's
JSON API is its documented public interface; crates.io asks for at most
one request per second with an identifying User-Agent (paced at that
rate); RubyGems' API is public and rate-limited at 10 requests per second
(paced well below). Scorecard's REST API data is CDLA-Permissive-2.0
(github.com/ossf/scorecard README). Only aggregate counts are published.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import quote

from .fetch_http import get_with_retry

SCORECARD_API = "https://api.scorecard.dev/projects/"
CHECKS = ("Maintained", "Code-Review", "Branch-Protection", "Signed-Releases")

# Seconds between requests to one host (politeness, see the terms above).
PACE = {"npm": 1.0, "pypi": 0.25, "crates": 1.0, "rubygems": 0.25,
        "scorecard": 0.25}

# Bounded retry: a few attempts with a short backoff. A host that keeps
# failing is dropped for the night by the stage's circuit breaker, so a
# dead upstream costs seconds, not the night.
ATTEMPTS = 3
BACKOFF = 5.0
TIMEOUT = 60.0


def account_id(eco: str, login: str) -> str:
    """A stable short id for one registry account (never published)."""
    return hashlib.sha256(f"{eco}:{login.strip().lower()}".encode()
                          ).hexdigest()[:16]


@dataclass(frozen=True)
class Publishers:
    """Who can publish one package, per its registry. ``status`` is
    ``"ok"`` or ``"missing"`` (the registry no longer has the package)."""

    status: str
    accounts: tuple[str, ...] = ()
    teams: int = 0
    org: bool = False

    def to_state(self, observed: str) -> dict:
        return {"observed": observed, "status": self.status,
                "accounts": list(self.accounts), "teams": self.teams,
                "org": self.org}


MISSING = Publishers(status="missing")


def _accounts(eco: str, logins) -> tuple[str, ...]:
    ids = {account_id(eco, x) for x in logins}
    return tuple(sorted(ids))


def parse_npm_collaborators(obj: object) -> Publishers:
    if not isinstance(obj, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in obj.items()):
        raise ValueError("npm collaborators: expected {login: permission}")
    unknown = {v for v in obj.values()} - {"write", "read"}
    if unknown:
        raise ValueError(f"npm collaborators: unknown permission {unknown}")
    writers = [k for k, v in obj.items() if v == "write"]
    if not writers:
        raise ValueError("npm collaborators: no account with write access")
    return Publishers("ok", _accounts("npm", writers))


def parse_pypi_project(obj: object) -> Publishers:
    own = obj.get("ownership") if isinstance(obj, dict) else None
    if not isinstance(own, dict) or not isinstance(own.get("roles"), list):
        raise ValueError("pypi: project JSON has no ownership.roles")
    users = []
    for role in own["roles"]:
        if not isinstance(role, dict) or role.get("role") not in (
                "Owner", "Maintainer") or not isinstance(role.get("user"), str):
            raise ValueError(f"pypi: unrecognised role entry {role!r}")
        users.append(role["user"])
    org = own.get("organization")
    if org is not None and not isinstance(org, str):
        raise ValueError(f"pypi: unusable organization {org!r}")
    if not users and not org:
        raise ValueError("pypi: project lists no role holder and no "
                         "organization")
    return Publishers("ok", _accounts("pypi", users), org=bool(org))


def parse_crates_owners(obj: object) -> Publishers:
    users = obj.get("users") if isinstance(obj, dict) else None
    if not isinstance(users, list):
        raise ValueError("crates.io owners: expected {users: [...]}")
    logins, teams = [], 0
    for u in users:
        if not isinstance(u, dict) or not isinstance(u.get("login"), str):
            raise ValueError(f"crates.io owners: unusable entry {u!r}")
        if u.get("kind") == "user":
            logins.append(u["login"])
        elif u.get("kind") == "team":
            teams += 1
        else:
            raise ValueError(f"crates.io owners: unknown kind {u.get('kind')!r}")
    if not logins and not teams:
        raise ValueError("crates.io owners: crate lists no owner")
    return Publishers("ok", _accounts("crates", logins), teams=teams)


def parse_rubygems_owners(obj: object) -> Publishers:
    if not isinstance(obj, list):
        raise ValueError("rubygems owners: expected a list")
    logins = []
    for u in obj:
        if not isinstance(u, dict):
            raise ValueError(f"rubygems owners: unusable entry {u!r}")
        handle = u.get("handle")
        ident = handle if isinstance(handle, str) and handle else u.get("id")
        if ident is None or ident == "":
            raise ValueError(f"rubygems owners: owner without handle or id")
        logins.append(str(ident))
    # An empty list is what the API returns for an organisation-managed
    # gem: no individual owner is listed, the organisation holds the rights.
    return Publishers("ok", _accounts("rubygems", logins), org=not logins)


PARSERS: dict[str, Callable[[object], Publishers]] = {
    "npm": parse_npm_collaborators,
    "pypi": parse_pypi_project,
    "crates": parse_crates_owners,
    "rubygems": parse_rubygems_owners,
}


def publishers_url(eco: str, name: str) -> str:
    if eco == "npm":
        return ("https://registry.npmjs.org/-/package/"
                f"{quote(name, safe='')}/collaborators")
    if eco == "pypi":
        return f"https://pypi.org/pypi/{quote(name, safe='')}/json"
    if eco == "crates":
        return f"https://crates.io/api/v1/crates/{quote(name, safe='')}/owners"
    if eco == "rubygems":
        return ("https://rubygems.org/api/v1/gems/"
                f"{quote(name, safe='')}/owners.json")
    raise KeyError(eco)


def scorecard_url(repo: str) -> str:
    return SCORECARD_API + repo


def parse_scorecard(obj: object) -> dict:
    """The parts of a Scorecard result the module reads: result date,
    overall score and the :data:`CHECKS` scores (-1 = inconclusive, as
    Scorecard reports it; a check missing from the result is None)."""
    if not isinstance(obj, dict):
        raise ValueError("scorecard: expected an object")
    date = obj.get("date")
    score = obj.get("score")
    checks = obj.get("checks")
    if not isinstance(date, str) or len(date) < 10:
        raise ValueError(f"scorecard: unusable date {date!r}")
    if isinstance(score, bool) or not isinstance(score, (int, float)) \
            or not -1 <= score <= 10:
        raise ValueError(f"scorecard: unusable score {score!r}")
    if not isinstance(checks, list):
        raise ValueError("scorecard: checks is not a list")
    found: dict[str, int | None] = dict.fromkeys(CHECKS)
    for c in checks:
        if not isinstance(c, dict):
            raise ValueError("scorecard: check entry is not an object")
        name = c.get("name")
        if name in found:
            s = c.get("score")
            if isinstance(s, bool) or not isinstance(s, int) \
                    or not -1 <= s <= 10:
                raise ValueError(f"scorecard: {name} score {s!r}")
            found[name] = s
    return {"date": date[:10], "score": round(float(score), 1),
            "checks": found}


# ------------------------------------------------------------- the fetch

class HostDown(Exception):
    """Raised for lookups skipped because their host failed repeatedly."""


@dataclass
class FetchStats:
    lookups: int = 0
    failed: int = 0
    skipped_hosts: set = field(default_factory=set)


def _get_json(session, url: str, label: str, *, sleep, log):
    """(status, body) for a JSON GET: 404 -> (404, None); other errors
    raise after the bounded retry."""
    resp = get_with_retry(session, url, label=label, timeout=TIMEOUT,
                          attempts=ATTEMPTS, backoff=BACKOFF, sleep=sleep,
                          log=log, raise_for_status=False)
    if resp.status_code == 404:
        return 404, None
    resp.raise_for_status()
    return resp.status_code, resp.json()


def fetch_publishers(session, eco: str, name: str, *, sleep=time.sleep,
                     log: Callable[[str], None] = print) -> Publishers:
    status, body = _get_json(session, publishers_url(eco, name),
                             f"oss/{eco}", sleep=sleep, log=log)
    if status == 404:
        return MISSING
    return PARSERS[eco](body)


def fetch_scorecard(session, repo: str, *, sleep=time.sleep,
                    log: Callable[[str], None] = print) -> dict | None:
    status, body = _get_json(session, scorecard_url(repo), "oss/scorecard",
                             sleep=sleep, log=log)
    if status == 404:
        return None
    return parse_scorecard(body)


# ------------------------------------------------------- offline fixtures

class _FixtureResponse:
    def __init__(self, status: int, body):
        self.status_code = status
        self._body = body
        self.headers: dict = {}

    def json(self):
        return self._body

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise OSError(f"fixture HTTP {self.status_code}")


class FixtureSession:
    """A session that answers from a recorded ``{url: {status, body}}``
    map (pipeline/tests/fixtures/oss/responses.json). An unrecorded URL is
    a 404, which is what the registries answer for an unknown package."""

    def __init__(self, path: Path):
        self.responses = json.loads(Path(path).read_text(encoding="utf-8"))

    def get(self, url, **_kwargs):
        hit = self.responses.get(url)
        if hit is None:
            return _FixtureResponse(404, None)
        return _FixtureResponse(int(hit["status"]), hit.get("body"))
