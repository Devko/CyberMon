"""CVE.org / CVE Program organization roster (the CNA partner list).

The CVE federation publishes its **current** roster of participating
organizations, but no history: accreditation dates, onboardings, departures
and scope changes are not recorded anywhere upstream. The roster is the JSON
that powers cve.org's "Partner Information -> List of Partners" page —

    https://raw.githubusercontent.com/CVEProject/cve-website/dev/
        src/assets/data/CNAsList.json

a single ~700 KB array of ~530 org records. (The ``cveawg.mitre.org/api/org``
CVE Services endpoint requires an authenticated ``CVE-API-ORG`` header and is
NOT usable for public aggregates; the ``cve.org/api/?action=getOrgs`` URL the
backlog spot-probed returns only the SPA's HTML shell, not JSON. The
GitHub-hosted ``CNAsList.json`` is the same data the site itself consumes and
is the working public source.)

Upstream shape relied on — each element is::

    {"shortName": "adobe", "cnaID": "CNA-2009-0001",
     "organizationName": "Adobe Systems Incorporated",
     "scope": "Adobe issues only.", "country": "USA",
     "CNA": {"isRoot": false,
             "root": {"shortName": "n/a", "organizationName": "n/a"},
             "type": ["Vendor"],
             "TLR": {"shortName": "mitre", ...},
             "roles": [{"role": "CNA", "helpText": ""}]}, ...}

Fields this module reads (the rest — contact, disclosurePolicy,
securityAdvisories, resources — are ignored): ``shortName`` is the natural
key (unique across the roster; the assigner id CVE records carry — ``cnaID``
is NOT unique, several orgs share one, so it is only an identity attribute
here). ``organizationName`` is the display name; ``scope`` is the org's
stated scope of authority (tracked for scope-change events); ``country``,
``CNA.type`` (Vendor / Open Source / Researcher / CERT / Bug Bounty Provider
/ Hosted Service / Consortium / N/A — an org may claim several), ``CNA.roles``
(CNA / CNA-LR / Root / Top-Level Root / ADP / Secretariat), ``CNA.TLR`` (the
top-level root: mitre or CISA) and ``CNA.root`` (the reporting root) are the
composition dimensions. **No accreditation date is published — that absence
is the whole point of the CNA Roster History module.**

Licensing: the roster is CVE Program data (the CVE List is already an
upstream this site republishes aggregates of); the CVE Program terms permit
reuse of the published data. Only aggregate counts and public org
names/scope are surfaced.

Fetch policy mirrors fetch_ransomwhere: a malformed *document* (not a list,
or empty) raises — an empty roster is a broken fetch, never news — while an
individual record missing its ``shortName`` is skipped (it cannot be keyed).
Transient network blips (HTTP 429/5xx, connection errors) get a bounded retry
(3 attempts, backoff); an exhausted retry still raises, and there is no
carry-forward for this source.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ROSTER_URL = ("https://raw.githubusercontent.com/CVEProject/cve-website/dev/"
              "src/assets/data/CNAsList.json")

USER_AGENT = "CyberMon/1.0 (+https://github.com/Devko/CyberMon)"

_RETRY_STATUSES = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 3


@dataclass
class RosterOrg:
    """One CNA/root organization on the roster, reduced to the fields the
    roster-history module tracks. ``types`` and ``roles`` are sorted tuples
    of the org's claimed classifications (an org may hold several)."""

    short_name: str
    org_name: str
    cna_id: str
    country: str
    scope: str
    types: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    tlr: str = "n/a"
    root: str = "n/a"
    is_root: bool = False

    @property
    def type_label(self) -> str:
        """The org's types joined for display / the event log
        (``"Open Source + Vendor"``); ``"N/A"`` when the roster lists none."""
        return " + ".join(self.types) if self.types else "N/A"


@dataclass
class RosterSnapshot:
    """A parsed roster snapshot: the org count plus the org records."""

    org_count: int
    orgs: list[RosterOrg] = field(default_factory=list, repr=False)


def _clean(value: object) -> str:
    """A trimmed string, or ``""`` for anything that is not a string."""
    return value.strip() if isinstance(value, str) else ""


def _sub_short_name(block: object) -> str:
    """``shortName`` from a nested ``{shortName, organizationName}`` block
    (CNA.root / CNA.TLR), defaulting to ``"n/a"`` when absent."""
    if isinstance(block, dict):
        name = _clean(block.get("shortName"))
        if name:
            return name
    return "n/a"


def parse_roster(obj: object) -> RosterSnapshot:
    """Parse the ``CNAsList.json`` document into a :class:`RosterSnapshot`.

    A non-list or empty document raises ``ValueError`` (a broken fetch, not
    a roster). Records without a usable ``shortName`` are skipped — they
    cannot be keyed — so ``org_count`` reflects the keyed orgs.
    """
    if not isinstance(obj, list) or not obj:
        raise ValueError("cna-roster: expected a non-empty JSON array of orgs")
    orgs: list[RosterOrg] = []
    seen: set[str] = set()
    for i, rec in enumerate(obj):
        if not isinstance(rec, dict):
            raise ValueError(f"cna-roster: orgs[{i}] is not an object")
        short = _clean(rec.get("shortName"))
        if not short or short in seen:
            continue  # unkeyable or duplicate — cannot track it
        seen.add(short)
        cna = rec.get("CNA") if isinstance(rec.get("CNA"), dict) else {}
        raw_types = cna.get("type") if isinstance(cna.get("type"), list) else []
        types = tuple(sorted({t.strip() for t in raw_types
                              if isinstance(t, str) and t.strip()}))
        raw_roles = cna.get("roles") if isinstance(cna.get("roles"),
                                                   list) else []
        roles = tuple(sorted({r["role"].strip() for r in raw_roles
                              if isinstance(r, dict)
                              and isinstance(r.get("role"), str)
                              and r["role"].strip()}))
        orgs.append(RosterOrg(
            short_name=short,
            org_name=_clean(rec.get("organizationName")) or short,
            cna_id=_clean(rec.get("cnaID")),
            country=_clean(rec.get("country")) or "Unknown",
            scope=_clean(rec.get("scope")),
            types=types,
            roles=roles,
            tlr=_sub_short_name(cna.get("TLR")),
            root=_sub_short_name(cna.get("root")),
            is_root=bool(cna.get("isRoot")),
        ))
    if not orgs:
        raise ValueError("cna-roster: document held no keyable org records")
    return RosterSnapshot(org_count=len(orgs), orgs=orgs)


def load_roster_file(path: Path) -> RosterSnapshot:
    """Load a roster snapshot from a local JSON file (fixtures)."""
    return parse_roster(json.loads(path.read_text(encoding="utf-8")))


def _get_with_retry(session, url: str, timeout: float, sleep, log):
    """GET with fetch_ransomwhere's bounded-retry discipline: up to
    ``_MAX_ATTEMPTS`` attempts, backing off on 429/5xx statuses and
    connection errors. The final failure raises exactly as an unretried call
    would — the retry absorbs blips, it never softens the loud-failure
    policy (there is no carry-forward for this source)."""
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        last = attempt == _MAX_ATTEMPTS
        try:
            resp = session.get(url, timeout=timeout,
                               headers={"User-Agent": USER_AGENT})
        except OSError as exc:  # requests exceptions subclass OSError
            if last:
                raise
            message = f"request failed: {exc!r}"
        else:
            if last or resp.status_code not in _RETRY_STATUSES:
                resp.raise_for_status()
                return resp
            message = f"HTTP {resp.status_code}"
        backoff = 15.0 * attempt
        log(f"  cna-roster: {message} for {url}; retrying in "
            f"{backoff:.0f}s (attempt {attempt}/{_MAX_ATTEMPTS})")
        sleep(backoff)


def fetch_roster(session=None, timeout: float = 120.0,
                 sleep=time.sleep, log: Callable[[str], None] = print
                 ) -> RosterSnapshot:
    """Download and parse the current CVE.org organization roster. Transient
    failures are retried (see :func:`_get_with_retry`); the last failure
    raises unchanged."""
    import requests

    session = session or requests.Session()
    resp = _get_with_retry(session, ROSTER_URL, timeout, sleep, log)
    return parse_roster(resp.json())
