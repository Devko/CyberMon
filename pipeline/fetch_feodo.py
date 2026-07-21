"""abuse.ch Feodo Tracker botnet C2 blocklist (the Botnet Weather feed).

Feodo Tracker publishes a live blocklist of botnet command-and-control
servers (Dridex, Emotet/Heodo, TrickBot, QakBot, BazarLoader, Pikabot, ...)
— only the **current** picture, never a series. The Botnet Weather module
snapshots it nightly and keeps the count history. Source:

    https://feodotracker.abuse.ch/downloads/ipblocklist.json

a small JSON array (single digits on quiet days — normal, and itself the
story) of per-C2 records::

    {"ip_address": "203.0.113.7", "port": 443, "status": "online",
     "hostname": null, "as_number": 64496, "as_name": "EXAMPLE-AS",
     "country": "US", "first_seen": "2025-12-30 13:56:31",
     "last_online": "2026-03-12", "malware": "QakBot"}

Fields this module reads: ``ip_address``+``port`` key an entry (the address
itself is never republished — the site renders aggregates only);
``status`` is ``online`` (answered like a botnet C2 on the tracker's last
probe) or ``offline`` (listed but dark); ``malware`` is the family;
``first_seen`` dates the infrastructure (the age chart); ``country`` /
``as_number`` / ``as_name`` are the composition dimensions. ``hostname``
and ``last_online`` are ignored.

**An empty array is a valid snapshot, not a broken fetch** — unlike the
CNA roster, where an empty document can only be an upstream failure. The
tracker's own FAQ documents the empty state as the intended result of
law-enforcement takedowns (Emotet 2021, Operation Endgame 2024): "The
Feodo Tracker datasets are currently empty thanks to various successful
takedowns". Recording that zero is exactly the module's job. The
broken-fetch guard is therefore *structural*: a non-array document, a
malformed entry, an unrecognized ``status`` or an unparseable
``first_seen`` raises loudly, and transient network blips (HTTP 429/5xx,
connection errors) get a bounded retry — an exhausted retry still raises,
and nothing is appended to the history on any failure.

Licensing / terms (checked live 2026-07-21): the endpoint is public — no
auth-key (abuse.ch's authenticated-platform terms cover their query APIs;
the blocklist downloads are offered openly and the page recommends polling
them every 5–15 minutes). The blocklist page's own Terms of Services state
all Feodo Tracker datasets "can be used for both, commercial and
non-commercial purpose without any limitations (CC0)". One nightly fetch
of a ~2 KB file is far inside fair use; the house User-Agent identifies
the project.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

USER_AGENT = "CyberMon/1.0 (+https://github.com/Devko/CyberMon)"

STATUSES = ("online", "offline")

_RETRY_STATUSES = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 3


@dataclass
class C2Entry:
    """One tracked C2 server, reduced to the fields Botnet Weather uses.
    The ip/port pair is kept only as the dedup key — it never reaches the
    emitted JSON (aggregates only)."""

    ip: str
    port: int
    status: str
    family: str
    first_seen: str          # YYYY-MM-DD (date part of the upstream stamp)
    country: str = "Unknown"
    as_name: str = "Unknown"
    as_number: int | None = None

    @property
    def online(self) -> bool:
        return self.status == "online"


@dataclass
class C2Snapshot:
    """A parsed blocklist snapshot. ``entry_count`` may be zero — the
    tracker's documented empty state, and a reading this module records."""

    entry_count: int
    entries: list[C2Entry] = field(default_factory=list, repr=False)

    @property
    def online_count(self) -> int:
        return sum(1 for e in self.entries if e.online)


def _clean(value: object) -> str:
    """A trimmed string, or ``""`` for anything that is not a string."""
    return value.strip() if isinstance(value, str) else ""


def _first_seen_date(value: object, path: str) -> str:
    """The date part of an upstream ``first_seen`` stamp
    (``"2025-12-30 13:56:31"`` -> ``"2025-12-30"``). Malformed stamps
    raise — the age chart depends on this field."""
    text = _clean(value)
    date = text[:10]
    if len(date) == 10 and date[4] == "-" and date[7] == "-" \
            and date[:4].isdigit() and date[5:7].isdigit() \
            and date[8:10].isdigit():
        return date
    raise ValueError(f"feodo: {path}: unparseable first_seen {value!r}")


def parse_blocklist(obj: object) -> C2Snapshot:
    """Parse the ``ipblocklist.json`` document into a :class:`C2Snapshot`.

    A non-list document raises ``ValueError``; an EMPTY list is a valid
    snapshot (see module docstring — the tracker's documented post-takedown
    state). Every entry is validated strictly: this feed is tiny and feeds
    an irreplaceable history, so a malformed entry is a broken fetch, never
    something to paper over. Duplicate ip:port pairs are collapsed (first
    occurrence wins).
    """
    if not isinstance(obj, list):
        raise ValueError("feodo: expected a JSON array of C2 entries")
    entries: list[C2Entry] = []
    seen: set[tuple[str, int]] = set()
    for i, rec in enumerate(obj):
        path = f"entries[{i}]"
        if not isinstance(rec, dict):
            raise ValueError(f"feodo: {path} is not an object")
        ip = _clean(rec.get("ip_address"))
        if not ip:
            raise ValueError(f"feodo: {path}: missing ip_address")
        port = rec.get("port")
        if isinstance(port, bool) or not isinstance(port, int):
            raise ValueError(f"feodo: {path}: unusable port {port!r}")
        status = _clean(rec.get("status"))
        if status not in STATUSES:
            # Status semantics matter (online = the "active" count); a new
            # upstream state must be looked at, not silently bucketed.
            raise ValueError(f"feodo: {path}: unrecognized status {status!r}")
        family = _clean(rec.get("malware"))
        if not family:
            raise ValueError(f"feodo: {path}: missing malware family")
        as_number = rec.get("as_number")
        if isinstance(as_number, bool) or not isinstance(as_number, int):
            as_number = None
        key = (ip, port)
        if key in seen:
            continue
        seen.add(key)
        entries.append(C2Entry(
            ip=ip,
            port=port,
            status=status,
            family=family,
            first_seen=_first_seen_date(rec.get("first_seen"), path),
            country=_clean(rec.get("country")) or "Unknown",
            as_name=_clean(rec.get("as_name")) or "Unknown",
            as_number=as_number,
        ))
    return C2Snapshot(entry_count=len(entries), entries=entries)


def load_blocklist_file(path: Path) -> C2Snapshot:
    """Load a blocklist snapshot from a local JSON file (fixtures)."""
    return parse_blocklist(json.loads(path.read_text(encoding="utf-8")))


def _get_with_retry(session, url: str, timeout: float, sleep, log):
    """GET with the fetch_cna_roster bounded-retry discipline: up to
    ``_MAX_ATTEMPTS`` attempts, backing off on 429/5xx statuses and
    connection errors. The final failure raises exactly as an unretried
    call would — the retry absorbs blips, it never softens the
    loud-failure policy (there is no carry-forward for this source)."""
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
        log(f"  feodo: {message} for {url}; retrying in "
            f"{backoff:.0f}s (attempt {attempt}/{_MAX_ATTEMPTS})")
        sleep(backoff)


def fetch_blocklist(session=None, timeout: float = 120.0,
                    sleep=time.sleep, log: Callable[[str], None] = print
                    ) -> C2Snapshot:
    """Download and parse the current Feodo Tracker C2 blocklist. Transient
    failures are retried (see :func:`_get_with_retry`); the last failure
    raises unchanged."""
    import requests

    session = session or requests.Session()
    resp = _get_with_retry(session, FEODO_URL, timeout, sleep, log)
    return parse_blocklist(resp.json())
