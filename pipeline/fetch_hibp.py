"""Have I Been Pwned public breach catalog (JSON feed, no API key).

One GET returns every breach HIBP has ever cataloged, with the breach's
own date (``BreachDate``, self-reported, usually rounded to the first of a
month), the date HIBP cataloged it (``AddedDate``), the account count
(``PwnCount``), the leaked data classes, and the classification flags the
cohort rule in :mod:`pipeline.breach_metrics` keys off. HIBP requires a
User-Agent and attribution (handled in the site's shared footer copy).

Failures are loud on purpose: transient blips (HTTP 429/5xx, connection
errors) get a bounded retry (3 attempts, backoff), but there is no
carry-forward machinery — if HIBP stays down, the run fails and nothing
stale is deployed.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .fetch_market import USER_AGENT

HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches"

_RETRY_STATUSES = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 3


@dataclass
class HibpBreach:
    """One cataloged breach: dates, size, data classes, cohort flags."""

    name: str
    breach_date: str          # "YYYY-MM-DD"; "" when the feed omits it
    added_date: str           # ISO timestamp; "" when the feed omits it
    pwn_count: int            # 0 when absent/malformed
    data_classes: list[str] = field(default_factory=list)
    is_fabricated: bool = False
    is_spam_list: bool = False
    is_malware: bool = False
    is_stealer_log: bool = False


@dataclass
class HibpData:
    """Parsed HIBP catalog: raw feed size + the parsed breach entries."""

    breach_count: int
    breaches: list[HibpBreach] = field(default_factory=list, repr=False)


def _flag(entry: dict, key: str) -> bool:
    return entry.get(key) is True


def parse_hibp(obj: list) -> HibpData:
    """Extract breach entries from the HIBP breaches document."""
    if not isinstance(obj, list):
        raise ValueError(
            f"HIBP breaches feed: expected a JSON array, got {type(obj).__name__}")
    breaches = []
    for entry in obj:
        if not isinstance(entry, dict) or not isinstance(entry.get("Name"), str):
            continue
        pwn_count = entry.get("PwnCount")
        if isinstance(pwn_count, bool) or not isinstance(pwn_count, int) \
                or pwn_count < 0:
            pwn_count = 0
        classes = [c for c in entry.get("DataClasses") or []
                   if isinstance(c, str) and c]
        breaches.append(HibpBreach(
            name=entry["Name"],
            breach_date=str(entry.get("BreachDate") or ""),
            added_date=str(entry.get("AddedDate") or ""),
            pwn_count=pwn_count,
            data_classes=classes,
            is_fabricated=_flag(entry, "IsFabricated"),
            is_spam_list=_flag(entry, "IsSpamList"),
            is_malware=_flag(entry, "IsMalware"),
            is_stealer_log=_flag(entry, "IsStealerLog"),
        ))
    return HibpData(breach_count=len(breaches), breaches=breaches)


def load_hibp_file(path: Path) -> HibpData:
    """Load HIBP breach data from a local JSON file (fixtures)."""
    return parse_hibp(json.loads(path.read_text(encoding="utf-8")))


def _get_with_retry(session, url: str, timeout: float, sleep, log):
    """GET with fetch_attack's bounded-retry discipline: up to
    ``_MAX_ATTEMPTS`` attempts, backing off on 429/5xx statuses and
    connection errors. The final failure raises exactly as an unretried
    call would — the retry absorbs blips, it never softens the
    loud-failure policy."""
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
        log(f"  hibp: {message} for {url}; retrying in {backoff:.0f}s "
            f"(attempt {attempt}/{_MAX_ATTEMPTS})")
        sleep(backoff)


def fetch_hibp(session=None, timeout: float = 60.0,
               sleep=time.sleep, log=print) -> HibpData:
    """Download and parse the current HIBP breach catalog. Transient
    failures are retried (see :func:`_get_with_retry`); the last failure
    raises unchanged."""
    import requests

    session = session or requests.Session()
    resp = _get_with_retry(session, HIBP_URL, timeout, sleep, log)
    return parse_hibp(resp.json())
