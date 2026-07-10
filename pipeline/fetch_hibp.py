"""Have I Been Pwned public breach catalog (JSON feed, no API key).

One GET returns every breach HIBP has ever cataloged, with the breach's
own date (``BreachDate``, self-reported, usually rounded to the first of a
month), the date HIBP cataloged it (``AddedDate``), the account count
(``PwnCount``), the leaked data classes, and the classification flags the
cohort rule in :mod:`pipeline.breach_metrics` keys off. HIBP requires a
User-Agent and attribution (handled in the site's shared footer copy).

Failures are loud on purpose: no carry-forward machinery. If HIBP is down,
the run fails and nothing stale is deployed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .fetch_market import USER_AGENT

HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches"


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


def fetch_hibp(session=None, timeout: float = 60.0) -> HibpData:
    """Download and parse the current HIBP breach catalog."""
    import requests

    session = session or requests.Session()
    resp = session.get(HIBP_URL, timeout=timeout,
                       headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    return parse_hibp(resp.json())
