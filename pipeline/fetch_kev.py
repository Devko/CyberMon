"""CISA Known Exploited Vulnerabilities catalog (JSON feed)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


@dataclass
class KevData:
    """Parsed KEV catalog: version metadata + the listed CVE ids."""

    catalog_version: str
    count: int
    cve_ids: list[str] = field(default_factory=list, repr=False)


def parse_kev(obj: dict) -> KevData:
    """Extract catalog version and CVE ids from the KEV JSON document."""
    cve_ids = [v["cveID"] for v in obj.get("vulnerabilities", [])
               if isinstance(v, dict) and isinstance(v.get("cveID"), str)]
    count = obj.get("count")
    if not isinstance(count, int) or isinstance(count, bool):
        count = len(cve_ids)
    return KevData(catalog_version=str(obj.get("catalogVersion", "unknown")),
                   count=count, cve_ids=cve_ids)


def load_kev_file(path: Path) -> KevData:
    """Load KEV data from a local JSON file."""
    return parse_kev(json.loads(path.read_text(encoding="utf-8")))


def fetch_kev(session=None, timeout: float = 60.0) -> KevData:
    """Download and parse the current KEV catalog."""
    import requests

    session = session or requests.Session()
    resp = session.get(KEV_URL, timeout=timeout)
    resp.raise_for_status()
    return parse_kev(resp.json())
