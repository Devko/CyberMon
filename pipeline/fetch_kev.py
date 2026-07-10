"""CISA Known Exploited Vulnerabilities catalog (JSON feed)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


@dataclass
class KevEntry:
    """One KEV catalog entry: the CVE id plus the catalog's own dates,
    ransomware flag, and vendor/product labels."""

    cve_id: str
    date_added: str
    due_date: str | None
    # knownRansomwareCampaignUse ("Known"/"Unknown"); None when the feed
    # omits the field — treated as "Unknown" downstream, never as "Known".
    ransomware_use: str | None = None
    # vendorProject / product as the catalog spells them (may carry stray
    # whitespace — security_products.normalize_vendor handles grouping).
    vendor_project: str = ""
    product: str = ""


@dataclass
class KevData:
    """Parsed KEV catalog: version metadata + the listed CVE ids."""

    catalog_version: str
    count: int
    cve_ids: list[str] = field(default_factory=list, repr=False)
    entries: list[KevEntry] = field(default_factory=list, repr=False)


def parse_kev(obj: dict) -> KevData:
    """Extract catalog version, CVE ids and entries from the KEV document."""
    vulns = [v for v in obj.get("vulnerabilities", [])
             if isinstance(v, dict) and isinstance(v.get("cveID"), str)]
    cve_ids = [v["cveID"] for v in vulns]
    entries = [KevEntry(cve_id=v["cveID"],
                        date_added=str(v.get("dateAdded") or ""),
                        due_date=(v["dueDate"]
                                  if isinstance(v.get("dueDate"), str)
                                  and v["dueDate"] else None),
                        ransomware_use=(v["knownRansomwareCampaignUse"]
                                        if isinstance(
                                            v.get("knownRansomwareCampaignUse"),
                                            str) else None),
                        vendor_project=(v["vendorProject"]
                                        if isinstance(v.get("vendorProject"),
                                                      str) else ""),
                        product=(v["product"]
                                 if isinstance(v.get("product"), str) else ""))
               for v in vulns]
    count = obj.get("count")
    if not isinstance(count, int) or isinstance(count, bool):
        count = len(cve_ids)
    return KevData(catalog_version=str(obj.get("catalogVersion", "unknown")),
                   count=count, cve_ids=cve_ids, entries=entries)


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
