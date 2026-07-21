"""Public proof-of-concept corpora: Exploit-DB, Metasploit, Nuclei.

Three exploit trackers, all public, all shipping their FULL history in one
file — so, like the APNIC stage, this module refetches statelessly every
night (no accumulated state, no committed history file). Downloads are
cached per UTC day in ``.cache/poc/`` so same-day re-runs are free.

* **Exploit-DB index CSV** (:data:`EXPLOITDB_URL`, ~10 MB) — one row per
  hosted exploit. ``codes`` is a semicolon-separated reference list where
  CVE ids live among OSVDB/EDB ids; ``date_published`` is the date OffSec
  records the exploit as published (usually its original publication),
  ``date_added`` when it entered the archive. This module dates a PoC by
  ``date_published`` — the earlier, more meaningful claim — and documents
  the choice in the page methodology.
* **Metasploit module metadata** (:data:`METASPLOIT_URL`, ~11 MB) — the
  framework's own ``modules_metadata_base.json``. ``references`` carries
  CVE ids; ``disclosure_date`` is the module author's record of when the
  vulnerability was publicly disclosed — NOT when the module shipped
  (that would need git history, which this pipeline deliberately never
  clones). It is used as a dated lower bound on public tooling and the
  semantics are stated in the methodology.
* **Nuclei templates CVE index** (:data:`NUCLEI_URL`, ~2 MB JSONL) — one
  line per CVE-keyed detection template. The index carries NO dates, so
  Nuclei contributes to COVERAGE (which CVEs have a template) and never
  to dating — stated honestly in the methodology.

Parsing is lenient per row/line (fetch_kev philosophy: a malformed entry
is skipped) but loud in aggregate: a source that yields zero CVE-linked
entries raises ``ValueError``, because publishing a coverage chart from a
silently-empty corpus would be worse than failing the run.

Dates before :data:`MIN_DATE` are treated as absent — Metasploit uses
placeholder dates like ``1900-01-01`` where the real disclosure date is
unknown, and letting one through would fabricate a decades-negative gap.
"""
from __future__ import annotations

import csv
import io
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

EXPLOITDB_URL = ("https://gitlab.com/exploit-database/exploitdb/-/raw/"
                 "main/files_exploits.csv")
METASPLOIT_URL = ("https://raw.githubusercontent.com/rapid7/"
                  "metasploit-framework/master/db/"
                  "modules_metadata_base.json")
NUCLEI_URL = ("https://raw.githubusercontent.com/projectdiscovery/"
              "nuclei-templates/main/cves.json")

USER_AGENT = "CyberMon/1.0 (+https://github.com/Devko/CyberMon)"
_HEADERS = {"User-Agent": USER_AGENT}
_RETRY_STATUSES = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 3

# Anything earlier is a placeholder, not a date: Metasploit ships
# 1900-01-01 for "unknown", and no public exploit tracker predates the
# late-1980s CERT era.
MIN_DATE = "1988-01-01"

_CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,})\b", re.IGNORECASE)
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _cve_ids(text: str) -> list[str]:
    """Normalized (uppercase, deduped, order-preserving) CVE ids in text."""
    seen: dict[str, None] = {}
    for year, num in _CVE_RE.findall(text or ""):
        seen.setdefault(f"CVE-{year}-{num}", None)
    return list(seen)


def _clean_date(value: object) -> str | None:
    """A usable YYYY-MM-DD, or None for absent/malformed/placeholder."""
    if not isinstance(value, str):
        return None
    value = value.strip()[:10]
    if not _DATE_RE.match(value) or value < MIN_DATE:
        return None
    return value


def _keep_earliest(dates: dict[str, str], cve: str, date: str) -> None:
    prev = dates.get(cve)
    if prev is None or date < prev:
        dates[cve] = date


@dataclass
class PocData:
    """The three parsed corpora, reduced to what the metrics need."""

    # cve -> earliest dated public PoC in that source (YYYY-MM-DD)
    edb_dates: dict[str, str] = field(default_factory=dict, repr=False)
    msf_dates: dict[str, str] = field(default_factory=dict, repr=False)
    # every CVE the source references, dated or not — COVERAGE is wider
    # than dating (a module with a placeholder date still covers its CVE)
    edb_ids: frozenset[str] = frozenset()
    msf_ids: frozenset[str] = frozenset()
    # Nuclei: coverage only — the index publishes no dates.
    nuclei_ids: frozenset[str] = frozenset()
    # per-source audit counts (the catalog block's raw material)
    edb_entries: int = 0
    edb_entries_with_cve: int = 0
    msf_modules: int = 0
    msf_modules_with_cve: int = 0
    nuclei_templates: int = 0

    @property
    def all_ids(self) -> frozenset[str]:
        """Every CVE id any of the three sources references."""
        return self.edb_ids | self.msf_ids | self.nuclei_ids

    @property
    def first_poc_dates(self) -> dict[str, str]:
        """cve -> earliest dated public PoC across the dated sources."""
        first = dict(self.edb_dates)
        for cve, date in self.msf_dates.items():
            _keep_earliest(first, cve, date)
        return first


def parse_exploitdb(text: str
                    ) -> tuple[dict[str, str], frozenset[str], int, int]:
    """(cve -> earliest date_published, all covered CVE ids, total rows,
    rows with a CVE). Malformed rows are skipped; zero CVE-linked rows
    fails loudly."""
    dates: dict[str, str] = {}
    covered: set[str] = set()
    total = with_cve = 0
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        if not isinstance(row.get("id"), str):
            continue
        total += 1
        cves = _cve_ids(row.get("codes") or "")
        if not cves:
            continue
        with_cve += 1
        covered.update(cves)
        date = _clean_date(row.get("date_published"))
        if date is None:
            continue
        for cve in cves:
            _keep_earliest(dates, cve, date)
    if not covered:
        raise ValueError("Exploit-DB index: zero CVE-linked rows parsed "
                         "(upstream shape drift?)")
    return dates, frozenset(covered), total, with_cve


def parse_metasploit(obj: dict
                     ) -> tuple[dict[str, str], frozenset[str], int, int]:
    """(cve -> earliest disclosure_date, all covered CVE ids, total
    modules, modules with a CVE).

    ``disclosure_date`` dates the disclosure the module targets, not the
    module's merge — see the module docstring. Placeholder dates (before
    :data:`MIN_DATE`) contribute coverage but never a date.
    """
    if not isinstance(obj, dict):
        raise ValueError("Metasploit metadata: expected a JSON object")
    dates: dict[str, str] = {}
    covered: set[str] = set()
    total = with_cve = 0
    for module in obj.values():
        if not isinstance(module, dict):
            continue
        total += 1
        refs = module.get("references")
        cves = _cve_ids(";".join(r for r in refs if isinstance(r, str))
                        if isinstance(refs, list) else "")
        if not cves:
            continue
        with_cve += 1
        covered.update(cves)
        date = _clean_date(module.get("disclosure_date"))
        if date is None:
            continue
        for cve in cves:
            _keep_earliest(dates, cve, date)
    if not covered:
        raise ValueError("Metasploit metadata: zero CVE-linked modules "
                         "parsed (upstream shape drift?)")
    return dates, frozenset(covered), total, with_cve


def parse_nuclei(text: str) -> frozenset[str]:
    """CVE ids with a Nuclei template (JSONL index; ids only, no dates)."""
    ids: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            ids.update(_cve_ids(str(entry.get("ID") or "")))
    if not ids:
        raise ValueError("Nuclei CVE index: zero CVE ids parsed "
                         "(upstream shape drift?)")
    return frozenset(ids)


def _assemble(edb_text: str, msf_obj: dict, nuclei_text: str) -> PocData:
    edb_dates, edb_ids, edb_total, edb_with_cve = parse_exploitdb(edb_text)
    msf_dates, msf_ids, msf_total, msf_with_cve = parse_metasploit(msf_obj)
    nuclei_ids = parse_nuclei(nuclei_text)
    return PocData(edb_dates=edb_dates, msf_dates=msf_dates,
                   edb_ids=edb_ids, msf_ids=msf_ids,
                   nuclei_ids=nuclei_ids,
                   edb_entries=edb_total, edb_entries_with_cve=edb_with_cve,
                   msf_modules=msf_total, msf_modules_with_cve=msf_with_cve,
                   nuclei_templates=len(nuclei_ids))


def load_poc_files(edb_path: Path, msf_path: Path,
                   nuclei_path: Path) -> PocData:
    """Parse the three corpora from local files (fixtures)."""
    return _assemble(edb_path.read_text(encoding="utf-8"),
                     json.loads(msf_path.read_text(encoding="utf-8")),
                     nuclei_path.read_text(encoding="utf-8"))


def _get_with_retry(session, url: str, timeout: float, sleep, log):
    """Bounded retry (fetch_dnssec discipline): 3 attempts, backoff on
    429/5xx and connection errors, final failure raises."""
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        last = attempt == _MAX_ATTEMPTS
        try:
            resp = session.get(url, headers=_HEADERS, timeout=timeout)
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
        log(f"  PoC corpora: {message} for {url}; retrying in "
            f"{backoff:.0f}s (attempt {attempt}/{_MAX_ATTEMPTS})")
        sleep(backoff)


def _cached_body(cache_dir: Path, name: str, url: str, session,
                 sleep, log, timeout: float = 300.0) -> bytes:
    """The file body, from today's cache if present, else downloaded.

    Cache key = UTC date + name; stale same-name files from earlier days
    are removed after a successful download, so the cache never grows.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    poc_dir = cache_dir / "poc"
    dest = poc_dir / f"{today}_{name}"
    if dest.exists():
        return dest.read_bytes()
    resp = _get_with_retry(session, url, timeout, sleep, log)
    poc_dir.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    tmp.write_bytes(resp.content)
    tmp.replace(dest)
    for old in poc_dir.glob(f"*_{name}"):
        if old != dest:
            old.unlink(missing_ok=True)
    return dest.read_bytes()


def fetch_poc(cache_dir: Path, session=None, sleep=time.sleep,
              log=print) -> PocData:
    """Download and parse all three corpora (~23 MB total, once a night)."""
    import requests

    session = session or requests.Session()
    edb = _cached_body(cache_dir, "files_exploits.csv", EXPLOITDB_URL,
                       session, sleep, log)
    msf = _cached_body(cache_dir, "modules_metadata_base.json",
                       METASPLOIT_URL, session, sleep, log)
    nuclei = _cached_body(cache_dir, "nuclei_cves.json", NUCLEI_URL,
                          session, sleep, log)
    return _assemble(edb.decode("utf-8"),
                     json.loads(msf.decode("utf-8")),
                     nuclei.decode("utf-8"))
