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
from typing import Callable, TypeVar

from .fetch_http import USER_AGENT, get_with_retry  # noqa: F401

T = TypeVar("T")

EXPLOITDB_URL = ("https://gitlab.com/exploit-database/exploitdb/-/raw/"
                 "main/files_exploits.csv")
METASPLOIT_URL = ("https://raw.githubusercontent.com/rapid7/"
                  "metasploit-framework/master/db/"
                  "modules_metadata_base.json")
NUCLEI_URL = ("https://raw.githubusercontent.com/projectdiscovery/"
              "nuclei-templates/main/cves.json")


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


def _assemble_parsed(edb: tuple, msf: tuple, nuclei_ids: frozenset[str]
                     ) -> PocData:
    """PocData from the three parse results (see :func:`_assemble`)."""
    edb_dates, edb_ids, edb_total, edb_with_cve = edb
    msf_dates, msf_ids, msf_total, msf_with_cve = msf
    return PocData(edb_dates=edb_dates, msf_dates=msf_dates,
                   edb_ids=edb_ids, msf_ids=msf_ids,
                   nuclei_ids=nuclei_ids,
                   edb_entries=edb_total, edb_entries_with_cve=edb_with_cve,
                   msf_modules=msf_total, msf_modules_with_cve=msf_with_cve,
                   nuclei_templates=len(nuclei_ids))


def _assemble(edb_text: str, msf_obj: dict, nuclei_text: str) -> PocData:
    return _assemble_parsed(parse_exploitdb(edb_text),
                            parse_metasploit(msf_obj),
                            parse_nuclei(nuclei_text))


# The per-source parsers as body -> parse-result callables, so the cache
# layer can refuse to keep a body that does not parse.
def _parse_edb_body(body: bytes) -> tuple:
    return parse_exploitdb(body.decode("utf-8"))


def _parse_msf_body(body: bytes) -> tuple:
    return parse_metasploit(json.loads(body.decode("utf-8")))


def _parse_nuclei_body(body: bytes) -> frozenset[str]:
    return parse_nuclei(body.decode("utf-8"))


def load_poc_files(edb_path: Path, msf_path: Path,
                   nuclei_path: Path) -> PocData:
    """Parse the three corpora from local files (fixtures)."""
    return _assemble(edb_path.read_text(encoding="utf-8"),
                     json.loads(msf_path.read_text(encoding="utf-8")),
                     nuclei_path.read_text(encoding="utf-8"))


def _cached_body(cache_dir: Path, name: str, url: str, session,
                 sleep, log, *, parse: Callable[[bytes], T],
                 timeout: float = 300.0) -> T:
    """``parse(body)`` for the file, from today's cache if present, else
    downloaded.

    Cache key = UTC date + name. A downloaded body is cached ONLY after
    ``parse`` succeeds — a body that does not parse (an upstream outage
    page, a truncated transfer) raises and leaves nothing behind, so the
    next attempt downloads again instead of re-reading garbage. Writes
    go to a ``.part`` file that is renamed into place; any ``.part`` left
    by a crash between write and rename is swept before the next download
    (the same-name glob deliberately never matched it before). Stale
    same-name files from earlier days are removed after a successful
    cache write, so the cache never grows.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    poc_dir = cache_dir / "poc"
    dest = poc_dir / f"{today}_{name}"
    if dest.exists():
        return parse(dest.read_bytes())
    resp = get_with_retry(session, url, label="PoC corpora",
                          timeout=timeout, sleep=sleep, log=log)
    body = resp.content
    result = parse(body)  # raises -> nothing is cached
    poc_dir.mkdir(parents=True, exist_ok=True)
    for stale in poc_dir.glob(f"*_{name}.part"):
        stale.unlink(missing_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    tmp.write_bytes(body)
    tmp.replace(dest)
    for old in poc_dir.glob(f"*_{name}"):
        if old != dest:
            old.unlink(missing_ok=True)
    return result


def fetch_poc(cache_dir: Path, session=None, sleep=time.sleep,
              log=print) -> PocData:
    """Download and parse all three corpora (~23 MB total, once a night)."""
    import requests

    session = session or requests.Session()
    edb = _cached_body(cache_dir, "files_exploits.csv", EXPLOITDB_URL,
                       session, sleep, log, parse=_parse_edb_body)
    msf = _cached_body(cache_dir, "modules_metadata_base.json",
                       METASPLOIT_URL, session, sleep, log,
                       parse=_parse_msf_body)
    nuclei = _cached_body(cache_dir, "nuclei_cves.json", NUCLEI_URL,
                          session, sleep, log, parse=_parse_nuclei_body)
    return _assemble_parsed(edb, msf, nuclei)
