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
  CVE ids and ``type`` says what the module is. Only ``exploit`` modules
  count as exploit code (:data:`MSF_EXPLOIT_TYPES`); auxiliary scanners,
  post modules and the rest are kept as a separate, non-exploit artifact
  set. ``disclosure_date`` is the module author's record of when the
  vulnerability was publicly disclosed — NOT when the module shipped
  (that would need git history, which this pipeline deliberately never
  clones) — so it is a vulnerability-disclosure date, kept for the audit
  block and NEVER used to date exploit code. Before 2026-09-20 it fed
  the first-public-PoC clock as a stand-in; that contaminated the clock
  with a different event and was removed.
* **Nuclei templates CVE index** (:data:`NUCLEI_URL`, ~2 MB JSONL) — one
  line per CVE-keyed DETECTION template. A template is a check, not an
  exploit, and the index carries no dates, so Nuclei contributes to
  detection coverage only — never to exploit coverage or dating.

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

# Metasploit module types that are exploit implementations. Everything
# else in the metadata (auxiliary scanners and fuzzers, post-exploitation
# modules, payloads, encoders, nops, evasion) references CVEs without
# being exploit code for them.
MSF_EXPLOIT_TYPES = frozenset({"exploit"})

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
    """The three parsed corpora, reduced to what the metrics need.

    Three artifact classes are kept apart because they answer different
    questions: **exploit code** (Exploit-DB entries, Metasploit exploit
    modules), **other Metasploit modules** (scanners, post modules — CVE
    references without exploit code) and **detection templates**
    (Nuclei). Only Exploit-DB dates an artifact's own publication, so
    only Exploit-DB dates the exploit clock.
    """

    # cve -> earliest Exploit-DB date_published (YYYY-MM-DD): the date
    # the archive records the EXPLOIT as published — an artifact date.
    edb_dates: dict[str, str] = field(default_factory=dict, repr=False)
    # cve -> earliest Metasploit disclosure_date: the VULNERABILITY's
    # disclosure as recorded by the module author, not the module's
    # publication. Audit only; never a clock input.
    msf_disclosure_dates: dict[str, str] = field(default_factory=dict,
                                                 repr=False)
    # every CVE the source references, dated or not — COVERAGE is wider
    # than dating (an entry with a placeholder date still covers its CVE)
    edb_ids: frozenset[str] = frozenset()
    # CVEs referenced by Metasploit EXPLOIT modules (MSF_EXPLOIT_TYPES)
    msf_ids: frozenset[str] = frozenset()
    # CVEs referenced only by other module types (auxiliary, post, ...)
    msf_other_ids: frozenset[str] = frozenset()
    # Nuclei: detection coverage only — the index publishes no dates.
    nuclei_ids: frozenset[str] = frozenset()
    # per-source audit counts (the catalog block's raw material)
    edb_entries: int = 0
    edb_entries_with_cve: int = 0
    msf_modules: int = 0
    msf_modules_with_cve: int = 0
    msf_exploit_modules_with_cve: int = 0
    nuclei_templates: int = 0

    @property
    def exploit_ids(self) -> frozenset[str]:
        """CVE ids with tracked public EXPLOIT CODE: an Exploit-DB entry
        or a Metasploit exploit module. The coverage and Field join."""
        return self.edb_ids | self.msf_ids

    @property
    def all_ids(self) -> frozenset[str]:
        """Every CVE id any tracked artifact references — exploit code,
        other Metasploit modules or a Nuclei detection template. Wider
        than :attr:`exploit_ids`; a caller wanting exploit code must not
        use it."""
        return self.exploit_ids | self.msf_other_ids | self.nuclei_ids

    @property
    def first_poc_dates(self) -> dict[str, str]:
        """cve -> earliest dated public exploit code. Exploit-DB is the
        only source that dates the artifact itself, so this is its
        ``date_published`` per CVE; Metasploit's disclosure dates are
        deliberately absent (see :attr:`msf_disclosure_dates`)."""
        return dict(self.edb_dates)


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


@dataclass(frozen=True)
class MetasploitParse:
    """What :func:`parse_metasploit` extracts from the module metadata."""

    # cve -> earliest disclosure_date over every CVE-referencing module
    # (any type). A vulnerability-disclosure date, never an exploit date.
    disclosure_dates: dict[str, str]
    # CVEs referenced by exploit modules
    exploit_ids: frozenset[str]
    # CVEs referenced by modules of any other type and by no exploit
    # module — a scanner or post module is not exploit code
    other_ids: frozenset[str]
    total_modules: int
    modules_with_cve: int
    exploit_modules_with_cve: int


def parse_metasploit(obj: dict) -> MetasploitParse:
    """Classify every module by ``type`` and collect its CVE references.

    A module's ``type`` decides which artifact class its CVEs land in:
    :data:`MSF_EXPLOIT_TYPES` is exploit code, everything else is not.
    A CVE referenced by both an exploit and an auxiliary module is
    exploit-covered. ``disclosure_date`` dates the disclosure the module
    targets, not the module's merge — see the module docstring — so it is
    collected for the audit block only. Placeholder dates (before
    :data:`MIN_DATE`) never yield a date.
    """
    if not isinstance(obj, dict):
        raise ValueError("Metasploit metadata: expected a JSON object")
    dates: dict[str, str] = {}
    exploit: set[str] = set()
    other: set[str] = set()
    total = with_cve = exploit_with_cve = 0
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
        module_type = module.get("type")
        is_exploit = isinstance(module_type, str) and \
            module_type.strip().lower() in MSF_EXPLOIT_TYPES
        if is_exploit:
            exploit_with_cve += 1
            exploit.update(cves)
        else:
            other.update(cves)
        date = _clean_date(module.get("disclosure_date"))
        if date is None:
            continue
        for cve in cves:
            _keep_earliest(dates, cve, date)
    if not exploit and not other:
        raise ValueError("Metasploit metadata: zero CVE-linked modules "
                         "parsed (upstream shape drift?)")
    return MetasploitParse(disclosure_dates=dates,
                           exploit_ids=frozenset(exploit),
                           other_ids=frozenset(other - exploit),
                           total_modules=total, modules_with_cve=with_cve,
                           exploit_modules_with_cve=exploit_with_cve)


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


def _assemble_parsed(edb: tuple, msf: MetasploitParse,
                     nuclei_ids: frozenset[str]) -> PocData:
    """PocData from the three parse results (see :func:`_assemble`)."""
    edb_dates, edb_ids, edb_total, edb_with_cve = edb
    return PocData(edb_dates=edb_dates,
                   msf_disclosure_dates=msf.disclosure_dates,
                   edb_ids=edb_ids, msf_ids=msf.exploit_ids,
                   msf_other_ids=msf.other_ids,
                   nuclei_ids=nuclei_ids,
                   edb_entries=edb_total, edb_entries_with_cve=edb_with_cve,
                   msf_modules=msf.total_modules,
                   msf_modules_with_cve=msf.modules_with_cve,
                   msf_exploit_modules_with_cve=msf.exploit_modules_with_cve,
                   nuclei_templates=len(nuclei_ids))


def _assemble(edb_text: str, msf_obj: dict, nuclei_text: str) -> PocData:
    return _assemble_parsed(parse_exploitdb(edb_text),
                            parse_metasploit(msf_obj),
                            parse_nuclei(nuclei_text))


# The per-source parsers as body -> parse-result callables, so the cache
# layer can refuse to keep a body that does not parse.
def _parse_edb_body(body: bytes) -> tuple:
    return parse_exploitdb(body.decode("utf-8"))


def _parse_msf_body(body: bytes) -> MetasploitParse:
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
