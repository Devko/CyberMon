"""The Field: every published CVE as one fixed-width binary record.

Feeds ``site/field.html`` — a WebGL instrument that places the whole
corpus in one space and lets a reader arrange it by the site's own theses
(publication date × score × EPSS, by CNA, by weakness, by NVD status, the
score-vs-reality grid). It is deliberately NOT a module: it never enters
``editorial.nav`` (so the carousel and motion pipelines ignore it), it
publishes no aggregate the claims audit could guard, and its data lives
OUTSIDE ``site/data`` — a multi-megabyte blob that changes every night must
never be committed (the nightly ships it inside the Pages artifact instead,
the carousel-PDF pattern).

Everything here rides the ONE streaming corpus pass: :class:`FieldCollector`
is handed to ``Aggregator.consume`` as an observer, so the record it sees is
the same record every module aggregates, reduced by the same
``extract_facts`` — the Field can never disagree with the charts about a
CVE's score, CNA or CWE.

Record layout (little-endian, :data:`RECORD_BYTES` per CVE, version
:data:`LAYOUT_VERSION`) — mirrored field-for-field by ``site/js/field.js``:

======  ====  ===================================================
offset  type  meaning
======  ====  ===================================================
0       u16   CVE-ID year
2       u32   CVE-ID sequence number
6       u16   datePublished, days since :data:`EPOCH`
8       u8    base score × 10 (0-100); :data:`NO_SCORE` when unscored
9       u8    CVSS family of that score: 2, 3, 4; 0 when unscored
10      u16   EPSS probability × 10000; :data:`NO_EPSS` when absent
12      u16   CNA index into ``field.json`` ``cnas``
14      u16   CWE number (79 for CWE-79); 0 when untagged/non-numeric
16      u16   vendor index into ``vendors`` (0 = "other" / unknown)
18      u16   KEV dateAdded, days since EPOCH; 0 when not in KEV
20      u16   earliest dated public PoC (Exploit-DB / Metasploit), days
              since EPOCH; 0 when none is dated (Nuclei carries no dates)
22      u8    flags — see ``FLAG_*`` and :data:`STATUS_CODES`
23      u8    reserved (0)
======  ====  ===================================================

Only PUBLISHED records with a parseable datePublished on or after EPOCH are
placed; everything else is counted in ``field.json`` ``skipped`` so the
page can say how much of the corpus it does not show.
"""
from __future__ import annotations

import gzip
import json
import struct
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Iterable

from .metrics import _FAMILY_ORDER, CveFacts

LAYOUT_VERSION = 2
RECORD = struct.Struct("<HIHBBHHHHHHBx")
RECORD_BYTES = RECORD.size  # 24
EPOCH = date(1999, 1, 1)
NO_SCORE = 255
NO_EPSS = 65535
MAX_DAY = 65535
MAX_VENDORS = 1023  # index 0 is reserved for "other"

FLAG_KEV = 1 << 0
FLAG_RANSOMWARE = 1 << 1
FLAG_POC = 1 << 2
STATUS_SHIFT = 3  # bits 3-5: NVD vulnStatus code
STATUS_CODES: tuple[str, ...] = (
    "Unknown", "Received", "Awaiting Analysis", "Undergoing Analysis",
    "Analyzed", "Modified", "Deferred", "Rejected",
)
_STATUS_INDEX = {name: i for i, name in enumerate(STATUS_CODES)}

BIN_NAME = "cves.bin.gz"
META_NAME = "field.json"


@dataclass
class FieldRow:
    """One placed CVE, before indexing (names, not indices)."""

    year: int
    seq: int
    day: int
    score: int  # ×10, NO_SCORE when unscored
    version: int  # 0 / 2 / 3 / 4
    cna: str
    cwe: int
    vendor: str


@dataclass
class FieldCollector:
    """Observer for ``Aggregator.consume``: keeps one :class:`FieldRow` per
    placeable record and counts the rest."""

    rows: list[FieldRow] = field(default_factory=list)
    skipped_rejected: int = 0
    skipped_undated: int = 0

    def __call__(self, facts: CveFacts, record: dict) -> None:
        if facts.state == "REJECTED":
            self.skipped_rejected += 1
            return
        day = _day_index(facts.date_published)
        id_year = _id_year(facts.cve_id)
        seq = _sequence(facts.cve_id)
        if day is None or seq is None or id_year is None:
            self.skipped_undated += 1
            return
        score, version = _score_and_family(facts)
        self.rows.append(FieldRow(
            year=id_year,
            seq=seq,
            day=day,
            score=score,
            version=version,
            cna=facts.cna,
            cwe=_cwe_number(facts.cwe),
            vendor=_vendor(record),
        ))


def _day_index(date_published: str | None) -> int | None:
    if not date_published:
        return None
    try:
        d = date.fromisoformat(date_published[:10])
    except ValueError:
        return None
    n = (d - EPOCH).days
    return n if 0 <= n <= MAX_DAY else None


def _id_year(cve_id: str) -> int | None:
    parts = cve_id.split("-")
    if len(parts) != 3:
        return None
    try:
        year = int(parts[1])
    except ValueError:
        return None
    return year if 0 <= year <= 0xFFFF else None


def _sequence(cve_id: str) -> int | None:
    parts = cve_id.split("-")
    if len(parts) != 3:
        return None
    try:
        seq = int(parts[2])
    except ValueError:
        return None
    return seq if 0 <= seq <= 0xFFFFFFFF else None


def _score_and_family(facts: CveFacts) -> tuple[int, int]:
    """(score×10, family digit) of the newest-version score in the record,
    CNA preferred — the same precedence as ``CveFacts.effective_score``."""
    for family in _FAMILY_ORDER:
        for scores in (facts.cna_scores, facts.adp_scores):
            if family in scores:
                score = max(0.0, min(10.0, scores[family]))
                return int(round(score * 10)), int(family[1])
    return NO_SCORE, 0


def _cwe_number(cwe: str | None) -> int:
    if not cwe:
        return 0
    try:
        n = int(cwe.split("-", 1)[1])
    except (IndexError, ValueError):
        return 0
    return n if 0 < n <= 0xFFFF else 0


def _vendor(record: dict) -> str:
    """The CNA container's first affected vendor, normalised for grouping;
    "" when absent or a placeholder."""
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    affected = cna.get("affected")
    if not isinstance(affected, list):
        return ""
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        vendor = entry.get("vendor")
        if isinstance(vendor, str):
            name = " ".join(vendor.lower().split())
            if name and name not in ("n/a", "unknown", "unspecified"):
                return name
    return ""


def _status_code(status: str | None) -> int:
    return _STATUS_INDEX.get(status or "", 0)


# ---------------------------------------------------------------- encoding

def encode(rows: Iterable[FieldRow], *, epss_scores: dict[str, float],
           kev_entries: Iterable[Any], poc_ids: Iterable[str],
           nvd_statuses: dict[str, str] | None,
           poc_dates: dict[str, str] | None = None) -> tuple[bytes, dict]:
    """Pack rows into the binary record stream plus the ``field.json``
    payload (minus ``generated_at``/``skipped``/``sources``, which
    :func:`build` stamps).

    Rows are sorted by (year, seq) so the stream is monotonic and gzips well.
    """
    rows = sorted(rows, key=lambda r: (r.year, r.seq))
    cna_counts = Counter(r.cna for r in rows)
    cnas = [name for name, _ in cna_counts.most_common()]
    cna_index = {name: i for i, name in enumerate(cnas)}
    vendor_counts = Counter(r.vendor for r in rows if r.vendor)
    vendors = ["other"] + [name for name, _ in
                           vendor_counts.most_common(MAX_VENDORS)]
    vendor_index = {name: i for i, name in enumerate(vendors)}

    kev: dict[str, tuple[int, bool]] = {}
    for entry in kev_entries:
        day = _day_index(getattr(entry, "date_added", None)) or 0
        ransomware = getattr(entry, "ransomware_use", None) == "Known"
        kev[entry.cve_id] = (day, ransomware)
    poc = frozenset(poc_ids)
    poc_day = {cve: d for cve, d in (
        (cve, _day_index(date)) for cve, date in (poc_dates or {}).items())
        if d}
    statuses = nvd_statuses or {}

    counts: Counter[str] = Counter()
    out = bytearray(RECORD_BYTES * len(rows))
    for i, r in enumerate(rows):
        cve_id = f"CVE-{r.year}-{r.seq:04d}"
        flags = 0
        kev_day = 0
        if cve_id in kev:
            flags |= FLAG_KEV
            kev_day, ransomware = kev[cve_id]
            if ransomware:
                flags |= FLAG_RANSOMWARE
            counts["kev"] += 1
        if cve_id in poc:
            flags |= FLAG_POC
            counts["poc"] += 1
        poc_d = poc_day.get(cve_id, 0)
        if poc_d:
            counts["poc_dated"] += 1
        flags |= _status_code(statuses.get(cve_id)) << STATUS_SHIFT
        epss = epss_scores.get(cve_id)
        if epss is None:
            epss_q = NO_EPSS
        else:
            epss_q = int(round(max(0.0, min(1.0, epss)) * 10000))
            counts["epss"] += 1
        if r.score != NO_SCORE:
            counts["scored"] += 1
        RECORD.pack_into(
            out, i * RECORD_BYTES,
            r.year, r.seq, r.day, r.score, r.version, epss_q,
            cna_index[r.cna], r.cwe, vendor_index.get(r.vendor, 0),
            kev_day, poc_d, flags)

    meta = {
        "layout": {
            "version": LAYOUT_VERSION,
            "record_bytes": RECORD_BYTES,
            "epoch": EPOCH.isoformat(),
            "no_score": NO_SCORE,
            "no_epss": NO_EPSS,
            "status_codes": list(STATUS_CODES),
        },
        "bin": BIN_NAME,
        "n": len(rows),
        "first_day": rows[0].day if rows else 0,
        "last_day": max((r.day for r in rows), default=0),
        "counts": {
            "kev": counts["kev"],
            "poc": counts["poc"],
            "poc_dated": counts["poc_dated"],
            "scored": counts["scored"],
            "epss": counts["epss"],
        },
        "cnas": cnas,
        "vendors": vendors,
    }
    return bytes(out), meta


def decode(blob: bytes) -> list[tuple]:
    """Unpack a record stream (tests and tooling; the page decodes in JS)."""
    if len(blob) % RECORD_BYTES:
        raise ValueError(f"blob length {len(blob)} is not a multiple of "
                         f"{RECORD_BYTES}")
    return [RECORD.unpack_from(blob, off)
            for off in range(0, len(blob), RECORD_BYTES)]


# ------------------------------------------------------------------ stage

def build(collector: FieldCollector, generated_at: str, *,
          epss_scores: dict[str, float], kev_entries: Iterable[Any],
          poc_ids: Iterable[str], nvd_statuses: dict[str, str] | None,
          sources: dict,
          poc_dates: dict[str, str] | None = None) -> tuple[bytes, dict]:
    """The Field's two outputs: the gzipped record stream and ``field.json``."""
    blob, meta = encode(collector.rows, epss_scores=epss_scores,
                        kev_entries=kev_entries, poc_ids=poc_ids,
                        nvd_statuses=nvd_statuses, poc_dates=poc_dates)
    meta["generated_at"] = generated_at
    meta["skipped"] = {
        "rejected": collector.skipped_rejected,
        "undated": collector.skipped_undated,
    }
    meta["sources"] = sources
    packed = gzip.compress(blob, compresslevel=9, mtime=0)
    meta["bin_bytes"] = len(packed)
    meta["raw_bytes"] = len(blob)
    return packed, meta


def write(out_dir: Path, packed: bytes, meta: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / BIN_NAME).write_bytes(packed)
    (out_dir / META_NAME).write_text(json.dumps(meta, indent=1) + "\n",
                                     encoding="utf-8")
