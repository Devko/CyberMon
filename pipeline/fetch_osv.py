"""OSV per-ecosystem exports (the Advisory Gap and Registry Malware feed).

OSV.dev publishes every record it holds as one zip per ecosystem::

    https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip

each member one OSV-schema JSON record. Two of the databases OSV
aggregates are read here, by id prefix:

* ``GHSA-*`` — the GitHub Advisory Database. OSV mirrors only the
  *GitHub-reviewed* advisories (checked 2026-09-22: all 35,769 GHSA ids in
  the twelve exports below carry ``database_specific.github_reviewed:
  true`` and source paths under ``advisories/github-reviewed/``, except two
  long-withdrawn records that predate the flag). The flag is still read per
  record: a live record without it is counted as ``not_reviewed`` and kept
  out of the tallies, so the "reviewed only" sentence on the page is checked
  nightly rather than assumed.
* ``MAL-*`` — the OpenSSF malicious-packages feed (reports of packages
  published to a registry with malicious intent).

Ecosystem sets (from ``ecosystems.txt`` and a count of id prefixes per
export, 2026-09-22): GHSA ids appear in the twelve GitHub advisory
ecosystems (:data:`GHSA_ECOSYSTEMS`); MAL ids in nine
(:data:`MAL_ECOSYSTEMS`) — VSCode is the only one that carries MAL and no
GHSA. The fetch reads the union, each zip once.

What is kept per record is only what the two pages aggregate:

* a GHSA advisory -> one compact row (id, publication date, CVE-alias flag,
  GitHub severity, reviewed / withdrawn flags, days from the advisory to its
  CVE's NVD publication, affected ecosystems). An advisory that affects
  several ecosystems sits in several zips; rows are merged by id downstream
  (``osv_metrics``), so it is counted once in every total.
* a MAL report -> counters only (per publication month: reports,
  withdrawn, and the feed's contributing sources). A report is counted in the
  zip of its own ecosystem only, so no report can be counted twice.

Cheap nightly: each zip is requested with ``If-None-Match`` /
``If-Modified-Since`` from the cached state; a 304 reuses the cached
summary. A changed zip streams into a spooled temporary file (members are
read in place, never extracted) and only its summary is kept. The state
(``.cache/osv_state.json.gz``) is a cache in the NVD-state sense: a miss
costs one full download, nothing else. Integrity guard: an ecosystem whose
record count falls below :data:`FLOOR_RATIO` of the cached count is refused
as a truncated export.

Licensing: GitHub Advisory Database content is CC-BY 4.0; the OpenSSF
malicious-packages data is Apache-2.0; OSV.dev serves both unchanged in
the exports. No key; one conditional GET per ecosystem per night.
"""
from __future__ import annotations

import gzip
import json
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator
from urllib.parse import quote

from .fetch_http import get_with_retry

OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com/"

# The GitHub Advisory Database's ecosystems, as OSV names them (GitHub's
# "Composer" is Packagist, "Erlang" is Hex, "Rust" is crates.io, "Swift"
# is SwiftURL, "pip" is PyPI).
GHSA_ECOSYSTEMS = ("npm", "PyPI", "Maven", "Packagist", "Go", "crates.io",
                   "NuGet", "RubyGems", "Hex", "SwiftURL", "GitHub Actions",
                   "Pub")
# Ecosystems whose exports carry OpenSSF malicious-packages reports.
MAL_ECOSYSTEMS = ("npm", "PyPI", "RubyGems", "NuGet", "crates.io", "Go",
                  "Maven", "Packagist", "VSCode")
ECOSYSTEMS = tuple(dict.fromkeys(GHSA_ECOSYSTEMS + MAL_ECOSYSTEMS))

SEVERITIES = ("CRITICAL", "HIGH", "MODERATE", "LOW")
# A report with no malicious-packages-origins block (the feed's early
# records predate it).
UNATTRIBUTED = "unattributed"
FLOOR_RATIO = 0.9
STATE_VERSION = 1
STATE_NAME = "osv_state.json.gz"

# GHSA row layout (a list, to keep the cached state small).
G_ID, G_PUBLISHED, G_CVE, G_SEVERITY, G_REVIEWED, G_WITHDRAWN, G_NVD_LAG, \
    G_ECOSYSTEMS = range(8)


def export_url(ecosystem: str) -> str:
    return f"{OSV_BASE}{quote(ecosystem)}/all.zip"


def base_ecosystem(name: object) -> str:
    """``"VSCode:https://open-vsx.org"`` -> ``"VSCode"``; OSV qualifies some
    ecosystems with a registry or release suffix after a colon."""
    return name.split(":", 1)[0].strip() if isinstance(name, str) else ""


def _date(value: object, what: str, rid: str) -> str:
    text = value if isinstance(value, str) else ""
    try:
        return date.fromisoformat(text[:10]).isoformat()
    except ValueError:
        raise ValueError(f"osv: {rid}: unparseable {what} {value!r}") from None


@dataclass
class EcosystemSummary:
    """Everything the two modules need from one ecosystem export."""

    ecosystem: str
    ghsa: list[list] = field(default_factory=list)
    # "YYYY-MM" -> [reports, withdrawn]
    mal_months: dict[str, list[int]] = field(default_factory=dict)
    # "YYYY-MM" -> {source: reports}
    mal_sources: dict[str, dict[str, int]] = field(default_factory=dict)
    records: int = 0          # every member read (all id prefixes)
    etag: str | None = None
    last_modified: str | None = None
    not_modified: bool = False  # tonight's GET answered 304

    @property
    def mal_count(self) -> int:
        return sum(v[0] for v in self.mal_months.values())

    def to_state(self) -> dict:
        return {"etag": self.etag, "last_modified": self.last_modified,
                "records": self.records, "ghsa": self.ghsa,
                "mal_months": self.mal_months,
                "mal_sources": self.mal_sources}

    @classmethod
    def from_state(cls, ecosystem: str, obj: dict) -> "EcosystemSummary":
        return cls(ecosystem=ecosystem, ghsa=obj["ghsa"],
                   mal_months=obj["mal_months"],
                   mal_sources=obj["mal_sources"],
                   records=obj["records"], etag=obj.get("etag"),
                   last_modified=obj.get("last_modified"))


def ghsa_row(rec: dict) -> list:
    """The compact row for one GHSA record (see the G_* layout)."""
    rid = rec["id"]
    published = _date(rec.get("published"), "published", rid)
    ds = rec.get("database_specific")
    ds = ds if isinstance(ds, dict) else {}
    aliases = rec.get("aliases") or []
    has_cve = any(isinstance(a, str) and a.startswith("CVE-")
                  for a in aliases)
    severity = ds.get("severity")
    severity = severity if severity in SEVERITIES else ""
    nvd_lag = None
    if has_cve and isinstance(ds.get("nvd_published_at"), str):
        try:
            nvd = date.fromisoformat(ds["nvd_published_at"][:10])
            nvd_lag = (nvd - date.fromisoformat(published)).days
        except ValueError:
            nvd_lag = None
    ecos = sorted({base_ecosystem((a.get("package") or {}).get("ecosystem"))
                   for a in rec.get("affected") or []
                   if isinstance(a, dict)} - {""})
    return [rid, published, int(has_cve), severity,
            int(ds.get("github_reviewed") is True),
            int(bool(rec.get("withdrawn"))), nvd_lag, ecos]


def _mal_ecosystem(rec: dict) -> str:
    ecos = {base_ecosystem((a.get("package") or {}).get("ecosystem"))
            for a in rec.get("affected") or [] if isinstance(a, dict)}
    ecos.discard("")
    if len(ecos) != 1:
        raise ValueError(f"osv: {rec['id']}: expected one affected "
                         f"ecosystem, got {sorted(ecos)}")
    return ecos.pop()


def _mal_sources(rec: dict) -> list[str]:
    ds = rec.get("database_specific")
    origins = ds.get("malicious-packages-origins") if isinstance(ds, dict) \
        else None
    names = sorted({o["source"] for o in origins or []
                    if isinstance(o, dict) and isinstance(o.get("source"), str)
                    and o["source"].strip()})
    return names or [UNATTRIBUTED]


def summarize_records(ecosystem: str, records: Iterable[dict]
                      ) -> EcosystemSummary:
    """Reduce one ecosystem's records to an :class:`EcosystemSummary`.
    Records of other databases (PYSEC-, GO-, RUSTSEC-, ...) are counted in
    ``records`` and otherwise ignored; a MAL report whose own ecosystem is
    not ``ecosystem`` is skipped (it is counted in its own export)."""
    out = EcosystemSummary(ecosystem=ecosystem)
    seen_mal: set[str] = set()
    for rec in records:
        out.records += 1
        rid = rec.get("id") if isinstance(rec, dict) else None
        if not isinstance(rid, str):
            raise ValueError(f"osv: {ecosystem}: record without an id")
        if rid.startswith("GHSA-"):
            out.ghsa.append(ghsa_row(rec))
        elif rid.startswith("MAL-"):
            if rid in seen_mal or _mal_ecosystem(rec) != ecosystem:
                continue
            seen_mal.add(rid)
            month = _date(rec.get("published"), "published", rid)[:7]
            slot = out.mal_months.setdefault(month, [0, 0])
            slot[0] += 1
            if rec.get("withdrawn"):
                slot[1] += 1
            per = out.mal_sources.setdefault(month, {})
            for src in _mal_sources(rec):
                per[src] = per.get(src, 0) + 1
    out.ghsa.sort(key=lambda r: r[G_ID])
    return out


def iter_zip_records(fileobj) -> Iterator[dict]:
    """Every JSON member of an OSV export, parsed in place (nothing is
    extracted to disk). A corrupt archive raises ``ValueError`` — the
    same class as a malformed record, so the caller's degrade path sees
    one kind of broken export."""
    try:
        with zipfile.ZipFile(fileobj) as zf:
            for name in zf.namelist():
                if name.endswith(".json"):
                    yield json.loads(zf.read(name))
    except zipfile.BadZipFile as exc:
        raise ValueError(f"osv: corrupt export zip ({exc})") from exc


def iter_dir_records(path: Path) -> Iterator[dict]:
    """Records from a directory of OSV JSON files (the offline fixtures)."""
    for p in sorted(path.glob("*.json")):
        yield json.loads(p.read_text(encoding="utf-8"))


def load_fixture_dir(root: Path) -> dict[str, EcosystemSummary]:
    """One summary per ``root/<Ecosystem>/`` directory of fixture records."""
    return {d.name: summarize_records(d.name, iter_dir_records(d))
            for d in sorted(root.iterdir()) if d.is_dir()}


# ---- cached state -------------------------------------------------------------

def load_state(cache_dir: Path, log: Callable[[str], None] = print
               ) -> dict[str, EcosystemSummary]:
    """Cached per-ecosystem summaries, or {} when absent/unreadable (every
    export is then downloaded in full — the state is only ever a cache)."""
    path = cache_dir / STATE_NAME
    if not path.exists():
        return {}
    try:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            obj = json.load(f)
        if obj.get("version") != STATE_VERSION:
            return {}
        return {eco: EcosystemSummary.from_state(eco, s)
                for eco, s in obj["ecosystems"].items()}
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        log(f"warning: ignoring unreadable OSV state {path}: {exc!r}")
        return {}


def save_state(cache_dir: Path, summaries: dict[str, EcosystemSummary]
               ) -> None:
    path = cache_dir / STATE_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        json.dump({"version": STATE_VERSION,
                   "ecosystems": {k: v.to_state()
                                  for k, v in summaries.items()}},
                  f, separators=(",", ":"))
    tmp.replace(path)


# ---- network ------------------------------------------------------------------

def _floor_check(new: EcosystemSummary, cached: EcosystemSummary | None
                 ) -> None:
    if cached is None or cached.records <= 0:
        return
    if new.records < cached.records * FLOOR_RATIO:
        raise ValueError(
            f"osv: {new.ecosystem} export holds {new.records} records, "
            f"cached copy {cached.records}; below the {FLOOR_RATIO:.0%} "
            f"floor — refusing a truncated export")


def fetch_ecosystem(session, ecosystem: str,
                    cached: EcosystemSummary | None = None, *,
                    timeout: float = 300.0, sleep=time.sleep,
                    log: Callable[[str], None] = print) -> EcosystemSummary:
    """Tonight's summary of one ecosystem export: the cached one when the
    server answers 304, else a fresh stream-and-summarize."""
    headers: dict[str, str] = {}
    if cached is not None:
        if cached.etag:
            headers["If-None-Match"] = cached.etag
        if cached.last_modified:
            headers["If-Modified-Since"] = cached.last_modified
    url = export_url(ecosystem)

    def consume(resp) -> EcosystemSummary:
        if resp.status_code == 304:
            if cached is None:
                raise ValueError(f"osv: {ecosystem}: 304 without a cached "
                                 f"copy")
            return EcosystemSummary(
                ecosystem=ecosystem, ghsa=cached.ghsa,
                mal_months=cached.mal_months, mal_sources=cached.mal_sources,
                records=cached.records, etag=cached.etag,
                last_modified=cached.last_modified, not_modified=True)
        resp.raise_for_status()
        with tempfile.SpooledTemporaryFile(max_size=64 << 20) as buf:
            for chunk in resp.iter_content(1 << 20):
                buf.write(chunk)
            buf.seek(0)
            summary = summarize_records(ecosystem, iter_zip_records(buf))
        summary.etag = resp.headers.get("ETag")
        summary.last_modified = resp.headers.get("Last-Modified")
        return summary

    summary = get_with_retry(session, url, label=f"osv {ecosystem}",
                             headers=headers, timeout=timeout, sleep=sleep,
                             log=log, stream=True, raise_for_status=False,
                             consume=consume)
    if not summary.not_modified:
        _floor_check(summary, cached)
    return summary


def fetch_all(cache_dir: Path, session=None, *,
              ecosystems: Iterable[str] = ECOSYSTEMS, sleep=time.sleep,
              log: Callable[[str], None] = print
              ) -> dict[str, EcosystemSummary]:
    """Every ecosystem's summary, conditional on the cached state. Any
    failure raises (the caller carries the modules forward); the state is
    saved only when every ecosystem succeeded."""
    if session is None:
        import requests

        session = requests.Session()
    cached = load_state(cache_dir, log=log)
    out: dict[str, EcosystemSummary] = {}
    for eco in ecosystems:
        summary = fetch_ecosystem(session, eco, cached.get(eco), sleep=sleep,
                                  log=log)
        how = "not modified" if summary.not_modified else "downloaded"
        log(f"  osv {eco}: {how} — {summary.records} records, "
            f"{len(summary.ghsa)} GHSA, {summary.mal_count} MAL")
        out[eco] = summary
    save_state(cache_dir, out)
    return out


def summary_stats(summaries: dict[str, Any]) -> dict[str, int]:
    """Download accounting for meta.sources.osv."""
    return {
        "ecosystems": len(summaries),
        "downloaded": sum(1 for s in summaries.values()
                          if not s.not_modified),
        "not_modified": sum(1 for s in summaries.values() if s.not_modified),
    }
