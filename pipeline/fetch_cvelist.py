"""cvelistV5 corpus: download the latest "all CVEs" release zip and stream it.

The repo is far too large to clone; each release ships the whole corpus as a
zip asset. We stream-download it once per release tag into a local cache
directory (``.cache/`` by default, gitignored) and then iterate the JSON
records straight out of the zip — one record in memory at a time, never the
corpus. Some releases nest the corpus zip inside the asset zip; both layouts
are handled.

Two floors guard the corpus itself. A release without an ``all_CVEs`` asset
is refused outright (the alternative — the largest zip on a delta-only
release — is a few hundred records dressed up as the corpus). And a zip in
which more than :data:`MAX_SKIPPED_SHARE` of the CVE members fail to decode
(past a grace of :data:`MAX_SKIPPED_MEMBERS`) is refused after the pass: a
handful of corrupt files must not sink a run, but a mostly-unreadable zip
is not the corpus.

``requests`` is imported lazily so offline/fixture runs and tests never need
the network stack.
"""
from __future__ import annotations

import json
import os
import re
import time
import zipfile
from pathlib import Path
from typing import IO, Callable, Iterator

from .fetch_http import get_with_retry

RELEASES_LATEST_URL = \
    "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
_CVE_NAME_RE = re.compile(r"CVE-\d{4}-\d{4,}\.json$")
_CHUNK = 1 << 20  # 1 MiB download chunks
_CACHE_PREFIX = "cvelistV5_"
# Corrupt-member tolerance for the streamed zip (see module docstring).
MAX_SKIPPED_MEMBERS = 50
MAX_SKIPPED_SHARE = 0.01


def _github_headers() -> dict[str, str]:
    """GitHub API headers: the JSON media type, plus a bearer token when
    ``GITHUB_TOKEN`` is set (Actions provides one; it lifts the anonymous
    60-requests-per-hour ceiling that shared CI egress IPs exhaust)."""
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def latest_release(session=None, timeout: float = 60.0,
                   sleep: Callable[[float], None] = time.sleep,
                   log: Callable[[str], None] = print) -> tuple[str, str]:
    """Return (release tag, download URL of the "all CVEs" zip asset).

    Raises ``RuntimeError`` when the release carries no ``all_CVEs`` zip:
    there is deliberately no fallback to another asset."""
    import requests

    session = session or requests.Session()
    resp = get_with_retry(session, RELEASES_LATEST_URL, label="cvelist",
                          headers=_github_headers(), timeout=timeout,
                          sleep=sleep, log=log)
    release = resp.json()
    tag = release["tag_name"]
    assets = release.get("assets") or []
    preferred = [a for a in assets
                 if a.get("name", "").endswith(".zip")
                 and "all_CVEs" in a.get("name", "")]
    if not preferred:
        names = sorted(a.get("name", "") for a in assets)
        raise RuntimeError(
            f"cvelistV5 release {tag!r} has no all_CVEs zip asset "
            f"(assets: {names}); refusing to substitute a delta release "
            f"for the corpus")
    return tag, preferred[0]["browser_download_url"]


def _cache_path(cache_dir: Path, tag: str) -> Path:
    safe_tag = re.sub(r"[^A-Za-z0-9._-]", "_", tag)
    return cache_dir / f"{_CACHE_PREFIX}{safe_tag}.zip"


def _prune_cache(cache_dir: Path, keep: Path,
                 log: Callable[[str], None]) -> None:
    """Remove every other cached release zip (and stray ``.part`` files).
    Releases are cut hourly, so without this the cache grows by one
    ~550 MB file per run."""
    for old in sorted(cache_dir.glob(f"{_CACHE_PREFIX}*.zip*")):
        if old == keep or not old.is_file():
            continue
        try:
            old.unlink()
        except OSError as exc:
            log(f"  cvelist: could not remove stale {old.name}: {exc!r}")
            continue
        log(f"  cvelist: removed stale release zip {old.name}")


def download_zip(cache_dir: Path, tag: str, url: str,
                 session=None, timeout: float = 120.0,
                 sleep: Callable[[float], None] = time.sleep,
                 log: Callable[[str], None] = print) -> Path:
    """Stream-download the release zip into ``cache_dir``, keyed by ``tag``.

    Re-runs on the same release are free: an existing cache file is reused.
    Downloads go to a ``.part`` file first so an interrupted run never
    leaves a truncated zip behind under the real name. The whole download
    — connect, status and the streamed body — sits inside the shared
    bounded retry, so a connection that dies mid-body is retried from
    scratch; the ``.part`` of a failed attempt is discarded. After a
    successful download every other cached release zip is removed.
    """
    import requests

    dest = _cache_path(cache_dir, tag)
    if dest.exists():
        return dest

    session = session or requests.Session()
    cache_dir.mkdir(parents=True, exist_ok=True)
    part = dest.with_suffix(dest.suffix + ".part")

    def _stream_to_part(resp) -> None:
        try:
            with part.open("wb") as f:
                for chunk in resp.iter_content(chunk_size=_CHUNK):
                    f.write(chunk)
        except BaseException:
            part.unlink(missing_ok=True)
            raise
        finally:
            close = getattr(resp, "close", None)
            if close is not None:
                close()

    get_with_retry(session, url, label="cvelist", timeout=timeout,
                   sleep=sleep, log=log, stream=True,
                   consume=_stream_to_part)
    part.replace(dest)
    _prune_cache(cache_dir, keep=dest, log=log)
    return dest


def _iter_records_in_zip(zf: zipfile.ZipFile,
                         stats: dict[str, int] | None = None
                         ) -> Iterator[dict]:
    """Yield every CVE record in ``zf`` (recursing into nested zips).
    ``stats`` (``members`` seen, ``skipped`` for JSON decode errors) is
    updated in place so the caller can judge the skip rate afterwards."""
    if stats is None:
        stats = {"members": 0, "skipped": 0}
    for name in zf.namelist():
        if _CVE_NAME_RE.search(name):
            stats["members"] += 1
            with zf.open(name) as member:
                try:
                    record = json.load(member)
                except json.JSONDecodeError:
                    stats["skipped"] += 1
                    continue  # a corrupt member must not sink the whole run
            yield record
        elif name.endswith(".zip"):  # nested corpus zip inside the asset zip
            inner: IO[bytes]
            with zf.open(name) as inner:
                with zipfile.ZipFile(inner) as nested:
                    yield from _iter_records_in_zip(nested, stats)


def _check_skip_rate(stats: dict[str, int], source: str,
                     log: Callable[[str], None]) -> None:
    members, skipped = stats["members"], stats["skipped"]
    if skipped:
        log(f"  cvelist: {skipped} of {members} CVE member(s) in {source} "
            f"skipped (JSON decode error)")
    limit = max(MAX_SKIPPED_MEMBERS, MAX_SKIPPED_SHARE * members)
    if skipped > limit:
        raise RuntimeError(
            f"cvelistV5 zip {source}: {skipped} of {members} CVE members "
            f"failed to decode (limit {limit:.0f}); refusing to treat a "
            f"corrupt archive as the corpus")


def iter_cve_records(zip_path: Path,
                     log: Callable[[str], None] = print) -> Iterator[dict]:
    """Yield every CVE JSON record in the release zip, one at a time.

    Members that fail to decode are skipped and counted; once the pass is
    complete the count is logged and, past the corrupt-member floor, a
    ``RuntimeError`` is raised (see module docstring)."""
    stats = {"members": 0, "skipped": 0}
    with zipfile.ZipFile(zip_path) as zf:
        yield from _iter_records_in_zip(zf, stats)
    _check_skip_rate(stats, zip_path.name, log)


def iter_cve_records_from_dir(directory: Path) -> Iterator[dict]:
    """Yield CVE records from loose ``*.json`` files (fixtures/testing)."""
    for path in sorted(directory.rglob("CVE-*.json")):
        yield json.loads(path.read_text(encoding="utf-8"))
