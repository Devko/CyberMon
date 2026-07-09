"""cvelistV5 corpus: download the latest "all CVEs" release zip and stream it.

The repo is far too large to clone; each release ships the whole corpus as a
zip asset. We stream-download it once per release tag into a local cache
directory (``.cache/`` by default, gitignored) and then iterate the JSON
records straight out of the zip — one record in memory at a time, never the
corpus. Some releases nest the corpus zip inside the asset zip; both layouts
are handled.

``requests`` is imported lazily so offline/fixture runs and tests never need
the network stack.
"""
from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import IO, Iterator

RELEASES_LATEST_URL = \
    "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
_CVE_NAME_RE = re.compile(r"CVE-\d{4}-\d{4,}\.json$")
_CHUNK = 1 << 20  # 1 MiB download chunks


def latest_release(session=None, timeout: float = 60.0) -> tuple[str, str]:
    """Return (release tag, download URL of the "all CVEs" zip asset)."""
    import requests

    session = session or requests.Session()
    resp = session.get(RELEASES_LATEST_URL, timeout=timeout,
                       headers={"Accept": "application/vnd.github+json"})
    resp.raise_for_status()
    release = resp.json()
    tag = release["tag_name"]
    assets = release.get("assets") or []
    zips = [a for a in assets if a.get("name", "").endswith(".zip")]
    preferred = [a for a in zips if "all_CVEs" in a.get("name", "")]
    chosen = preferred or sorted(zips, key=lambda a: -a.get("size", 0))
    if not chosen:
        raise RuntimeError(f"cvelistV5 release {tag!r} has no zip asset")
    return tag, chosen[0]["browser_download_url"]


def download_zip(cache_dir: Path, tag: str, url: str,
                 session=None, timeout: float = 120.0) -> Path:
    """Stream-download the release zip into ``cache_dir``, keyed by ``tag``.

    Re-runs on the same release are free: an existing cache file is reused.
    Downloads go to a ``.part`` file first so an interrupted run never
    leaves a truncated zip behind under the real name.
    """
    import requests

    safe_tag = re.sub(r"[^A-Za-z0-9._-]", "_", tag)
    dest = cache_dir / f"cvelistV5_{safe_tag}.zip"
    if dest.exists():
        return dest

    session = session or requests.Session()
    cache_dir.mkdir(parents=True, exist_ok=True)
    part = dest.with_suffix(dest.suffix + ".part")
    with session.get(url, stream=True, timeout=timeout) as resp:
        resp.raise_for_status()
        with part.open("wb") as f:
            for chunk in resp.iter_content(chunk_size=_CHUNK):
                f.write(chunk)
    part.replace(dest)
    return dest


def _iter_records_in_zip(zf: zipfile.ZipFile) -> Iterator[dict]:
    for name in zf.namelist():
        if _CVE_NAME_RE.search(name):
            with zf.open(name) as member:
                try:
                    yield json.load(member)
                except json.JSONDecodeError:
                    continue  # a corrupt member must not sink the whole run
        elif name.endswith(".zip"):  # nested corpus zip inside the asset zip
            inner: IO[bytes]
            with zf.open(name) as inner:
                with zipfile.ZipFile(inner) as nested:
                    yield from _iter_records_in_zip(nested)


def iter_cve_records(zip_path: Path) -> Iterator[dict]:
    """Yield every CVE JSON record in the release zip, one at a time."""
    with zipfile.ZipFile(zip_path) as zf:
        yield from _iter_records_in_zip(zf)


def iter_cve_records_from_dir(directory: Path) -> Iterator[dict]:
    """Yield CVE records from loose ``*.json`` files (fixtures/testing)."""
    for path in sorted(directory.rglob("CVE-*.json")):
        yield json.loads(path.read_text(encoding="utf-8"))
