"""cvelistV5 release discovery, the streamed download, cache pruning and
the two corpus-size floors (no all_CVEs asset; too many corrupt members).
No network: every session is a fake."""
from __future__ import annotations

import io
import json
import zipfile

import pytest

from pipeline import fetch_cvelist
from pipeline.fetch_cvelist import (download_zip, iter_cve_records,
                                    latest_release)


class FakeResponse:
    def __init__(self, status_code=200, payload=None, chunks=(),
                 fail_after=None):
        self.status_code = status_code
        self._payload = payload
        self._chunks = list(chunks)
        self._fail_after = fail_after
        self.closed = False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload

    def iter_content(self, chunk_size=None):
        for i, chunk in enumerate(self._chunks):
            if self._fail_after is not None and i >= self._fail_after:
                raise ConnectionError("connection broken mid-body")
            yield chunk

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _quiet(_):
    pass


def _release(tag="cve_2026-09-08_0600Z", assets=()):
    return {"tag_name": tag, "assets": list(assets)}


def _asset(name, size=1, url=None):
    return {"name": name, "size": size,
            "browser_download_url": url or f"https://dl/{name}"}


# ---------------------------------------------------------- latest_release

def test_latest_release_prefers_the_all_cves_asset_over_a_larger_zip():
    session = FakeSession([FakeResponse(payload=_release(assets=[
        _asset("2026-09-08_delta_CVEs_at_0600Z.zip", size=10_000_000),
        _asset("2026-09-08_all_CVEs_at_midnight.zip", size=5),
        _asset("README.txt", size=99)]))])
    tag, url = latest_release(session=session, sleep=_quiet, log=_quiet)
    assert tag == "cve_2026-09-08_0600Z"
    assert url.endswith("all_CVEs_at_midnight.zip")


def test_latest_release_without_all_cves_asset_is_refused():
    """A delta-only release must never be mistaken for the corpus: no
    silent fallback to the largest zip."""
    session = FakeSession([FakeResponse(payload=_release(assets=[
        _asset("2026-09-08_delta_CVEs_at_0600Z.zip", size=10_000_000)]))])
    with pytest.raises(RuntimeError, match="no all_CVEs zip asset"):
        latest_release(session=session, sleep=_quiet, log=_quiet)


def test_latest_release_without_any_asset_is_refused():
    session = FakeSession([FakeResponse(payload=_release(assets=[]))])
    with pytest.raises(RuntimeError, match="no all_CVEs zip asset"):
        latest_release(session=session, sleep=_quiet, log=_quiet)


def test_latest_release_sends_user_agent_and_no_auth_without_token(
        monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    session = FakeSession([FakeResponse(payload=_release(assets=[
        _asset("all_CVEs.zip")]))])
    latest_release(session=session, sleep=_quiet, log=_quiet)
    headers = session.calls[0]["headers"]
    assert headers["User-Agent"].startswith("CyberMon/")
    assert headers["Accept"] == "application/vnd.github+json"
    assert "Authorization" not in headers


def test_latest_release_sends_bearer_token_when_env_is_set(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_abc123")
    session = FakeSession([FakeResponse(payload=_release(assets=[
        _asset("all_CVEs.zip")]))])
    latest_release(session=session, sleep=_quiet, log=_quiet)
    headers = session.calls[0]["headers"]
    assert headers["Authorization"] == "Bearer ghs_abc123"
    assert headers["User-Agent"].startswith("CyberMon/")


def test_latest_release_empty_token_is_treated_as_absent(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "")
    session = FakeSession([FakeResponse(payload=_release(assets=[
        _asset("all_CVEs.zip")]))])
    latest_release(session=session, sleep=_quiet, log=_quiet)
    assert "Authorization" not in session.calls[0]["headers"]


def test_latest_release_retries_transient_failures():
    session = FakeSession([FakeResponse(status_code=503),
                           OSError("reset"),
                           FakeResponse(payload=_release(assets=[
                               _asset("all_CVEs.zip")]))])
    sleeps = []
    tag, _ = latest_release(session=session, sleep=sleeps.append,
                            log=_quiet)
    assert tag.startswith("cve_") and len(sleeps) == 2


def test_latest_release_persistent_failure_raises():
    session = FakeSession([FakeResponse(status_code=502)] * 5)
    with pytest.raises(RuntimeError, match="HTTP 502"):
        latest_release(session=session, sleep=_quiet, log=_quiet)
    assert len(session.calls) == 3


# ------------------------------------------------------------ download_zip

def test_download_streams_to_part_then_renames_and_prunes(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    stale = cache / "cvelistV5_cve_2026-09-07_2300Z.zip"
    stale.write_bytes(b"old")
    stale_part = cache / "cvelistV5_cve_2026-09-07_2200Z.zip.part"
    stale_part.write_bytes(b"older")
    unrelated = cache / "nvd_status_state.json.gz"
    unrelated.write_bytes(b"keep me")

    resp = FakeResponse(chunks=[b"PK", b"rest"])
    session = FakeSession([resp])
    logs = []
    dest = download_zip(cache, "cve_2026-09-08_0600Z", "https://dl/all.zip",
                        session=session, sleep=_quiet, log=logs.append)
    assert dest == cache / "cvelistV5_cve_2026-09-08_0600Z.zip"
    assert dest.read_bytes() == b"PKrest"
    assert not dest.with_suffix(".zip.part").exists()
    assert session.calls[0]["stream"] is True
    assert session.calls[0]["headers"]["User-Agent"].startswith("CyberMon/")
    assert resp.closed
    # every other cached release zip (and stray .part) is gone; other
    # cache files are untouched
    assert not stale.exists() and not stale_part.exists()
    assert unrelated.exists()
    assert any("removed stale" in m and stale.name in m for m in logs)


def test_download_cache_hit_makes_no_request(tmp_path):
    dest = tmp_path / "cvelistV5_tag.zip"
    dest.write_bytes(b"cached")
    session = FakeSession([])
    assert download_zip(tmp_path, "tag", "https://dl/x", session=session,
                        sleep=_quiet, log=_quiet) == dest
    assert session.calls == []


def test_download_mid_body_failure_discards_part_and_retries(tmp_path):
    session = FakeSession([FakeResponse(chunks=[b"AB", b"CD"], fail_after=1),
                           FakeResponse(status_code=503),
                           FakeResponse(chunks=[b"AB", b"CD"])])
    sleeps = []
    dest = download_zip(tmp_path, "t", "https://dl/x", session=session,
                        sleep=sleeps.append, log=_quiet)
    assert dest.read_bytes() == b"ABCD"
    assert len(session.calls) == 3 and len(sleeps) == 2
    assert not list(tmp_path.glob("*.part"))


def test_download_exhausted_ladder_leaves_no_part_and_raises(tmp_path):
    session = FakeSession([FakeResponse(chunks=[b"AB"], fail_after=0)] * 3)
    with pytest.raises(ConnectionError):
        download_zip(tmp_path, "t", "https://dl/x", session=session,
                     sleep=_quiet, log=_quiet)
    assert len(session.calls) == 3
    assert list(tmp_path.glob("cvelistV5_*")) == []


def test_download_http_error_on_final_attempt_raises(tmp_path):
    session = FakeSession([FakeResponse(status_code=500)] * 3)
    with pytest.raises(RuntimeError, match="HTTP 500"):
        download_zip(tmp_path, "t", "https://dl/x", session=session,
                     sleep=_quiet, log=_quiet)


# ------------------------------------------------------- iter_cve_records

def _zip_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in members.items():
            zf.writestr(name, body)
    return buf.getvalue()


def _record(i: int) -> bytes:
    return json.dumps({"cveMetadata": {"cveId": f"CVE-2026-{i:04d}"}}
                      ).encode()


def _write_zip(path, good: int, bad: int, nested=False):
    members = {f"cves/2026/CVE-2026-{i:04d}.json": _record(i)
               for i in range(1, good + 1)}
    members.update({f"cves/2026/CVE-2026-{good + i:04d}.json": b"{not json"
                    for i in range(1, bad + 1)})
    members["README.md"] = b"ignored"
    body = _zip_bytes(members)
    if nested:
        body = _zip_bytes({"inner_corpus.zip": body})
    path.write_bytes(body)
    return path


def test_iter_cve_records_reads_flat_and_nested_layouts(tmp_path):
    flat = _write_zip(tmp_path / "flat.zip", good=3, bad=0)
    nested = _write_zip(tmp_path / "nested.zip", good=3, bad=0, nested=True)
    for path in (flat, nested):
        ids = [r["cveMetadata"]["cveId"] for r in iter_cve_records(path)]
        assert ids == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]


def test_a_few_corrupt_members_are_skipped_and_counted(tmp_path):
    path = _write_zip(tmp_path / "c.zip", good=10, bad=3)
    logs = []
    ids = [r["cveMetadata"]["cveId"]
           for r in iter_cve_records(path, log=logs.append)]
    assert len(ids) == 10
    assert any("3 of 13" in m and "skipped" in m for m in logs)


def test_no_corrupt_members_logs_nothing(tmp_path):
    path = _write_zip(tmp_path / "c.zip", good=5, bad=0)
    logs = []
    assert len(list(iter_cve_records(path, log=logs.append))) == 5
    assert logs == []


def test_corrupt_share_past_the_floor_raises_after_the_pass(tmp_path):
    """51 corrupt of 60 members: past both the 50-member grace and the 1%
    share. The good records still stream (the check is a post-pass
    verdict), then the generator raises so the run fails loudly."""
    path = _write_zip(tmp_path / "c.zip", good=9, bad=51)
    seen = []
    with pytest.raises(RuntimeError, match="51 of 60 CVE members"):
        for record in iter_cve_records(path, log=_quiet):
            seen.append(record)
    assert len(seen) == 9


def test_corrupt_count_under_the_member_grace_is_tolerated(tmp_path):
    """50 corrupt of 55: far over 1%, but not over the 50-member grace —
    a fixture-sized corpus with a few bad files must not abort."""
    path = _write_zip(tmp_path / "c.zip", good=5, bad=50)
    assert len(list(iter_cve_records(path, log=_quiet))) == 5


def test_corrupt_share_under_one_percent_is_tolerated_at_scale(tmp_path):
    """60 corrupt of 6060: over the member grace but under the 1% share."""
    assert fetch_cvelist.MAX_SKIPPED_MEMBERS == 50
    assert fetch_cvelist.MAX_SKIPPED_SHARE == 0.01
    stats = {"members": 6060, "skipped": 60}
    fetch_cvelist._check_skip_rate(stats, "big.zip", _quiet)  # no raise
    stats = {"members": 6060, "skipped": 61}
    with pytest.raises(RuntimeError, match="61 of 6060"):
        fetch_cvelist._check_skip_rate(stats, "big.zip", _quiet)
