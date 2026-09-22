"""OSV export fetcher: record reduction, zip streaming, conditional GETs,
the cached state and the truncation floor. No network."""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from pipeline import fetch_osv
from pipeline.fetch_osv import (G_CVE, G_ECOSYSTEMS, G_NVD_LAG, G_PUBLISHED,
                                G_REVIEWED, G_SEVERITY, G_WITHDRAWN,
                                EcosystemSummary, export_url, fetch_all,
                                fetch_ecosystem, ghsa_row, iter_zip_records,
                                load_fixture_dir, load_state, save_state,
                                summarize_records)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "osv"


def _ghsa(rid="GHSA-aaaa-bbbb-cccc", published="2025-03-04T05:06:07Z",
          aliases=(), severity="HIGH", ecos=("npm",), **extra):
    ds = {"github_reviewed": True, "severity": severity}
    ds.update(extra.pop("ds", {}))
    return {"id": rid, "published": published, "aliases": list(aliases),
            "affected": [{"package": {"name": "p", "ecosystem": e}}
                         for e in ecos],
            "database_specific": ds, **extra}


def _mal(rid="MAL-2025-1", published="2025-11-03T08:00:00Z", eco="npm",
         sources=("amazon-inspector",), **extra):
    rec = {"id": rid, "published": published,
           "affected": [{"package": {"name": "p", "ecosystem": eco}}], **extra}
    if sources is not None:
        rec["database_specific"] = {"malicious-packages-origins": [
            {"source": s} for s in sources]}
    return rec


def _zip(records) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for r in records:
            zf.writestr(f"{r['id']}.json", json.dumps(r))
    return buf.getvalue()


# ---- record reduction -----------------------------------------------------------

def test_ghsa_row_reads_cve_alias_severity_and_nvd_lag():
    row = ghsa_row(_ghsa(aliases=["PYSEC-1", "CVE-2025-1"],
                         ds={"nvd_published_at": "2025-03-14T00:00:00Z"}))
    assert row[G_PUBLISHED] == "2025-03-04"
    assert row[G_CVE] == 1
    assert row[G_SEVERITY] == "HIGH"
    assert row[G_REVIEWED] == 1 and row[G_WITHDRAWN] == 0
    assert row[G_NVD_LAG] == 10


def test_ghsa_row_without_cve_has_no_lag_and_unknown_severity_is_blank():
    row = ghsa_row(_ghsa(aliases=["GHSA-zzzz-zzzz-zzzz"], severity="UNKNOWN",
                         ds={"nvd_published_at": "2025-03-14T00:00:00Z"}))
    assert row[G_CVE] == 0 and row[G_NVD_LAG] is None
    assert row[G_SEVERITY] == ""


def test_ghsa_row_flags_withdrawn_and_unreviewed_and_unions_ecosystems():
    rec = _ghsa(ecos=("Maven", "npm", "Maven"), withdrawn="2025-04-01T00:00:00Z")
    rec["database_specific"].pop("github_reviewed")
    row = ghsa_row(rec)
    assert row[G_WITHDRAWN] == 1 and row[G_REVIEWED] == 0
    assert row[G_ECOSYSTEMS] == ["Maven", "npm"]


def test_ghsa_row_rejects_an_unparseable_publication_date():
    with pytest.raises(ValueError):
        ghsa_row(_ghsa(published="soon"))


def test_summarize_counts_mal_by_month_withdrawn_and_source():
    s = summarize_records("npm", [
        _mal("MAL-1", "2025-11-03T00:00:00Z"),
        _mal("MAL-2", "2025-11-09T00:00:00Z",
             sources=("amazon-inspector", "ghsa-malware"),
             withdrawn="2025-12-01T00:00:00Z"),
        _mal("MAL-3", "2024-06-01T00:00:00Z", sources=None),
        _mal("MAL-1", "2025-11-03T00:00:00Z"),          # duplicate id
        _mal("MAL-4", "2025-11-03T00:00:00Z", eco="PyPI"),  # not this zip's
        {"id": "PYSEC-2024-1", "published": "2024-01-01T00:00:00Z"},
        _ghsa(),
    ])
    assert s.records == 7
    assert s.mal_months == {"2025-11": [2, 1], "2024-06": [1, 0]}
    assert s.mal_sources == {
        "2025-11": {"amazon-inspector": 2, "ghsa-malware": 1},
        "2024-06": {fetch_osv.UNATTRIBUTED: 1}}
    assert s.mal_count == 3
    assert len(s.ghsa) == 1


def test_summarize_strips_the_registry_suffix_of_an_ecosystem():
    s = summarize_records("VSCode", [
        _mal(eco="VSCode:https://open-vsx.org", sources=("socket",))])
    assert s.mal_count == 1


def test_summarize_refuses_a_record_without_an_id():
    with pytest.raises(ValueError):
        summarize_records("npm", [{"published": "2025-01-01"}])


def test_zip_members_are_read_in_place_and_a_corrupt_zip_is_a_value_error():
    recs = [_ghsa(), _mal()]
    assert [r["id"] for r in iter_zip_records(io.BytesIO(_zip(recs)))] == \
        ["GHSA-aaaa-bbbb-cccc", "MAL-2025-1"]
    with pytest.raises(ValueError):
        list(iter_zip_records(io.BytesIO(b"not a zip")))


def test_fixture_directory_loads_one_summary_per_ecosystem():
    summaries = load_fixture_dir(FIXTURES)
    assert set(summaries) == {"npm", "PyPI", "crates.io", "VSCode"}
    assert summaries["VSCode"].mal_count == 1
    assert summaries["npm"].mal_count == 5


def test_export_url_quotes_the_ecosystem_name():
    assert export_url("GitHub Actions").endswith("/GitHub%20Actions/all.zip")
    assert export_url("crates.io").endswith("/crates.io/all.zip")


# ---- network --------------------------------------------------------------------

class FakeResp:
    def __init__(self, status, body=b"", headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise OSError(f"HTTP {self.status_code}")

    def iter_content(self, size):
        for i in range(0, len(self._body), size):
            yield self._body[i:i + size]


class FakeSession:
    def __init__(self, responses):
        self.responses = responses  # url suffix -> FakeResp
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs.get("headers", {})))
        for suffix, resp in self.responses.items():
            if url.endswith(suffix):
                return resp
        raise AssertionError(f"unexpected url {url}")


def test_first_fetch_downloads_and_keeps_the_validators():
    body = _zip([_ghsa(), _mal()])
    sess = FakeSession({"/npm/all.zip": FakeResp(
        200, body, {"ETag": '"e1"', "Last-Modified": "Tue, 22 Sep 2026"})})
    s = fetch_ecosystem(sess, "npm", None, sleep=lambda _: None)
    assert not s.not_modified
    assert (s.etag, s.last_modified) == ('"e1"', "Tue, 22 Sep 2026")
    assert len(s.ghsa) == 1 and s.mal_count == 1
    headers = sess.calls[0][1]
    assert "If-None-Match" not in headers and "If-Modified-Since" not in headers


def test_unchanged_export_is_a_304_that_reuses_the_cache():
    cached = summarize_records("npm", [_ghsa(), _mal()])
    cached.etag, cached.last_modified = '"e1"', "Tue, 22 Sep 2026"
    sess = FakeSession({"/npm/all.zip": FakeResp(304)})
    s = fetch_ecosystem(sess, "npm", cached, sleep=lambda _: None)
    assert s.not_modified and s.ghsa == cached.ghsa
    assert s.mal_months == cached.mal_months
    assert sess.calls[0][1]["If-None-Match"] == '"e1"'
    assert sess.calls[0][1]["If-Modified-Since"] == "Tue, 22 Sep 2026"


def test_a_304_without_a_cached_copy_is_refused():
    sess = FakeSession({"/npm/all.zip": FakeResp(304)})
    with pytest.raises(ValueError):
        fetch_ecosystem(sess, "npm", None, sleep=lambda _: None)


def test_a_truncated_export_is_refused_against_the_cached_count():
    cached = summarize_records("npm", [_mal(f"MAL-{i}") for i in range(20)])
    sess = FakeSession({"/npm/all.zip": FakeResp(200, _zip([_mal()]))})
    with pytest.raises(ValueError, match="floor"):
        fetch_ecosystem(sess, "npm", cached, sleep=lambda _: None)


def test_a_server_error_raises_after_the_retries():
    sess = FakeSession({"/npm/all.zip": FakeResp(503)})
    with pytest.raises(OSError):
        fetch_ecosystem(sess, "npm", None, sleep=lambda _: None,
                        log=lambda _: None)


def test_fetch_all_saves_state_and_the_next_night_is_conditional(tmp_path):
    body = _zip([_ghsa(), _mal()])
    sess = FakeSession({"/npm/all.zip": FakeResp(200, body, {"ETag": '"e1"'}),
                        "/PyPI/all.zip": FakeResp(200, _zip([]),
                                                  {"ETag": '"p1"'})})
    first = fetch_all(tmp_path, sess, ecosystems=("npm", "PyPI"),
                      log=lambda _: None)
    assert fetch_osv.summary_stats(first) == {
        "ecosystems": 2, "downloaded": 2, "not_modified": 0}
    state = load_state(tmp_path)
    assert state["npm"].etag == '"e1"' and len(state["npm"].ghsa) == 1

    sess2 = FakeSession({"/npm/all.zip": FakeResp(304),
                         "/PyPI/all.zip": FakeResp(304)})
    second = fetch_all(tmp_path, sess2, ecosystems=("npm", "PyPI"),
                       log=lambda _: None)
    assert fetch_osv.summary_stats(second)["not_modified"] == 2
    assert second["npm"].ghsa == first["npm"].ghsa


def test_unreadable_or_foreign_state_is_ignored(tmp_path):
    (tmp_path / fetch_osv.STATE_NAME).write_bytes(b"garbage")
    assert load_state(tmp_path, log=lambda _: None) == {}
    save_state(tmp_path, {"npm": EcosystemSummary("npm")})
    assert set(load_state(tmp_path)) == {"npm"}
