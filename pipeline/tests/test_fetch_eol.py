"""Unit tests for the endoflife.date fetcher/parser (pipeline/fetch_eol.py)."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from pipeline import fetch_eol as fe

FIX = Path(__file__).parent / "fixtures" / "eol_products_full.json"


def _doc() -> dict:
    return json.loads(FIX.read_text("utf-8"))


def _rel(name="1", release="2020-01-01", eol="2022-01-01", is_eol=True,
         **extra):
    rel = {"name": name, "codename": None, "label": name,
           "releaseDate": release, "isLts": False, "ltsFrom": None,
           "isEol": is_eol, "eolFrom": eol, "isMaintained": not is_eol,
           "latest": None, "custom": None}
    rel.update(extra)
    return rel


def _big_doc(n_products=120, lines_each=2) -> dict:
    result = [{"name": f"p{i}", "label": f"P{i}", "category": "app",
               "releases": [_rel(str(j)) for j in range(lines_each)]}
              for i in range(n_products)]
    return {"schema_version": "1.2.1", "generated_at": "2026-11-05T00:00:00+00:00",
            "total": n_products, "result": result}


# ---------------------------------------------------------------- parse

def test_fixture_parses_every_product_and_line():
    snap = fe.load_full_file(FIX)
    assert snap.product_count == 8
    assert snap.line_count == 24
    assert snap.malformed == 0
    assert snap.schema_version == "1.2.1"
    assert snap.upstream_generated_at == "2026-11-05T00:09:15+00:00"
    os_ = next(p for p in snap.products if p.name == "demo-os")
    assert os_.category == "os" and os_.label == "Demo OS"
    line = os_.lines[0]
    assert line.release == "2024-04-01" and line.eol == "2099-04-01"
    assert line.has_eoas and line.eoas == "2026-04-01"
    assert line.is_eol is False


def test_lines_without_active_support_fields_have_no_phase():
    snap = fe.load_full_file(FIX)
    fw = next(p for p in snap.products if p.name == "demo-framework")
    assert all(not ln.has_eoas and ln.eoas is None for ln in fw.lines)


def test_null_end_dates_parse_as_none():
    snap = fe.load_full_file(FIX)
    phone = next(p for p in snap.products if p.name == "demo-phone")
    x1 = next(ln for ln in phone.lines if ln.name == "x1")
    assert x1.eol is None and x1.is_eol is True   # ended, no date
    lang = next(p for p in snap.products if p.name == "demo-lang")
    four = next(ln for ln in lang.lines if ln.name == "4")
    assert four.eol is None and four.is_eol is False   # open
    assert four.has_eoas and four.eoas is None and four.is_eoas is False


def test_default_floor_refuses_a_small_catalogue():
    with pytest.raises(ValueError, match="truncated catalogue"):
        fe.parse_full(_doc())


def test_total_must_match_the_list():
    doc = _doc()
    doc["total"] = 9
    with pytest.raises(ValueError, match="'total' says 9"):
        fe.parse_full(doc, min_products=1)


@pytest.mark.parametrize("doc", [[], {"result": {}}, {"total": 1}, "x"])
def test_wrong_document_shape_raises(doc):
    with pytest.raises(ValueError, match="expected an object"):
        fe.parse_full(doc, min_products=1)


def test_product_without_category_raises():
    doc = _doc()
    del doc["result"][0]["category"]
    with pytest.raises(ValueError, match="without a name, category"):
        fe.parse_full(doc, min_products=1)


def test_duplicate_product_raises():
    doc = _doc()
    doc["result"].append(copy.deepcopy(doc["result"][0]))
    doc["total"] += 1
    with pytest.raises(ValueError, match="duplicate product"):
        fe.parse_full(doc, min_products=1)


@pytest.mark.parametrize("bad", [
    {"releaseDate": "not a date"},
    {"releaseDate": None},
    {"eolFrom": "2019-01-01"},           # ends before it was released
    {"isEol": "yes"},
    {"eoasFrom": "2019-01-01"},
])
def test_unusable_release_is_skipped_and_counted(bad):
    doc = _big_doc()
    doc["result"][0]["releases"][0].update(bad)
    snap = fe.parse_full(doc)
    assert snap.malformed == 1
    assert snap.line_count == 120 * 2 - 1


def test_too_many_unusable_releases_raise():
    doc = _big_doc()
    for p in doc["result"][:3]:
        for rel in p["releases"]:
            rel["releaseDate"] = "bad"
    with pytest.raises(ValueError, match="ceiling"):
        fe.parse_full(doc)


def test_state_round_trip(tmp_path):
    snap = fe.load_full_file(FIX)
    snap.etag = '"abc"'
    fe.save_state(tmp_path, snap)
    back = fe.load_state(tmp_path)
    assert back.etag == '"abc"'
    assert [p.to_state() for p in back.products] == \
        [p.to_state() for p in snap.products]


def test_unreadable_state_is_ignored(tmp_path):
    (tmp_path / fe.STATE_NAME).write_bytes(b"not gzip")
    assert fe.load_state(tmp_path, log=lambda m: None) is None


# ---------------------------------------------------------------- network

class _Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"HTTP {self.status_code}")


class _Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


def test_fetch_downloads_then_reuses_on_304(tmp_path):
    body = _big_doc()
    s1 = _Session([_Resp(200, body, {"ETag": '"v1"'})])
    snap = fe.fetch_full(tmp_path, session=s1, log=lambda m: None)
    assert snap.product_count == 120 and not snap.not_modified
    assert s1.calls[0][0] == fe.EOL_URL
    assert "If-None-Match" not in s1.calls[0][1]["headers"]
    assert (tmp_path / fe.STATE_NAME).exists()

    s2 = _Session([_Resp(304)])
    again = fe.fetch_full(tmp_path, session=s2, log=lambda m: None)
    assert again.not_modified is True
    assert again.product_count == 120
    assert s2.calls[0][1]["headers"]["If-None-Match"] == '"v1"'


def test_one_request_per_night(tmp_path):
    s = _Session([_Resp(200, _big_doc(), {"ETag": '"v1"'})])
    fe.fetch_full(tmp_path, session=s, log=lambda m: None)
    assert len(s.calls) == 1


def test_304_without_a_cache_raises(tmp_path):
    s = _Session([_Resp(304)])
    with pytest.raises(ValueError, match="304 without a cached copy"):
        fe.fetch_full(tmp_path, session=s, log=lambda m: None)


def test_shrunk_dump_is_refused_against_the_prior_edition(tmp_path):
    s = _Session([_Resp(200, _big_doc(n_products=120))])
    with pytest.raises(ValueError, match="below the 90% floor"):
        fe.fetch_full(tmp_path, session=s, prior_products=489,
                      log=lambda m: None)
    assert not (tmp_path / fe.STATE_NAME).exists()


def test_shrunk_dump_is_refused_against_the_cache(tmp_path):
    fe.fetch_full(tmp_path, session=_Session([_Resp(200, _big_doc(200))]),
                  log=lambda m: None)
    with pytest.raises(ValueError, match="below the 90% floor"):
        fe.fetch_full(tmp_path, session=_Session([_Resp(200, _big_doc(120))]),
                      log=lambda m: None)


def test_server_errors_retry_then_raise(tmp_path):
    import requests

    s = _Session([_Resp(503), _Resp(503), _Resp(503)])
    with pytest.raises(requests.HTTPError):
        fe.fetch_full(tmp_path, session=s, sleep=lambda x: None,
                      log=lambda m: None)
    assert len(s.calls) == 3
