"""The corpus-size floor: a CVE corpus only grows, so a nightly whose
record count falls below 97% of the previous edition's is refused."""
from __future__ import annotations

import json

from pipeline.__main__ import CORPUS_FLOOR_RATIO, _corpus_floor_error, main


def _write_meta(out, cve_count, generated_at="2026-09-07T02:00:00Z"):
    out.mkdir(parents=True, exist_ok=True)
    (out / "meta.json").write_text(json.dumps({
        "generated_at": generated_at, "sample": False,
        "sources": {"cvelist": {"release": "cve_prev",
                                "cve_count": cve_count}}}),
        encoding="utf-8")


def test_ratio_is_97_percent():
    assert CORPUS_FLOOR_RATIO == 0.97


def test_no_previous_edition_means_nothing_to_compare(tmp_path):
    assert _corpus_floor_error(tmp_path, 5) is None


def test_unreadable_or_shapeless_previous_meta_is_not_a_failure(tmp_path):
    (tmp_path / "meta.json").write_text("{not json", encoding="utf-8")
    assert _corpus_floor_error(tmp_path, 5) is None
    (tmp_path / "meta.json").write_text(json.dumps({"sources": {}}),
                                        encoding="utf-8")
    assert _corpus_floor_error(tmp_path, 5) is None
    _write_meta(tmp_path, cve_count="lots")
    assert _corpus_floor_error(tmp_path, 5) is None
    _write_meta(tmp_path, cve_count=0)
    assert _corpus_floor_error(tmp_path, 5) is None


def test_growth_and_small_dips_pass(tmp_path):
    _write_meta(tmp_path, cve_count=300_000)
    assert _corpus_floor_error(tmp_path, 300_500) is None   # grew
    assert _corpus_floor_error(tmp_path, 300_000) is None   # flat
    assert _corpus_floor_error(tmp_path, 291_000) is None   # exactly 97%
    assert _corpus_floor_error(tmp_path, 295_000) is None   # a dedupe fix


def test_shrink_below_the_floor_is_refused_with_a_clear_message(tmp_path):
    _write_meta(tmp_path, cve_count=300_000)
    msg = _corpus_floor_error(tmp_path, 290_999)
    assert msg is not None
    assert "290999" in msg and "300000" in msg and "97%" in msg
    assert "2026-09-07T02:00:00Z" in msg
    # the delta-release failure mode: a few hundred records
    assert "shrank" in _corpus_floor_error(tmp_path, 400)


def test_offline_fixture_run_skips_the_floor(tmp_path, capsys):
    """Fixture corpora are eleven records; the floor is a production
    guard and must not fire under --offline-fixtures even when a huge
    previous edition sits in the out dir."""
    _write_meta(tmp_path, cve_count=1_000_000)
    assert main(["--offline-fixtures", "--out", str(tmp_path)]) == 0
    meta = json.loads((tmp_path / "meta.json").read_text(encoding="utf-8"))
    assert meta["sources"]["cvelist"]["cve_count"] == 11
    assert "corpus shrank" not in capsys.readouterr().err
