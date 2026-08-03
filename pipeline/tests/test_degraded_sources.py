"""Single-upstream modules degrade; they never abort the nightly.

HIBP (Breach Ledger), Ransomwhere (Extortion Ledger) and APNIC (Hygiene
Index) each feed exactly one module. When one is down, that module carries
its previous edition forward marked stale — the other twelve modules, and
the append-only history files that can never be rebuilt for a missed date,
still get their nightly run. Ransomwhere 502'd through two entire nightly
windows in August 2026; that is the scenario these tests pin.
"""
from __future__ import annotations

import json

from pipeline.__main__ import _carry_forward, _carry_forward_source

GENERATED_AT = "2026-08-03T05:59:00Z"


def _write(path, obj) -> None:
    path.write_text(json.dumps(obj), encoding="utf-8")


def test_carry_forward_restamps_and_marks_stale(tmp_path):
    _write(tmp_path / "extortion_ledger.json",
           {"generated_at": "2026-08-01T05:41:00Z", "catalog": {"total_usd": 7}})

    carried = _carry_forward(tmp_path, "extortion_ledger.json", GENERATED_AT,
                             "Ransomwhere fetch failed (HTTPError(502))")

    # tonight's edition stamp, last night's numbers, honestly labeled
    assert carried["generated_at"] == GENERATED_AT
    assert carried["stale"] is True
    assert carried["catalog"] == {"total_usd": 7}


def test_carry_forward_invents_nothing_without_a_prior_file(tmp_path):
    assert _carry_forward(tmp_path, "extortion_ledger.json", GENERATED_AT,
                          "upstream down") is None


def test_carry_forward_invents_nothing_from_an_unreadable_prior(tmp_path):
    (tmp_path / "breach_ledger.json").write_text("{not json", encoding="utf-8")
    assert _carry_forward(tmp_path, "breach_ledger.json", GENERATED_AT,
                          "upstream down") is None


def test_carry_forward_source_reuses_last_nights_block(tmp_path):
    _write(tmp_path / "meta.json", {"sources": {
        "ransomwhere": {"fetched_at": "2026-08-01T05:41:00Z",
                        "address_count": 9, "tx_count": 21},
        "hibp": {"fetched_at": "2026-08-01T05:41:00Z", "breach_count": 3},
    }})

    rw = _carry_forward_source(tmp_path, "ransomwhere")
    # verbatim block (it validated last night) + the stale marker the
    # footer renders as "(carried forward)"
    assert rw == {"fetched_at": "2026-08-01T05:41:00Z", "address_count": 9,
                  "tx_count": 21, "stale": True}
    assert _carry_forward_source(tmp_path, "hibp")["stale"] is True


def test_carry_forward_source_none_when_absent_or_unusable(tmp_path):
    assert _carry_forward_source(tmp_path, "ransomwhere") is None  # no meta

    _write(tmp_path / "meta.json", {"sources": {"hibp": {"breach_count": 3}}})
    assert _carry_forward_source(tmp_path, "ransomwhere") is None  # no block

    (tmp_path / "meta.json").write_text("{not json", encoding="utf-8")
    assert _carry_forward_source(tmp_path, "hibp") is None


def test_carried_meta_block_still_satisfies_the_contract(tmp_path):
    """A degraded run must not smuggle a contract violation into meta."""
    from pipeline import contracts

    _write(tmp_path / "meta.json", {"sources": {
        "ransomwhere": {"fetched_at": "2026-08-01T05:41:00Z",
                        "address_count": 9, "tx_count": 21}}})
    meta = {
        "generated_at": GENERATED_AT,
        "sample": False,
        "sources": {
            "cvelist": {"release": "cve_2026-08-03_0500Z", "cve_count": 1},
            "epss": {"model_version": "v5", "score_date": "2026-08-02",
                     "row_count": 1},
            "kev": {"catalog_version": "2026.08.02", "count": 1},
            "ransomwhere": _carry_forward_source(tmp_path, "ransomwhere"),
        },
    }
    contracts.validate("meta.json", meta)  # raises on any mismatch
