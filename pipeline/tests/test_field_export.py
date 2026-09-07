"""The Field export: record layout, collector rules, joins, contract."""
from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from pipeline import contracts, field_export as fe
from pipeline.fetch_kev import KevEntry
from pipeline.metrics import Aggregator, CveFacts, extract_facts

FIXTURES = Path(__file__).parent / "fixtures"


def _facts(cve_id="CVE-2023-0001", state="PUBLISHED", date="2023-01-15",
           cna="VendorX", cna_scores=None, adp_scores=None, cwe="CWE-79"):
    return CveFacts(cve_id=cve_id, state=state, year=int(cve_id[4:8]),
                    cna=cna, cna_scores=cna_scores or {},
                    adp_scores=adp_scores or {}, date_published=date, cwe=cwe)


def _record(vendor="VendorX"):
    return {"containers": {"cna": {"affected": [
        {"vendor": vendor, "product": "Widget"}]}}}


# ------------------------------------------------------------ collector

def test_collector_places_published_dated_records_only():
    c = fe.FieldCollector()
    c(_facts(), _record())
    c(_facts(cve_id="CVE-2023-0002", state="REJECTED"), _record())
    c(_facts(cve_id="CVE-2023-0003", date=None), _record())
    c(_facts(cve_id="CVE-1998-0001", date="1998-06-01"), _record())
    assert [r.seq for r in c.rows] == [1]
    assert c.skipped_rejected == 1
    assert c.skipped_undated == 2  # no date, and a date before the epoch


def test_collector_day_index_and_id_year():
    c = fe.FieldCollector()
    c(_facts(cve_id="CVE-2020-99999", date="1999-01-02"), _record())
    row = c.rows[0]
    assert row.day == 1
    assert row.year == 2020  # the ID year, not the publication year
    assert row.seq == 99999


def test_score_follows_effective_score_precedence():
    """Newest CVSS family anywhere in the record wins, CNA before ADP within
    a family — exactly ``CveFacts.effective_score``, so the Field and the
    inflation chart can never disagree about a record's score."""
    c = fe.FieldCollector()
    c(_facts(cna_scores={"v3": 7.5}, adp_scores={"v4": 9.9}), _record())
    c(_facts(cve_id="CVE-2023-0002", adp_scores={"v2": 4.3}), _record())
    c(_facts(cve_id="CVE-2023-0003"), _record())
    c(_facts(cve_id="CVE-2023-0004", cna_scores={"v3": 5.0},
             adp_scores={"v3": 8.0}), _record())
    assert (c.rows[0].score, c.rows[0].version) == (99, 4)
    assert (c.rows[3].score, c.rows[3].version) == (50, 3)
    assert (c.rows[1].score, c.rows[1].version) == (43, 2)
    assert (c.rows[2].score, c.rows[2].version) == (fe.NO_SCORE, 0)


def test_cwe_number_and_vendor_normalisation():
    c = fe.FieldCollector()
    c(_facts(cwe="CWE-787"), _record("  Acme   Corp "))
    c(_facts(cve_id="CVE-2023-0002", cwe="CWE-noinfo"), _record("n/a"))
    c(_facts(cve_id="CVE-2023-0003", cwe=None),
      {"containers": {"cna": {}}})
    assert (c.rows[0].cwe, c.rows[0].vendor) == (787, "acme corp")
    assert (c.rows[1].cwe, c.rows[1].vendor) == (0, "")
    assert (c.rows[2].cwe, c.rows[2].vendor) == (0, "")


def test_collector_rides_the_aggregator_pass():
    """The observer sees exactly the records the Aggregator folds."""
    records = [json.loads(p.read_text(encoding="utf-8"))
               for p in sorted((FIXTURES / "cvelist").glob("*.json"))]
    agg = Aggregator()
    c = fe.FieldCollector()
    agg.consume(records, observer=c)
    placed = len(c.rows) + c.skipped_rejected + c.skipped_undated
    assert placed == agg.cve_count
    assert c.rows  # the fixture corpus has published, dated records


# --------------------------------------------------------------- encode

def _rows():
    c = fe.FieldCollector()
    c(_facts(cna_scores={"v3": 9.8}), _record("acme"))
    c(_facts(cve_id="CVE-2023-0002", cna="Other", cwe=None), _record("acme"))
    c(_facts(cve_id="CVE-2021-0007", date="2021-03-03"), _record("zed"))
    return c


def test_encode_round_trip_and_joins():
    c = _rows()
    kev = [KevEntry(cve_id="CVE-2023-0001", date_added="2023-02-01",
                    due_date=None, ransomware_use="Known")]
    blob, meta = fe.encode(
        c.rows, epss_scores={"CVE-2023-0001": 0.9731, "CVE-2021-0007": 0.0},
        kev_entries=kev, poc_ids={"CVE-2021-0007"},
        nvd_statuses={"CVE-2023-0002": "Awaiting Analysis"})
    assert len(blob) == 3 * fe.RECORD_BYTES
    rows = fe.decode(blob)
    # sorted by (year, seq): 2021-0007 first
    years = [r[0] for r in rows]
    assert years == [2021, 2023, 2023]
    (year, seq, day, score, ver, epss, cna, cwe, vendor, kevday, flags) = rows[1]
    assert (year, seq) == (2023, 1)
    assert day == (fe.date(2023, 1, 15) - fe.EPOCH).days
    assert (score, ver) == (98, 3)
    assert epss == 9731
    assert meta["cnas"][cna] == "VendorX"
    assert cwe == 79
    assert meta["vendors"][vendor] == "acme"
    assert kevday == (fe.date(2023, 2, 1) - fe.EPOCH).days
    assert flags & fe.FLAG_KEV and flags & fe.FLAG_RANSOMWARE
    assert not flags & fe.FLAG_POC
    # the PoC-only, EPSS-0 record
    r = rows[0]
    assert r[5] == 0 and r[10] & fe.FLAG_POC and not r[10] & fe.FLAG_KEV
    # NVD status rides bits 3-5
    r = rows[2]
    assert (r[10] >> fe.STATUS_SHIFT) & 7 == \
        fe.STATUS_CODES.index("Awaiting Analysis")
    assert r[5] == fe.NO_EPSS
    assert meta["counts"] == {"kev": 1, "poc": 1, "scored": 1, "epss": 2}
    assert meta["n"] == 3
    assert meta["first_day"] == rows[0][2]
    assert meta["last_day"] == max(x[2] for x in rows)


def test_index_tables_rank_by_volume_and_reserve_other():
    c = _rows()
    _, meta = fe.encode(c.rows, epss_scores={}, kev_entries=[], poc_ids=(),
                        nvd_statuses=None)
    assert meta["cnas"][0] == "VendorX"  # two records beat one
    assert meta["vendors"][:2] == ["other", "acme"]


def test_decode_rejects_partial_records():
    with pytest.raises(ValueError):
        fe.decode(b"\x00" * (fe.RECORD_BYTES + 1))


# ---------------------------------------------------------------- build

def test_build_writes_validated_outputs(tmp_path):
    c = _rows()
    packed, meta = fe.build(
        c, "2026-09-07T02:00:00Z", epss_scores={}, kev_entries=[],
        poc_ids=(), nvd_statuses=None,
        sources={"cvelist": {"release": "fixtures"}})
    contracts.validate("field.json", meta)  # registered like every output
    assert gzip.decompress(packed) == fe.encode(
        c.rows, epss_scores={}, kev_entries=[], poc_ids=(),
        nvd_statuses=None)[0]
    assert meta["raw_bytes"] == 3 * fe.RECORD_BYTES
    assert meta["bin_bytes"] == len(packed)
    assert meta["skipped"] == {"rejected": 0, "undated": 0}
    fe.write(tmp_path, packed, meta)
    assert (tmp_path / fe.BIN_NAME).read_bytes() == packed
    assert json.loads((tmp_path / fe.META_NAME).read_text())["n"] == 3


def test_contract_rejects_size_mismatch_and_empty_field():
    c = _rows()
    _, meta = fe.build(c, "2026-09-07T02:00:00Z", epss_scores={},
                       kev_entries=[], poc_ids=(), nvd_statuses=None,
                       sources={})
    bad = dict(meta, raw_bytes=meta["raw_bytes"] + 1)
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("field.json", bad)
    empty = fe.FieldCollector()
    _, meta0 = fe.build(empty, "2026-09-07T02:00:00Z", epss_scores={},
                        kev_entries=[], poc_ids=(), nvd_statuses=None,
                        sources={})
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("field.json", meta0)


def test_gzip_is_deterministic():
    c = _rows()
    a, _ = fe.build(c, "2026-09-07T02:00:00Z", epss_scores={},
                    kev_entries=[], poc_ids=(), nvd_statuses=None, sources={})
    b, _ = fe.build(c, "2026-09-07T02:00:00Z", epss_scores={},
                    kev_entries=[], poc_ids=(), nvd_statuses=None, sources={})
    assert a == b


def test_extract_facts_state_drives_the_rejected_skip():
    """Guard the coupling: the collector reads ``facts.state`` exactly as
    ``extract_facts`` spells it (upper-cased), so a REJECTED fixture record
    must land in ``skipped_rejected`` and never in ``rows``."""
    rejected = None
    for p in (FIXTURES / "cvelist").glob("*.json"):
        rec = json.loads(p.read_text(encoding="utf-8"))
        if rec["cveMetadata"].get("state") == "REJECTED":
            rejected = rec
            break
    if rejected is None:
        pytest.skip("no REJECTED record in the fixture corpus")
    c = fe.FieldCollector()
    c(extract_facts(rejected), rejected)
    assert c.rows == [] and c.skipped_rejected == 1
