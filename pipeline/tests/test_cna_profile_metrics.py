"""CNA profiles (cna_profiles.json): CNA-container extraction, the window
of complete years, the volume floor, the per-CNA metrics, competition
ranks, the summary spread, the rescore join, and the contract."""
from __future__ import annotations

import copy

import pytest

from pipeline import contracts, metrics
from pipeline.cna_profile_metrics import (build_cna_profiles,
                                          competition_ranks, score_bin)
from pipeline.metrics import extract_facts

GENERATED_AT = "2026-11-05T06:00:00Z"  # window 2021-2025


def _record(cve_id, cna, published, *, score=None, cwe=None, version=None,
            adp_cwe=None, state="PUBLISHED"):
    cna_c: dict = {"providerMetadata": {"shortName": cna}}
    if score is not None:
        cna_c["metrics"] = [{"cvssV3_1": {"baseScore": score}}]
    if cwe is not None:
        cna_c["problemTypes"] = [{"descriptions": [{"cweId": cwe}]}]
    if version is not None:
        cna_c["affected"] = [{"versions": [{"version": version,
                                            "status": "affected"}]}]
    meta = {"cveId": cve_id, "state": state, "assignerShortName": cna}
    if published is not None:
        meta["datePublished"] = f"{published}T00:00:00Z"
    rec = {"cveMetadata": meta, "containers": {"cna": cna_c}}
    if adp_cwe is not None:
        rec["containers"]["adp"] = [{
            "providerMetadata": {"shortName": "CISA-ADP"},
            "problemTypes": [{"descriptions": [{"cweId": adp_cwe}]}]}]
    return rec


def _agg(records, kev=(), poc=()) -> metrics.Aggregator:
    agg = metrics.Aggregator(kev_ids=kev, poc_ids=poc)
    agg.consume(records)
    return agg


def _corpus():
    recs = []
    # "big": 4 published in-window records, one rejected, one 2026 record
    # (partial year: outside the window) and one 2020 record (too old).
    recs.append(_record("CVE-2021-0001", "big", "2021-03-01", score=9.8,
                        cwe="CWE-79", version="1.0"))
    recs.append(_record("CVE-2022-0002", "big", "2022-03-01", score=5.0,
                        cwe="CWE-89"))
    recs.append(_record("CVE-2023-0003", "big", "2023-03-01", score=10.0))
    recs.append(_record("CVE-2025-0004", "big", "2025-12-31",
                        adp_cwe="CWE-20", version="n/a"))
    recs.append(_record("CVE-2024-0005", "big", "2024-01-01",
                        state="REJECTED"))
    recs.append(_record("CVE-2026-0006", "big", "2026-01-02", score=1.0,
                        cwe="CWE-1"))
    recs.append(_record("CVE-2020-0007", "big", "2020-06-01", score=1.0))
    # "small": 2 published in-window records, both with a CWE and a score.
    recs.append(_record("CVE-2023-0101", "small", "2023-01-01", score=7.5,
                        cwe="CWE-22", version="2.1"))
    recs.append(_record("CVE-2023-0102", "small", "2023-02-01", score=4.0,
                        cwe="CWE-22", version="2.2"))
    # "tiny": one record — below a floor of 2.
    recs.append(_record("CVE-2023-0201", "tiny", "2023-01-01", score=3.3,
                        cwe="CWE-22"))
    return recs


def _build(**kw):
    agg = _agg(_corpus(), kev={"CVE-2021-0001", "CVE-2023-0101"},
               poc={"CVE-2021-0001", "CVE-2022-0002"})
    kw.setdefault("min_published", 2)
    kw.setdefault("min_scored", 2)
    return build_cna_profiles(agg, GENERATED_AT, **kw)


def _row(obj, cna):
    return next(r for r in obj["cnas"] if r["cna"] == cna)


# ------------------------------------------------------------ extraction

def test_cna_container_flags_ignore_adp_enrichment():
    facts = extract_facts(_record("CVE-2025-0004", "big", "2025-12-31",
                                  adp_cwe="CWE-20"))
    assert facts.cwe == "CWE-20"          # record-level: ADP fills it
    assert facts.cna_has_cwe is False     # but the CNA named none
    facts = extract_facts(_record("CVE-2023-0101", "small", "2023-01-01",
                                  cwe="CWE-22", version="2.1"))
    assert facts.cna_has_cwe and facts.cna_has_affected


def test_placeholder_versions_are_not_usable_affected_data():
    facts = extract_facts(_record("CVE-2025-0004", "big", "2025-12-31",
                                  version="n/a"))
    assert facts.cna_has_affected is False


def test_rejected_records_never_join_the_profile_tallies():
    agg = _agg([_record("CVE-2024-0005", "big", "2024-01-01", cwe="CWE-1",
                        state="REJECTED")], kev={"CVE-2024-0005"})
    assert not agg.cna_year_profile


# --------------------------------------------------------------- builder

def test_window_is_the_last_five_complete_years():
    obj = _build()
    assert obj["window"] == {"from": 2021, "to": 2025, "years": 5}
    big = _row(obj, "big")
    # 2020 and 2026 records are outside; the rejection is inside
    assert big["published"] == 4 and big["rejected"] == 1


def test_volume_floor_and_largest_first():
    obj = _build()
    assert [r["cna"] for r in obj["cnas"]] == ["big", "small"]
    assert obj["all"]["cna_count"] == 3          # tiny counts in the pool
    assert obj["all"]["published"] == 7
    contracts.validate("cna_profiles.json", obj)


def test_per_cna_values():
    obj = _build()
    big = _row(obj, "big")
    assert big["counts"] == {"scored": 3, "cwe": 2, "affected": 1,
                             "kev": 1, "exploit": 2}
    v = big["values"]
    assert v["cwe_pct"] == 50.0          # the ADP-only CWE does not count
    assert v["scored_pct"] == 75.0
    assert v["affected_pct"] == 25.0     # "n/a" is a placeholder
    assert v["rejected_pct"] == 20.0     # 1 / (4 + 1)
    assert v["kev_pct"] == 25.0 and v["exploit_pct"] == 50.0
    assert v["score_median"] == 9.8      # median of 5.0, 9.8, 10.0
    # 10.0 falls in the top bin, 5.0 in 5.0-5.9
    assert big["score_bins"] == [0, 0, 0, 0, 0, 1, 0, 0, 0, 2]


def test_pooled_scores_cover_every_cna():
    obj = _build()
    pooled = obj["all"]
    assert pooled["scored"] == 6         # big 3 + small 2 + tiny 1
    assert sum(pooled["score_bins"]) == 6
    assert pooled["score_median"] == 6.2  # median of 3.3 4 5 7.5 9.8 10


def test_score_median_needs_min_scored():
    obj = _build(min_scored=3)
    assert _row(obj, "big")["values"]["score_median"] == 9.8
    small = _row(obj, "small")
    assert small["values"]["score_median"] is None
    assert small["ranks"]["score_median"] is None
    assert small["score_bins"] == [0, 0, 0, 0, 1, 0, 0, 1, 0, 0]
    assert obj["summary"]["score_median"]["n"] == 1
    contracts.validate("cna_profiles.json", obj)


def test_rescores_count_only_same_version_changes():
    rows = [
        {"observed_date": "2026-07-15", "cna": "big",
         "change_type": "rescore"},
        {"observed_date": "2026-08-01", "cna": "big",
         "change_type": "rescore"},
        {"observed_date": "2026-08-02", "cna": "big",
         "change_type": "first_score"},
        {"observed_date": "2026-09-01", "cna": "small",
         "change_type": "version_shift"},
        {"observed_date": "2026-10-01", "cna": "tiny",
         "change_type": "rescore"},
    ]
    obj = _build(rescore_rows=rows)
    assert _row(obj, "big")["values"]["rescores"] == 2
    assert _row(obj, "small")["values"]["rescores"] == 0
    assert obj["rescore_log"] == {"first_observed": "2026-07-15",
                                  "last_observed": "2026-10-01",
                                  "rescores": 3}
    contracts.validate("cna_profiles.json", obj)


def test_empty_rescore_log_is_null_dated():
    obj = _build()
    assert obj["rescore_log"] == {"first_observed": None,
                                  "last_observed": None, "rescores": 0}


def test_competition_ranks_share_the_best_rank():
    ranks = competition_ranks({"a": 9.0, "b": 5.0, "c": 5.0, "d": 1.0,
                               "e": None})
    assert ranks == {"a": 1, "b": 2, "c": 2, "d": 4, "e": None}


def test_summary_is_the_median_cna_and_quartiles():
    obj = _build()
    s = obj["summary"]["cwe_pct"]
    assert s == {"n": 2, "median": 75.0, "p25": 62.5, "p75": 87.5,
                 "min": 50.0, "max": 100.0}


@pytest.mark.parametrize("score,index", [(0.0, 0), (0.9, 0), (3.9, 3),
                                         (9.0, 9), (10.0, 9)])
def test_score_bins_are_whole_points(score, index):
    assert score_bin(score) == index


def test_empty_corpus_is_valid():
    obj = build_cna_profiles(metrics.Aggregator(), GENERATED_AT)
    assert obj["cnas"] == [] and obj["summary"]["cwe_pct"]["n"] == 0
    contracts.validate("cna_profiles.json", obj)


# -------------------------------------------------------------- contract

@pytest.mark.parametrize("mutate", [
    lambda o: o["window"].update({"to": 2026}),
    lambda o: o["window"].update({"years": 4}),
    lambda o: o["cnas"][1].update({"published": 1}),
    lambda o: o["cnas"].reverse(),
    lambda o: o["cnas"][0]["ranks"].update({"cwe_pct": 1}),
    lambda o: o["cnas"][0]["values"].update({"cwe_pct": 51.0}),
    lambda o: o["cnas"][0]["values"].update({"rejected_pct": 25.0}),
    lambda o: o["cnas"][0]["score_bins"].append(0),
    lambda o: o["cnas"][0]["counts"].update({"kev": 99}),
    lambda o: o["summary"]["cwe_pct"].update({"median": 60.0}),
    lambda o: o["summary"]["cwe_pct"].update({"n": 3}),
    lambda o: o["all"].update({"scored": 7}),
    lambda o: o["rescore_log"].update({"first_observed": "2026-07-15"}),
    lambda o: o.update({"metrics": o["metrics"][:-1]}),
    lambda o: o["cnas"][0]["values"].update({"score_median": None}),
])
def test_contract_rejects(mutate):
    obj = _build()
    contracts.validate("cna_profiles.json", obj)
    bad = copy.deepcopy(obj)
    mutate(bad)
    with pytest.raises(contracts.ContractViolation):
        contracts.validate("cna_profiles.json", bad)
