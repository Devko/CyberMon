"""Claims audit for the Time-to-PoC copy (test_claims_breach.py pattern).

Each entry quotes site/js/editorial.js VERBATIM (test_claims_anchors.py
enforces the anchor) and asserts the committed number still sits in a range
where the sentence stays true. Ranges are calibrated from the live fetch of
2026-07-21 (median gap 2025: -12 days; KEV trend preempted 80.7% of 228;
coverage 2025: critical 8.3% vs medium 1.0%; union 29,360 CVEs of 367,886
records) and deliberately tolerant — nightly drift must not trip them, only
a claim becoming untrue should. When one fails, fix the copy AND this test
together, or fix the pipeline; never silence the test.

Skips itself when site/data holds sample data or the file is missing (the
file first appears after the module's first nightly run).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parents[2] / "site" / "data"

_meta_path = DATA_DIR / "meta.json"
if not _meta_path.exists():
    pytest.skip(
        "site/data/meta.json missing — no committed data to audit",
        allow_module_level=True,
    )
_META = json.loads(_meta_path.read_text("utf-8"))
if _META.get("sample") is True:
    pytest.skip(
        "site/data holds sample data — claims audit only judges real data",
        allow_module_level=True,
    )

GENERATION_YEAR = int(_META["generated_at"][:4])


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return json.loads(path.read_text("utf-8"))


# --------------------------------------------------------------------------
# Claim checks (verbatim copy in the comments — grep it in editorial.js).
# --------------------------------------------------------------------------


def check_median_hugs_zero_since_mid_2000s(d: dict) -> None:
    # editorial.js (exploits.html hero): "Since the mid-2000s the median
    # has hugged zero". (Live fetch 2026-07: every complete-year median
    # from 2005 on sits between -30 and +4 days.)
    modern = [r for r in d["hero"]["years"]
              if 2005 <= r["year"] < GENERATION_YEAR]
    assert modern, "no complete years charted — the claim has no subject"
    worst = max(abs(r["median_days"]) for r in modern)
    assert worst <= 45, (
        f"'Since the mid-2000s the median has hugged zero' needs every "
        f"complete-year median from 2005 on inside +/-45 days; the worst "
        f"year is {worst} days out"
    )


def check_early_records_catalogued_an_arsenal(d: dict) -> None:
    # editorial.js (exploits.html hero): "early CVE records were
    # cataloguing an arsenal that already existed". (Live fetch 2026-07:
    # 1999-2002 medians run -800 to -88 days, 96-98% negative.)
    early = [r for r in d["hero"]["years"] if r["year"] <= 2002]
    if not early:
        pytest.skip("no pre-2003 years survive the min-n gate")
    assert all(r["median_days"] < 0 for r in early), (
        f"'cataloguing an arsenal that already existed' needs every "
        f"charted pre-2003 median negative; data says "
        f"{[(r['year'], r['median_days']) for r in early]}"
    )


def check_four_in_five_kev_preempted(d: dict) -> None:
    # editorial.js (exploits.html #2): "roughly four in five listings with
    # a dated PoC were beaten to the announcement". (Live 2026-07: 80.7%.)
    pct = d["kev_preempt"]["trend"]["pct_preempted"]
    n = d["kev_preempt"]["trend"]["with_poc_date"]
    assert 65 <= pct <= 92, (
        f"'roughly four in five listings with a dated PoC were beaten to "
        f"the announcement' claims ~80%; data says {pct}% (over {n} entries)"
    )


def check_four_in_ten_of_catalog_matched(d: dict) -> None:
    # editorial.js (exploits.html #2 methodology): "entries with a dated
    # PoC, roughly four in ten of the catalog". (Live 2026-07: 38.8%.)
    kp = d["kev_preempt"]
    with_poc = kp["trend"]["with_poc_date"] + kp["seeding"]["with_poc_date"]
    share = 100.0 * with_poc / kp["total_kev"]
    assert 25 <= share <= 55, (
        f"'roughly four in ten of the catalog' claims ~40%; data says "
        f"{share:.1f}% ({with_poc} of {kp['total_kev']})"
    )


def check_overwhelming_majority_uncovered(d: dict) -> None:
    # editorial.js (exploits.html #3): "the overwhelming majority of
    # records never attract tracked public exploit code at all".
    # (Live 2026-07: 1.9% of the 2025 window covered.)
    cov = d["coverage"]
    rows = cov["buckets"] + [cov["unscored"]]
    total = sum(r["total"] for r in rows)
    covered = sum(r["with_poc"] for r in rows)
    assert total > 0
    share = 100.0 * covered / total
    assert share <= 15, (
        f"'the overwhelming majority of records never attract tracked "
        f"public exploit code' needs window coverage well under half; "
        f"data says {share:.1f}%"
    )


def check_criticals_several_times_middle(d: dict) -> None:
    # editorial.js (exploits.html #3): "criticals draw public exploit
    # attention at several times the rate of the middle of the scale".
    # (Live 2026-07: 8.3% vs 1.0%.)
    rows = {r["bucket"]: r for r in d["coverage"]["buckets"]}
    critical = rows.get("9.0-10.0")
    medium = rows.get("4.0-6.9")
    assert critical and medium, "both buckets must survive the min-n gate"
    assert medium["pct"] > 0, "middle-bucket coverage vanished entirely"
    ratio = critical["pct"] / medium["pct"]
    assert ratio >= 2.5, (
        f"'several times the rate of the middle of the scale' needs the "
        f"critical/medium coverage ratio comfortably above 2; data says "
        f"{critical['pct']}% vs {medium['pct']}% (x{ratio:.1f})"
    )


def check_few_percent_ever_get_a_poc(d: dict) -> None:
    # editorial.js (exploits.html hero methodology): "only a few percent of
    # records ever get a tracked public exploit". (Live 2026-07: 29,360
    # union CVEs against 367,886 corpus records = 8.0%.)
    cve_count = _META["sources"]["cvelist"]["cve_count"]
    share = 100.0 * d["catalog"]["union_cves"] / cve_count
    assert 0.5 <= share <= 12, (
        f"'only a few percent of records ever get a tracked public "
        f"exploit' claims single digits; data says {share:.1f}% "
        f"({d['catalog']['union_cves']} of {cve_count})"
    )


CLAIMS = [
    (
        "Since the mid-2000s the median has hugged zero",
        "time_to_poc.json",
        check_median_hugs_zero_since_mid_2000s,
    ),
    (
        "early CVE records were cataloguing an arsenal that already existed",
        "time_to_poc.json",
        check_early_records_catalogued_an_arsenal,
    ),
    (
        "roughly four in five listings with a dated PoC were beaten to the announcement",
        "time_to_poc.json",
        check_four_in_five_kev_preempted,
    ),
    (
        "roughly four in ten of the catalog",
        "time_to_poc.json",
        check_four_in_ten_of_catalog_matched,
    ),
    (
        "the overwhelming majority of records never attract tracked public exploit code at all",
        "time_to_poc.json",
        check_overwhelming_majority_uncovered,
    ),
    (
        "criticals draw public exploit attention at several times the rate of the middle of the scale",
        "time_to_poc.json",
        check_criticals_several_times_middle,
    ),
    (
        "only a few percent of records ever get a tracked public exploit",
        "time_to_poc.json",
        check_few_percent_ever_get_a_poc,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
