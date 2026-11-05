"""Claims audit for the Detection Rules module (sigma.html; pattern:
test_claims_c2.py).

The sigma.html copy and its home card (site/js/editorial.js) make verbal
claims about site/data/sigma_coverage.json. Each CLAIMS entry quotes the
copy verbatim and asserts the data still sits where the sentence stays
true. Ranges are tolerant: ordinary drift — SigmaHQ merging a month of
rules, a point release of ATT&CK — must not trip them; only a claim
becoming untrue should.

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim + range, in the same
commit) or the pipeline broke (fix the pipeline). NEVER silence a failing
claim check without doing one of the two.

Skips itself when site/data/ holds sample data or the file is missing —
this audit only ever judges the committed real data.
"""
from __future__ import annotations

import json
import re

import pytest

from . import claims_support

DATA_DIR = claims_support.DATA_DIR

_meta_path = DATA_DIR / "meta.json"
if not _meta_path.exists():
    pytest.skip(
        "site/data/meta.json missing — no committed data to audit",
        allow_module_level=True,
    )
if json.loads(_meta_path.read_text("utf-8")).get("sample") is True:
    pytest.skip(
        "site/data holds sample data — claims audit only judges real data",
        allow_module_level=True,
    )


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return claims_support.read_json(path)


_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def check_counts_not_rules(d: dict) -> None:
    # editorial.js (sigma.html churn methodology): "The pipeline republishes
    # no rule, only these counts." Structural red line, the one that keeps
    # the Detection Rule License's attribution terms out of play: no rule
    # id (a UUID), title, author or detection logic anywhere in the file.
    def walk(node, path="sigma_coverage"):
        if isinstance(node, dict):
            for k, v in node.items():
                assert k not in ("title", "author", "detection", "logsource"), (
                    f"{path}.{k}: rule content in the emitted file")
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str):
            assert not _UUID_RE.search(node), (
                f"{path}: {node!r} looks like a Sigma rule id")

    walk(d)


def check_fifth_of_peak(d: dict) -> None:
    # editorial.js (sigma.html hero headline): "The SigmaHQ repository holds
    # about a fifth as many rules dated 2025 as rules dated 2022, its peak
    # year." (2026-11-05: 222 rules dated 2025 vs 1,023 dated 2022, 21.7%;
    # 2023 725, 2024 284.) Only judged (complete) years compete for the
    # peak; the band 15–27% keeps "about a fifth" true through a month of
    # merges carrying old dates or a few outright deletions.
    years = {y["year"]: y["added"] for y in d["years"]
             if claims_support.judged(y["year"])}
    assert 2022 in years and 2025 in years, sorted(years)
    peak = max(years, key=lambda y: years[y])
    assert peak == 2022, f"'2022, its peak year' — the peak is now {peak} " \
                         f"({years[peak]} rules)"
    ratio = years[2025] / years[2022]
    assert 0.15 <= ratio <= 0.27, (
        f"'about a fifth as many rules dated 2025 as rules dated 2022' vs "
        f"{years[2025]}/{years[2022]} = {ratio:.1%}")


def check_coverage_fell_since_2023(d: dict) -> None:
    # editorial.js (sigma.html coverage headline, and the home card): "The
    # share of ATT&CK techniques with at least one Sigma rule has fallen
    # since 2023, from more than four in five to about three in four."
    # (2026-11-05: 2023 quarter ends 82.8 / 81.5 / 82.6 / 80.9%, now 75.3%
    # = 171 of 227.) "About three in four" holds for 70–79%: an ATT&CK
    # release adding five untagged techniques (~73.7%) or SigmaHQ tagging
    # five more (~77.5%) stays inside. The fall must be real: tonight below
    # every 2023 quarter end by at least three points.
    rows = {q["quarter"]: q["pct"] for q in d["quarters"]
            if q["pct"] is not None}
    y2023 = [rows[f"2023Q{i}"] for i in range(1, 5)]
    now = d["coverage"]["pct"]
    assert max(y2023) > 80.0, (
        f"'from more than four in five' — 2023 quarter ends {y2023}")
    assert 70.0 <= now < 80.0, f"'about three in four' vs {now}%"
    assert now <= min(y2023) - 3.0, (
        f"'has fallen since 2023' — now {now}% vs 2023 quarter ends {y2023}")


def check_most_recent_techniques_uncovered(d: dict) -> None:
    # editorial.js (sigma.html lag headline): "Most techniques ATT&CK added
    # since 2023 have no Sigma rule." (2026-11-05: 30 of the 35 active
    # techniques that entered ATT&CK on or after 2023-01-01 have no rule
    # outside the deprecated folder; 86%.) "Have no Sigma rule" is today's
    # active-rule count, the same test the coverage chart applies.
    recent = [t for t in d["techniques"] if t["debut_date"] >= "2023-01-01"]
    assert len(recent) >= 20, (
        f"only {len(recent)} techniques entered since 2023 — too few for "
        f"'most'")
    without = [t["id"] for t in recent if t["rules"] == 0]
    assert len(without) / len(recent) > 0.5, (
        f"'most ... have no Sigma rule' vs {len(without)} of {len(recent)}")


def check_pre_intrusion_tactics_lowest(d: dict) -> None:
    # editorial.js (sigma.html tactics headline): "Reconnaissance and
    # resource development, the two tactics ATT&CK lists before initial
    # access, have among the lowest Sigma coverage." (2026-11-05: 58.3% and
    # 55.6%, the two lowest of 15; next exfiltration 60.0%, execution
    # 63.6%.) "Among the lowest" = both in the bottom third of the
    # tactics by share, which survives one or two newly tagged techniques.
    tactics = d["tactics"]
    order = [t["id"] for t in d["attack"]["tactics"]]
    assert order[:3] == ["reconnaissance", "resource-development",
                         "initial-access"], (
        f"'the two tactics ATT&CK lists before initial access' vs {order[:3]}")
    assert len(tactics) >= 12, f"only {len(tactics)} tactics"
    ranked = sorted(tactics, key=lambda t: (t["pct"], t["id"]))
    bottom = {t["id"] for t in ranked[:len(tactics) // 3]}
    for tid in ("reconnaissance", "resource-development"):
        assert tid in bottom, (
            f"'{tid} ... among the lowest' — bottom third is "
            f"{sorted(bottom)}; ranking {[(t['id'], t['pct']) for t in ranked]}")


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "The pipeline republishes no rule, only these counts.",
        "sigma_coverage.json",
        check_counts_not_rules,
    ),
    (
        "The SigmaHQ repository holds about a fifth as many rules dated 2025 "
        "as rules dated 2022, its peak year.",
        "sigma_coverage.json",
        check_fifth_of_peak,
    ),
    (
        "The share of ATT&CK techniques with at least one Sigma rule has "
        "fallen since 2023, from more than four in five to about three in "
        "four.",
        "sigma_coverage.json",
        check_coverage_fell_since_2023,
    ),
    (
        "Most techniques ATT&CK added since 2023 have no Sigma rule.",
        "sigma_coverage.json",
        check_most_recent_techniques_uncovered,
    ),
    (
        "Reconnaissance and resource development, the two tactics ATT&CK "
        "lists before initial access, have among the lowest Sigma coverage.",
        "sigma_coverage.json",
        check_pre_intrusion_tactics_lowest,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
