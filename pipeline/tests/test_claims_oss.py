"""Claims audit for the Open-Source Maintainers module (oss.html and its
home card).

The copy (site/js/editorial.js) makes claims about
site/data/oss_maintainers.json. Each CLAIMS entry quotes the copy verbatim
and asserts the data still sits where the sentence stays true. The thresholds
leave margin: publish rights and Scorecard results move slowly, and an
ordinary month of drift must not trip them; only a claim becoming untrue
should. No guard reads a calendar year, so the January rehearsals do not
touch this module.

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim and threshold, in the same
commit) or the pipeline broke (fix the pipeline). NEVER silence a failing
claim check without doing one of the two.

Skips itself when site/data/ holds sample data or the file is missing.
"""
from __future__ import annotations

import json

import pytest

from . import claims_support

DATA_DIR = claims_support.DATA_DIR

_meta_path = DATA_DIR / "meta.json"
if not _meta_path.exists():
    pytest.skip("site/data/meta.json missing — no committed data to audit",
                allow_module_level=True)
if json.loads(_meta_path.read_text("utf-8")).get("sample") is True:
    pytest.skip("site/data holds sample data — claims audit only judges "
                "real data", allow_module_level=True)

FILE = "oss_maintainers.json"


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return claims_support.read_json(path)


def eco(d: dict, eco_id: str) -> dict:
    return next(e for e in d["ecosystems"] if e["id"] == eco_id)


def share(n: int, d: int) -> float:
    return 100.0 * n / d if d else 0.0


def bucket(e: dict, check: str, label: str) -> int:
    return next(b["n"] for b in e["scorecard"]["checks"][check]
                if b["label"] == label)


def judged(e: dict, check: str) -> int:
    return e["scorecard"]["scored"] - e["scorecard"]["not_reported"][check]


def check_250_per_registry(d: dict) -> None:
    # Every "250 most-depended-on" sentence: the frozen list holds 250
    # packages per registry, and (almost) all are still on their registry.
    assert d["universe"]["per_ecosystem"] == 250, d["universe"]
    for e in d["ecosystems"]:
        assert e["packages"] == 250, e["id"]
        assert e["measured"] >= 240, (
            f"{e['id']}: only {e['measured']} of 250 still on the registry — "
            f"the '250 most-depended-on' wording needs the denominator")


def check_one_in_five_single_account(d: dict) -> None:
    # oss.html hero + home card: "In each of four registries, more than one
    # in five of the 250 most-depended-on packages have only one account
    # that can publish them."
    # (2026-11-05: npm 26.8%, PyPI 29.6%, crates.io 41.2%, RubyGems 26.0% —
    # the lowest is 15 packages clear of 20%.) A package that a team or
    # organisation can also publish is not single-account.
    check_250_per_registry(d)
    for e in d["ecosystems"]:
        pct = share(e["single_account"]["n"], e["measured"])
        assert pct > 20.0, (
            f"{e['id']}: single-account share {pct:.1f}% — 'more than one in "
            f"five' no longer holds in every registry")


def check_crates_ten_accounts_third(d: dict) -> None:
    # oss.html section 2: "On crates.io, ten accounts can publish more than a
    # third of the 250 most-depended-on crates." (2026-11-05: 104 of 250,
    # 41.6% — 21 crates clear of a third.) A lower bound: teams are not
    # ranked.
    check_250_per_registry(d)
    e = eco(d, "crates")
    top10 = next(t for t in e["shared"]["top"] if t["k"] == 10)
    assert share(top10["n"], e["measured"]) > 100.0 / 3, (
        f"crates.io: the ten accounts with the most rights reach "
        f"{top10['n']} of {e['measured']} — not more than a third")


def check_maintained_zero_third(d: dict) -> None:
    # oss.html section 3: "More than a third of the repositories behind the
    # crates.io and RubyGems packages score 0 on Scorecard's Maintained
    # check." (2026-11-05:
    # crates.io 75 of 178 = 42.1%, RubyGems 82 of 189 = 43.4%.) Denominator:
    # repositories with a recent Scorecard result that reports the check.
    for eco_id in ("crates", "rubygems"):
        e = eco(d, eco_id)
        n, total = bucket(e, "Maintained", "0"), judged(e, "Maintained")
        assert total >= 100, f"{eco_id}: only {total} scored repositories"
        assert share(n, total) > 100.0 / 3, (
            f"{eco_id}: {n} of {total} repositories score 0 on Maintained — "
            f"not more than a third")


def check_signed_releases_mostly_inconclusive(d: dict) -> None:
    # oss.html section 3 note: "For most repositories in every registry,
    # Scorecard returned Signed-Releases as inconclusive: it found no release
    # files to check." (2026-11-05: npm 161/169, PyPI 142/213, crates.io
    # 176/178, RubyGems 174/189; PyPI, the lowest, at 66.7%.)
    for e in d["ecosystems"]:
        n = bucket(e, "Signed-Releases", "inconclusive")
        total = judged(e, "Signed-Releases")
        assert share(n, total) > 50.0, (
            f"{e['id']}: {n} of {total} Signed-Releases results inconclusive "
            f"— not 'most'")


def check_reread_weekly(d: dict) -> None:
    # Home card: "The package list is fixed per edition and each package is
    # re-read weekly." — the rolling refresh re-reads every observation
    # once it is seven days old, and an edition needs all of them fresh.
    assert d["observed"]["refresh_days"] == 7, d["observed"]
    assert d["observed"]["max_age_days"] <= 14, d["observed"]
    assert d["universe"]["edition"] and d["universe"]["rule_version"] >= 1


def check_counts_only(d: dict) -> None:
    # Home card: "Only counts are published, never a package or account
    # name." — the emitted file holds no package, account or repository
    # name. Every string must be a date, the edition or a fixed label (the
    # contract's own allowlist, re-checked here against the committed file).
    # contracts first: it registers module contracts from its own bottom.
    from pipeline import contracts  # noqa: F401
    from pipeline.oss_contracts import _scan_strings
    from pipeline.oss_universe import load_universe

    _scan_strings(d, "oss_maintainers")
    text = json.dumps(d)
    leaked = [p.name for p in load_universe().packages
              if len(p.name) > 3 and f'"{p.name}"' in text
              and p.name not in {"npm"}]
    assert not leaked, f"package names in the emitted file: {leaked[:5]}"


# --------------------------------------------------------------------------
# (verbatim claim from editorial.js, data file, assertion)
# --------------------------------------------------------------------------
CLAIMS = [
    (
        "In each of four registries, more than one in five of the 250 "
        "most-depended-on packages have only one account that can publish "
        "them.",
        FILE,
        check_one_in_five_single_account,
    ),
    (
        "On crates.io, ten accounts can publish more than a third of the 250 "
        "most-depended-on crates.",
        FILE,
        check_crates_ten_accounts_third,
    ),
    (
        "More than a third of the repositories behind the crates.io and "
        "RubyGems packages score 0 on Scorecard's Maintained check.",
        FILE,
        check_maintained_zero_third,
    ),
    (
        "For most repositories in every registry, Scorecard returned "
        "Signed-Releases as inconclusive: it found no release files to "
        "check.",
        FILE,
        check_signed_releases_mostly_inconclusive,
    ),
    (
        "The package list is fixed per edition and each package is re-read "
        "weekly.",
        FILE,
        check_reread_weekly,
    ),
    (
        "Only counts are published, never a package or account name.",
        FILE,
        check_counts_only,
    ),
    (
        "For the 250 most-depended-on packages in each of npm, PyPI, "
        "crates.io and RubyGems",
        FILE,
        check_250_per_registry,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
