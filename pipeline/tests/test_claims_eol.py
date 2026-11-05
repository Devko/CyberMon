"""Claims audit for the Support Windows module (eol.html).

The copy (site/js/editorial.js, sections eol_*, and the home card) makes
verbal claims about site/data/support_windows.json. Each CLAIMS entry
quotes the copy verbatim and asserts the data still sits where the sentence
stays true. The figures are pooled medians over three release years each
and over every tracked product, so ordinary nightly drift moves them by a
day or two; the ranges below leave room for that and fail only when a
sentence stops being true.

Robustness checked when the copy was written (2026-11-05, 489 products):
dropping a random 5% of products 200 times kept the panel change between
-28% and -10% (90% of draws -25% to -16%), the phase ratio between 1.88
and 2.04, devices on top and server applications at the bottom in every
draw; moving the snapshot date forward three months changed none of them.

When a test here fails: either the world changed (fix the copy in
site/js/editorial.js AND this test's quoted claim + range, in the same
commit) or the pipeline broke (fix the pipeline). NEVER silence a failing
claim check without doing one of the two.

Skips itself when site/data/ holds sample data or the files are missing.
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


def load(name: str) -> dict:
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} missing — nothing to audit")
    return claims_support.read_json(path)


def check_same_products_fifth_shorter(d: dict) -> None:
    # Hero headline and home card. (2026-11-05: 195 products; pooled
    # medians 1,065 days for 2014-2016 lines, 853 for 2022-2024: -19.9%.)
    # "About a fifth" holds from -27% to -13%.
    assert d["panel"]["early"] == [2014, 2016], d["panel"]
    assert d["panel"]["late"] == [2022, 2024], d["panel"]
    assert d["panel"]["products"] >= 100, (
        f"'the same products' is a panel of only {d['panel']['products']}")
    pan = d["periods"]["panel"]
    assert pan["early"]["median_days"] and pan["late"]["median_days"], (
        f"a panel median was not reached: {pan}")
    assert -27.0 <= pan["change_pct"] <= -13.0, (
        f"'about a fifth shorter' vs a change of {pan['change_pct']}%")


def check_both_groups_fell(d: dict) -> None:
    # Hero caption: both medians "fell", and the all-products periods
    # "hold different products". (2026-11-05: all -42.4%, panel -19.9%;
    # 436 products with 2022-2024 lines, 195 of them also in 2014-2016.)
    for key in ("panel", "all"):
        chg = d["periods"][key]["change_pct"]
        assert chg is not None and chg <= -5.0, (
            f"'fell' for {key} vs a change of {chg}%")
    late = d["periods"]["all"]["late"]["products"]
    panel = d["panel"]["products"]
    assert late - panel >= 0.25 * late, (
        f"'its two periods hold different products': only {late - panel} "
        f"of {late} products with 2022-2024 lines lack 2014-2016 lines")


def check_security_twice_active(d: dict) -> None:
    # Phases headline. (2026-11-05: 168 products; pooled medians 548 days
    # to the end of active support, 1,092 to the end of security support:
    # 1.99x. Settled release years since 2017: 1.75x to 2.28x.) "About
    # twice" holds from 1.6x to 2.5x pooled; no settled recent year may
    # fall under 1.4x.
    ph = d["phases"]
    assert ph["products"] >= 50, f"only {ph['products']} products list both"
    act, sec = ph["active_median_days"], ph["security_median_days"]
    assert act and sec, f"a pooled phase median was not reached: {ph}"
    ratio = sec / act
    assert 1.6 <= ratio <= 2.5, f"'about twice as long' vs {ratio:.2f}x"
    for r in ph["years"]:
        if r["year"] < 2017 or r["provisional"] or \
                not claims_support.judged(r["year"]):
            continue
        a, s = r["active_median_days"], r["security_median_days"]
        if not a or not s:
            continue
        assert s / a >= 1.4, (
            f"{r['year']}: security support ends only {s / a:.2f}x as long "
            f"after release as active support")


def check_devices_longest_server_apps_shortest(d: dict) -> None:
    # Categories headline. (2026-11-05: devices 2,191 days, next cloud
    # services 1,633; server applications 543, next applications 729.)
    # Each end needs a 10% lead so a small shift cannot swap the order
    # under the copy.
    rows = [r for r in d["categories"] if r["median_days"] is not None]
    assert len(rows) >= 4, rows
    top, second = rows[0], rows[1]
    bottom, next_low = rows[-1], rows[-2]
    assert top["category"] == "device", (
        f"longest window is {top['category']}, not devices")
    assert top["median_days"] >= 1.1 * second["median_days"], (
        f"devices {top['median_days']} vs {second['category']} "
        f"{second['median_days']}: too close to call longest")
    assert bottom["category"] == "server-app", (
        f"shortest window is {bottom['category']}, not server applications")
    assert bottom["median_days"] <= 0.9 * next_low["median_days"], (
        f"server applications {bottom['median_days']} vs "
        f"{next_low['category']} {next_low['median_days']}: too close to "
        f"call shortest")


def check_open_lines_censored_not_dropped(d: dict) -> None:
    # Hero methodology: lines with no announced end "count as supported for
    # at least its age", "neither dropped nor treated as ended"; undated
    # ended lines "are left out of the medians". Structural: the
    # catalogue's state counts must cover every line, and the medians must
    # come from a catalogue that has open lines to censor.
    c = d["catalog"]
    assert c["ended"] + c["scheduled"] + c["open"] + c["ended_undated"] == \
        c["lines"], c
    assert c["open"] > 0, "no open lines: the censoring sentence is moot"


CLAIMS = [
    (
        "For the same products, release lines from 2022–2024 have a median "
        "support window about a fifth shorter than lines from 2014–2016.",
        "support_windows.json",
        check_same_products_fifth_shorter,
    ),
    (
        "their median fell from {panel_early} to {panel_late}. “All tracked "
        "products” fell from {all_early} to {all_late}, but its two periods "
        "hold different products",
        "support_windows.json",
        check_both_groups_fell,
    ),
    (
        "Where a product lists both phases, security support ends about "
        "twice as long after a line's release as active support does.",
        "support_windows.json",
        check_security_twice_active,
    ),
    (
        "Devices have the longest median support window of any category, "
        "server applications the shortest.",
        "support_windows.json",
        check_devices_longest_server_apps_shortest,
    ),
    (
        "each such line counts as supported for at least its age on "
        "{as_of}, and is neither dropped nor treated as ended",
        "support_windows.json",
        check_open_lines_censored_not_dropped,
    ),
]


@pytest.mark.parametrize(
    ("claim", "filename", "check"),
    CLAIMS,
    ids=[c[2].__name__ for c in CLAIMS],
)
def test_claim_still_true(claim: str, filename: str, check) -> None:
    check(load(filename))
