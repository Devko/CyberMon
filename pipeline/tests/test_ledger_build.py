"""tools/claims_ledger.py: the Claims Ledger's builder (site/ledger.html).

Unit tests of its parts (the editorial.js reader, quote location, page
mapping, margin arithmetic, ``claims_support.record``) and one end-to-end
run of the tool against the committed data. Not named test_claims_*: the
ledger runs those suites, and must not run itself.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools import claims_ledger as cl  # noqa: E402

from . import claims_support  # noqa: E402
from .test_claims_anchors import (PARAPHRASE_EXEMPT,  # noqa: E402
                                  _claims_modules)

EDITORIAL = ROOT / "site" / "js" / "editorial.js"


@pytest.fixture(scope="module")
def editorial() -> dict:
    return cl.read_editorial(EDITORIAL)


def _all_quotes() -> list[tuple[str, str]]:
    return [(mod.__name__.split(".")[-1], row[0])
            for mod in _claims_modules() for row in getattr(mod, "CLAIMS", [])]


# ---- record() ------------------------------------------------------------------

def test_record_is_a_noop_outside_the_ledger():
    assert claims_support._LEDGER is None
    assert claims_support.record(5, lo=1, unit="x") is None


def test_record_appends_while_the_ledger_listens():
    sink: list = []
    claims_support._LEDGER = sink
    try:
        claims_support.record(52.9, lo=50, hi=200 / 3, unit="%", note="2025")
        claims_support.record(None)
    finally:
        claims_support._LEDGER = None
    assert sink == [
        {"value": 52.9, "lo": 50, "hi": 200 / 3, "unit": "%", "note": "2025"},
        {"value": None, "lo": None, "hi": None, "unit": "", "note": ""},
    ]


def test_record_never_raises():
    claims_support._LEDGER = ()          # no .append: bookkeeping breaks
    try:
        claims_support.record(1, lo=0)   # ... and the guard carries on
    finally:
        claims_support._LEDGER = None


# ---- reading editorial.js --------------------------------------------------------

def test_reader_returns_the_editorial_object(editorial):
    assert {"nav", "home", "sections", "ui"} <= set(editorial)
    assert editorial["nav"][0]["id"] == "home"
    ids = [i["id"] for i in editorial["home"]["instruments"]["items"]]
    assert "ledger" in ids
    # concatenated strings are joined, consts resolved
    assert editorial["repoUrl"].startswith("https://github.com/")
    assert all(isinstance(s, str) for _, s in cl.flatten(editorial))


def test_strings_remember_their_line(editorial):
    lines = EDITORIAL.read_text("utf-8").splitlines()
    checked = 0
    for path, text in cl.flatten(editorial):
        if path[0] in ("repoUrl", "pipelineUrl") or "\n" in text:
            continue        # a const reference; an escaped newline
        # a wrapped string starts on its line with its first literal
        assert text[:12] in lines[text.line - 1], (path, text.line)
        checked += 1
    assert checked > 1000


def test_every_claim_quote_is_located(editorial):
    strings = list(cl.flatten(editorial))
    missing = [(suite, q) for suite, q in _all_quotes()
               if q not in PARAPHRASE_EXEMPT and not cl.locate(q, strings)]
    assert not missing, missing


def test_locate_treats_placeholders_as_wildcards():
    strings = [(("sections", "x", "note"), "In 2025, 52.9% of all records.")]
    assert cl.locate("In {year}, {pct} of all records.", strings) == \
        [("sections", "x", "note")]
    assert cl.locate("In {year}, {pct} of no records.", strings) == []


def test_every_section_has_a_page(editorial):
    pages, section_page = cl.page_index(editorial)
    missing = sorted(set(editorial["sections"]) - set(section_page))
    assert not missing, f"sections no page script lists: {missing}"
    for page in set(section_page.values()):
        assert (ROOT / "site" / pages[page]["href"]).exists(), page


def test_home_card_quote_places_on_the_overview(editorial):
    pages, section_page = cl.page_index(editorial)
    i = next(i for i, m in enumerate(editorial["home"]["modules"])
             if m["id"] == "c2")
    key, entry, field = cl.place(("home", "modules", i, "headline"),
                                 editorial, pages, section_page)
    assert key == "card:c2" and field == "headline"
    assert entry["page"] == "home" and entry["href"] == "index.html"
    key, entry, field = cl.place(("sections", "c2_age", "caption"),
                                 editorial, pages, section_page)
    assert (key, entry["page"], entry["href"], field) == \
        ("c2_age", "c2", "c2.html#s-c2_age", "caption")


# ---- margins ---------------------------------------------------------------------

@pytest.mark.parametrize(("raw", "margin", "share", "side"), [
    ({"value": 52.9, "lo": 50, "hi": 200 / 3}, 2.9, 0.0548, "lo"),
    ({"value": 5, "hi": 10}, 5, 1.0, "hi"),
    ({"value": 15, "hi": 10}, -5, -0.3333, "hi"),        # past the bound
    ({"value": 0, "hi": 1}, 1, 1.0, "hi"),               # share of the bound
    ({"value": 20.4, "lo": 17, "hi": 24}, 3.4, 0.1667, "lo"),
])
def test_margin_is_the_distance_to_the_nearest_bound(raw, margin, share,
                                                     side):
    m = cl.measure(raw)
    assert m["margin"] == pytest.approx(margin)
    assert m["share"] == pytest.approx(share, abs=1e-4)
    assert m["side"] == side and not m["exact"]


@pytest.mark.parametrize("raw", [
    {"value": 1, "lo": 1, "hi": 1},     # "one credit before 2025"
    {"value": 0, "hi": 0},              # "nothing bends"
])
def test_a_claim_with_no_room_is_exact(raw):
    m = cl.measure(raw)
    assert m["exact"] and m["margin"] == 0 and m["share"] is None


def test_unbounded_or_missing_values_have_no_margin():
    assert cl.measure({"value": 3})["margin"] is None
    assert cl.measure({"value": None, "lo": 1})["margin"] is None
    assert cl.measure({"value": float("nan"), "lo": 1})["value"] is None


def test_tightest_is_the_smallest_share():
    ms = [cl.measure(r) for r in ({"value": 41.6, "lo": 40, "hi": 60},
                                  {"value": 56.6, "lo": 40, "hi": 62},
                                  {"value": 0, "hi": 0})]
    assert cl.tightest(ms) == 0
    assert cl.tightest(ms[2:]) == 0       # exact only when nothing else
    assert cl.tightest([cl.measure({"value": 3})]) is None


def test_suites_follow_the_anchor_rule():
    names = {p.stem for p in cl.suite_files()}
    assert names == {m.__name__.split(".")[-1] for m in _claims_modules()}
    assert "test_ledger_build" not in names


# ---- the tool against the committed data --------------------------------------------

def test_ledger_of_the_committed_data(tmp_path):
    meta = claims_support.META
    if not meta or meta.get("sample") is True:
        pytest.skip("no real edition to build a ledger from")
    out = tmp_path / "claims_ledger.json"
    run = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "claims_ledger.py"),
         "--data-dir", str(claims_support.DATA_DIR), "--out", str(out)],
        cwd=ROOT, capture_output=True, text=True, timeout=300)
    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]
    ledger = json.loads(out.read_text("utf-8"))

    assert ledger["schema_version"] == cl.SCHEMA_VERSION
    assert ledger["edition"] == meta["generated_at"]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",
                        ledger["generated_at"])
    claims, s = ledger["claims"], ledger["summary"]

    # one row per CLAIMS row, each with a result
    quotes = sorted(q for _, q in _all_quotes())
    assert sorted(c["quote"] for c in claims) == quotes
    assert s["claims"] == len(claims) == s["pass"] + s["fail"] + s["skip"]
    assert {c["status"] for c in claims} <= {"pass", "fail", "skip"}
    assert all(c.get("message") for c in claims if c["status"] != "pass")

    # every row is placed on a page section the ledger describes
    for c in claims:
        assert c["where"] or c["quote"] in PARAPHRASE_EXEMPT, c["quote"]
        for w in c["where"]:
            sec = ledger["sections"][w["section"]]
            assert sec["page"] in ledger["pages"], sec
            if sec["href"]:
                assert (ROOT / "site" / sec["href"].split("#")[0]).exists()

    # the guard links point at the guard's def line
    for c in claims[::23]:
        path = ROOT / c.get("path", f"pipeline/tests/{c['suite']}.py")
        line = path.read_text("utf-8").splitlines()[c["line"] - 1]
        assert line.startswith(f"def {c['guard']}("), (c["guard"], line)

    # measures and the summary agree
    tight = [c["measures"][c["tightest"]] for c in claims
             if c["tightest"] is not None]
    assert s["measured"] == len(tight) > 0
    assert s["near"] == sum(m["share"] is not None
                            and m["share"] < ledger["near_share"]
                            for m in tight)
    for m in tight:
        assert m["value"] is not None and m["margin"] is not None
    # small enough to ship nightly
    assert out.stat().st_size < 300_000


def test_committed_ledger_is_readable():
    path = claims_support.DATA_DIR / "claims_ledger.json"
    if not path.exists():
        pytest.skip("no committed ledger in this edition")
    ledger = json.loads(path.read_text("utf-8"))
    assert ledger["schema_version"] == cl.SCHEMA_VERSION
    assert ledger["claims"] and ledger["summary"]["claims"] == \
        len(ledger["claims"])
