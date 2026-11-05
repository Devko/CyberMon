#!/usr/bin/env python3
"""Build site/data/claims_ledger.json, the data behind the Claims Ledger
(site/ledger.html).

A guard is a CLAIMS row in a claims suite (pipeline/tests/test_claims_*.py,
test_adp_claims.py, test_top25_claims.py): a sentence quoted verbatim from
site/js/editorial.js, the data file it is about, and a check function that
asserts the sentence against that file. This tool runs every guard once,
in-process under pytest, and writes one ledger row per guard:

* the quote, and where it sits: the page, the section and the editorial
  field, found by locating the quote in editorial.js the way
  test_claims_anchors.py does ({placeholders} are wildcards, case and
  whitespace are ignored);
* the guard's name, its suite and a link to its source line on GitHub;
* tonight's result (pass, fail or skip, with the reason);
* each value the guard measured and the bounds it held the value to, as
  reported through ``claims_support.record()``, and the margin: the
  distance from the value to the nearest bound, absolute and as a share of
  the value (of the bound, when the value is zero). A negative margin means
  the value is past the bound.

    python tools/claims_ledger.py                       # site/data
    python tools/claims_ledger.py --data-dir /tmp/x/data --out /tmp/l.json
    python tools/claims_ledger.py --check               # exit 1 on a failure

The nightly runs it right after the claims gate, so the file it commits
describes the edition it ships with. It never fails the night on its own:
without --check a failing guard is written down, not raised (the gate step
before it is what fails a night).
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib
import inspect
import json
import math
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "pipeline" / "tests"
EDITORIAL = ROOT / "site" / "js" / "editorial.js"
SITE_JS = ROOT / "site" / "js"
REPO_BLOB = "https://github.com/Devko/CyberMon/blob/main/"
NEAR_SHARE = 0.10      # "within 10% of a bound"
SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# editorial.js: a small reader for the one object literal it exports.
# ---------------------------------------------------------------------------

_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<comment>//[^\n]*|/\*.*?\*/)
  | (?P<string>"(?:[^"\\\n]|\\.)*")
  | (?P<number>-?\d+(?:\.\d+)?)
  | (?P<name>[A-Za-z_$][\w$]*)
  | (?P<punct>[{}\[\]():,+;=])
""", re.X | re.S)

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'",
            "/": "/", "b": "\b", "f": "\f", "0": "\0"}


def _unescape(body: str) -> str:
    def sub(m: re.Match) -> str:
        e = m.group(1)
        if e.startswith("u"):
            return chr(int(e[1:], 16))
        return _ESCAPES.get(e, e)
    return re.sub(r"\\(u[0-9a-fA-F]{4}|.)", sub, body)


def _tokens(src: str, start: int):
    pos = start
    line = src.count("\n", 0, start) + 1
    while pos < len(src):
        m = _TOKEN.match(src, pos)
        if not m:
            # Past the object literal (the tpl() helper's regex, say): stop.
            return
        kind = m.lastgroup
        text = m.group(kind)
        if kind not in ("ws", "comment"):
            yield kind, text, line
        line += text.count("\n")
        pos = m.end()


class _Parser:
    """Recursive descent over the editorial object literal. Values are
    strings (with ``+`` concatenation), numbers, booleans, null, consts
    declared above the object, arrays and objects. Every string keeps the
    line it starts on."""

    def __init__(self, src: str):
        self.consts = {m.group(1): _unescape(m.group(2)) for m in re.finditer(
            r'^const (\w+) = "((?:[^"\\]|\\.)*)";', src, re.M)}
        m = re.search(r"export const editorial\s*=\s*", src)
        if not m:
            raise ValueError("editorial.js: no `export const editorial =`")
        self.toks = _tokens(src, m.end())
        self.cur = next(self.toks)

    def _take(self, kind: str | None = None, text: str | None = None):
        tok = self.cur
        if (kind and tok[0] != kind) or (text and tok[1] != text):
            raise ValueError(f"editorial.js line {tok[2]}: expected "
                             f"{text or kind}, found {tok[1]!r}")
        self.cur = next(self.toks, ("eof", "", tok[2]))
        return tok

    def value(self):
        kind, text, line = self.cur
        if text == "{":
            return self._object()
        if text == "[":
            return self._array()
        parts, first_line = [], line
        while True:
            kind, text, line = self._take()
            if kind == "string":
                parts.append(_unescape(text[1:-1]))
            elif kind == "number":
                parts.append(float(text) if "." in text else int(text))
            elif kind == "name":
                parts.append({"true": True, "false": False,
                              "null": None}.get(text, self.consts.get(text)))
            else:
                raise ValueError(f"editorial.js line {line}: unexpected "
                                 f"{text!r}")
            if self.cur[1] != "+":
                break
            self._take("punct", "+")
        if len(parts) == 1 and not isinstance(parts[0], str):
            return parts[0]
        return _Str("".join(str(p) for p in parts), first_line)

    def _object(self) -> dict:
        self._take("punct", "{")
        out: dict = {}
        while self.cur[1] != "}":
            kind, text, _ = self._take()
            key = _unescape(text[1:-1]) if kind == "string" else text
            self._take("punct", ":")
            out[key] = self.value()
            if self.cur[1] == ",":
                self._take()
        self._take("punct", "}")
        return out

    def _array(self) -> list:
        self._take("punct", "[")
        out: list = []
        while self.cur[1] != "]":
            out.append(self.value())
            if self.cur[1] == ",":
                self._take()
        self._take("punct", "]")
        return out


class _Str(str):
    """A string that remembers its line in editorial.js."""

    def __new__(cls, text: str, line: int):
        obj = super().__new__(cls, text)
        obj.line = line
        return obj


def read_editorial(path: Path = EDITORIAL) -> dict:
    return _Parser(path.read_text("utf-8")).value()


def flatten(node, path: tuple = ()):
    """(path, string) for every string in the editorial object, in order."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from flatten(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from flatten(v, path + (i,))
    elif isinstance(node, str):
        yield path, node


# ---------------------------------------------------------------------------
# Locating a quote: the anchor test's normalisation, applied per string.
# ---------------------------------------------------------------------------

def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def chunks(quote: str) -> list[str]:
    """The quote's literal fragments, {placeholders} as split points. Same
    rule as test_claims_anchors._chunks (fragments of 12+ characters), and
    every non-empty fragment when none is that long."""
    parts = [_norm(p) for p in re.split(r"\{\w+\}", quote)]
    long = [p for p in parts if len(p) >= 12]
    return long or [p for p in parts if p]


def locate(quote: str, strings: list[tuple[tuple, str]]) -> list[tuple]:
    """Paths of the editorial strings that hold the quote: those holding
    every fragment; failing that (a quote that spans two strings), each
    string holding at least one fragment."""
    want = chunks(quote)
    if not want:
        return []
    normed = [(p, _norm(s)) for p, s in strings]
    whole = [p for p, s in normed if all(c in s for c in want)]
    if whole:
        return whole
    squash = [(p, s.replace(" ", "")) for p, s in normed]
    whole = [p for p, s in squash
             if all(c.replace(" ", "") in s for c in want)]
    if whole:
        return whole
    return [p for p, s in normed if any(c in s for c in want)]


# ---------------------------------------------------------------------------
# Where a located string is shown: pages and sections.
# ---------------------------------------------------------------------------

def page_index(editorial: dict, js_dir: Path = SITE_JS
               ) -> tuple[dict[str, dict], dict[str, str]]:
    """(pages, section_page). ``pages``: page id -> {label, href}, in nav
    order, plus the two places copy is shown outside a module page (the
    animated clips, and chrome every page shares). ``section_page``:
    section id -> page id, read from each module page's script (its
    SECTIONS list of ``{ id: "…" }`` entries)."""
    pages: dict[str, dict] = {}
    section_page: dict[str, str] = {}
    for tab in editorial.get("nav", []):
        pages[tab["id"]] = {"label": tab["label"], "href": tab["href"]}
        script = js_dir / f"{tab['id']}.js"
        if tab["id"] == "home" or not script.exists():
            continue
        for sid in re.findall(r'\{\s*id:\s*"(\w+)"',
                              script.read_text("utf-8")):
            section_page.setdefault(sid, tab["id"])
    pages.setdefault("home", {"label": "Overview", "href": "index.html"})
    pages["motion"] = {"label": "Animated clips", "href": None}
    pages["shared"] = {"label": "Every page", "href": None}
    return pages, section_page


def _field(rest: tuple) -> str:
    out = ""
    for p in rest:
        out += f"[{p}]" if isinstance(p, int) else (f".{p}" if out else p)
    return out


def place(path: tuple, editorial: dict, pages: dict[str, dict],
          section_page: dict[str, str]) -> tuple[str, dict, str]:
    """(section key, section entry, field) for one editorial string path.
    The section entry is {page, num, label, href}."""
    head = path[0] if path else ""
    if head == "sections" and len(path) >= 3:
        sid = path[1]
        sec = editorial["sections"].get(sid, {})
        page = section_page.get(sid, "shared")
        href = pages[page]["href"]
        return sid, {"page": page, "num": sec.get("num"),
                     "label": sec.get("kicker") or sid,
                     "href": f"{href}#s-{sid}" if href else None}, \
            _field(path[2:])
    if head == "home" and len(path) >= 4 and path[1] == "modules":
        mod = editorial["home"]["modules"][path[2]]
        return f"card:{mod['id']}", {
            "page": "home", "num": mod.get("num"),
            "label": f"{mod['label']} card", "href": "index.html",
        }, _field(path[3:])
    if head == "motion" and len(path) >= 4 and path[1] == "scenes":
        scene = path[2]
        return f"motion:{scene}", {
            "page": "motion", "num": None, "label": f"{scene} clip",
            "href": None,
        }, _field(path[3:])
    page = "home" if head == "home" else "shared"
    return head or "editorial", {
        "page": page, "num": None, "label": head or "editorial",
        "href": "index.html" if page == "home" else None,
    }, _field(path[1:])


# ---------------------------------------------------------------------------
# Margins
# ---------------------------------------------------------------------------

def _num(v) -> float | None:
    if isinstance(v, bool) or v is None:
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _round(x: float | None, nd: int = 4):
    if x is None:
        return None
    r = round(x, nd)
    return int(r) if r == int(r) and abs(r) < 1e15 else r


def measure(raw: dict) -> dict:
    """One recorded value with its bounds, plus the margin to the nearest
    bound: absolute (``margin``, in the value's unit) and as a share of
    the value, or of the bound when the value is zero (``share``). Negative
    when the value is past the bound. ``exact`` marks a claim with no room
    at all, an exact count (``lo == hi``) or a "none" held at zero: any
    change breaks it, so it has no share."""
    value, lo, hi = (_num(raw.get(k)) for k in ("value", "lo", "hi"))
    out = {"value": _round(value), "lo": _round(lo), "hi": _round(hi),
           "unit": str(raw.get("unit") or ""),
           "note": str(raw.get("note") or ""),
           "margin": None, "share": None, "side": None, "exact": False}
    if value is None:
        return out
    gaps = []
    if lo is not None:
        gaps.append((value - lo, lo, "lo"))
    if hi is not None:
        gaps.append((hi - value, hi, "hi"))
    if not gaps:
        return out
    gap, bound, side = min(gaps, key=lambda g: g[0])
    base = abs(value) or abs(bound)
    exact = (lo is not None and lo == hi) or base == 0
    out.update({"margin": _round(gap), "side": side, "exact": exact,
                "share": None if exact else _round(gap / base)})
    return out


def _slim(m: dict) -> dict:
    """A measure as written to the file: no empty note, ``exact`` only
    when true."""
    return {k: v for k, v in m.items()
            if not (k == "note" and not v) and not (k == "exact" and not v)}


def tightest(measures: list[dict]) -> int | None:
    """Index of the measure closest to its bound: the smallest share; an
    exact measure only when no measure has a share."""
    scored = [(m["share"], m["margin"], i) for i, m in enumerate(measures)
              if m["share"] is not None]
    if scored:
        return min(scored)[2]
    exact = [i for i, m in enumerate(measures) if m["exact"]]
    return exact[0] if exact else None


# ---------------------------------------------------------------------------
# Running the guards
# ---------------------------------------------------------------------------

def suite_files(tests: Path = TESTS) -> list[Path]:
    """The claims suites, by the anchor test's rule."""
    return sorted(p for p in tests.glob("test_*.py")
                  if (p.stem.startswith("test_claims_")
                      or p.stem.endswith("_claims"))
                  and p.stem != "test_claims_anchors")


class LedgerPlugin:
    """Collects one row per CLAIMS guard: the parametrised tests whose
    parameters carry a check function next to a quoted claim. Everything
    else in the suites (structural tests, unit tests of a guard) is
    deselected."""

    def __init__(self):
        self.rows: dict[str, dict] = {}
        self.support = None

    @staticmethod
    def _claim_of(item):
        params = getattr(getattr(item, "callspec", None), "params", {})
        check = params.get("check")
        quote = params.get("claim", params.get("quote"))
        if callable(check) and isinstance(quote, str):
            return quote, params.get("filename"), check
        return None

    def pytest_collection_modifyitems(self, config, items):
        keep, drop = [], []
        for item in items:
            (keep if self._claim_of(item) else drop).append(item)
        if drop:
            config.hook.pytest_deselected(items=drop)
        items[:] = keep
        for idx, item in enumerate(keep):
            quote, filename, check = self._claim_of(item)
            src = Path(inspect.getsourcefile(check)).resolve()
            try:
                rel = src.relative_to(ROOT).as_posix()
            except ValueError:
                rel = src.name
            self.rows[item.nodeid] = {
                "order": idx,
                "suite": Path(str(item.fspath)).stem,
                "guard": check.__name__,
                "path": rel,
                "line": check.__code__.co_firstlineno,
                "quote": quote,
                "file": filename,
                "status": None,
                "message": "",
                "recorded": [],
            }

    def pytest_runtest_call(self, item):
        row = self.rows.get(item.nodeid)
        if row is None:
            return
        self.support = importlib.import_module(
            "pipeline.tests.claims_support")
        row["recorded"] = []
        self.support._LEDGER = row["recorded"]

    def pytest_runtest_teardown(self, item):
        if self.support is not None:
            self.support._LEDGER = None

    def pytest_runtest_logreport(self, report):
        row = self.rows.get(report.nodeid)
        if row is None:
            return
        if report.skipped:
            row["status"] = "skip"
            longrepr = report.longrepr
            reason = (longrepr[2] if isinstance(longrepr, tuple)
                      else str(longrepr))
            row["message"] = re.sub(r"^Skipped: ", "", reason)
        elif report.failed:
            row["status"] = "fail"
            row["message"] = _failure_line(report)
        elif report.when == "call" and row["status"] is None:
            row["status"] = "pass"


def _failure_line(report) -> str:
    crash = getattr(report.longrepr, "reprcrash", None)
    text = crash.message if crash else str(report.longrepr)
    text = text.split("\nassert ")[0]
    text = re.sub(r"^AssertionError:\s*", "", text.strip())
    return re.sub(r"\s+", " ", text).strip()[:400]


def run_guards(data_dir: Path, files: list[Path]) -> list[dict]:
    """Run the guards in-process against ``data_dir`` and return the raw
    rows. CYBERMON_DATA_DIR must be set before claims_support is first
    imported, so this runs once per process."""
    import pytest

    os.environ["CYBERMON_DATA_DIR"] = str(data_dir)
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    plugin = LedgerPlugin()
    args = [str(f) for f in files] + [
        "-q", "-p", "no:cacheprovider", "--rootdir", str(ROOT),
        "-o", "addopts=", "--no-header", "-W", "ignore"]
    code = int(pytest.main(args, plugins=[plugin]))
    # 0 all passed, 1 some failed, 5 nothing collected (the suites skip
    # themselves on sample data); anything else means pytest itself broke.
    if code not in (0, 1, 5):
        raise SystemExit(f"pytest could not run the claims suites "
                         f"(exit {code})")
    for row in plugin.rows.values():
        if row["status"] is None:
            row["status"] = "skip"
            row["message"] = row["message"] or "not run"
    return sorted(plugin.rows.values(), key=lambda r: r["order"])


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------

def build(rows: list[dict], editorial: dict, pages: dict[str, dict],
          section_page: dict[str, str], *, generated_at: str,
          edition: str | None) -> dict:
    strings = list(flatten(editorial))
    line_of = {p: getattr(s, "line", None) for p, s in strings}
    sections: dict[str, dict] = {}
    claims = []
    tight = []
    for row in rows:
        where = []
        for path in locate(row["quote"], strings):
            key, entry, field = place(path, editorial, pages, section_page)
            sections.setdefault(key, entry)
            where.append({"section": key, "field": field,
                          "line": line_of.get(path)})
        measures = [measure(m) for m in row["recorded"]]
        best = tightest(measures)
        if best is not None:
            tight.append(measures[best])
        claim = {
            "quote": row["quote"],
            "where": where,
            "file": row["file"],
            "suite": row["suite"],
            "guard": row["guard"],
            "line": row["line"],
            "status": row["status"],
        }
        # Only what differs from the usual case, to keep the file small.
        if row["status"] != "pass" and row["message"]:
            claim["message"] = row["message"]
        if row["path"] != f"pipeline/tests/{row['suite']}.py":
            claim["path"] = row["path"]
        claim["measures"] = [_slim(m) for m in measures]
        claim["tightest"] = best
        claims.append(claim)

    used = {s["page"] for s in sections.values()}
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "edition": edition,
        "near_share": NEAR_SHARE,
        "repo_blob": REPO_BLOB,
        "summary": {
            "claims": len(claims),
            **{s: sum(c["status"] == s for c in claims)
               for s in ("pass", "fail", "skip")},
            "measured": len(tight),
            "near": sum(m["share"] is not None and m["share"] < NEAR_SHARE
                        for m in tight),
            "exact": sum(m["exact"] for m in tight),
            "unlocated": sum(not c["where"] for c in claims),
        },
        "pages": {k: v for k, v in pages.items() if k in used},
        "sections": sections,
        "claims": claims,
    }


def dumps(ledger: dict) -> str:
    """One line per top-level key, per page, per section and per claim:
    small, and a nightly diff shows which claims moved."""
    def one(v) -> str:
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))

    parts = []
    for key, value in ledger.items():
        if key == "claims":
            body = ",\n".join(one(c) for c in value)
            parts.append(f'"claims":[\n{body}\n]')
        elif key in ("pages", "sections"):
            body = ",\n".join(f"{one(k)}:{one(v)}" for k, v in value.items())
            parts.append(f"{one(key)}:{{\n{body}\n}}")
        else:
            parts.append(f"{one(key)}:{one(value)}")
    return "{\n" + ",\n".join(parts) + "\n}\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data-dir", type=Path, default=ROOT / "site" / "data",
                    help="the edition to judge (default: site/data)")
    ap.add_argument("--out", type=Path, default=None,
                    help="where to write the ledger "
                         "(default: <data-dir>/claims_ledger.json)")
    ap.add_argument("--editorial", type=Path, default=EDITORIAL)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 when any guard fails")
    args = ap.parse_args(argv)

    data_dir = args.data_dir.resolve()
    out = args.out or data_dir / "claims_ledger.json"
    meta_path = data_dir / "meta.json"
    meta = (json.loads(meta_path.read_text("utf-8"))
            if meta_path.exists() else {})
    editorial = read_editorial(args.editorial)
    pages, section_page = page_index(editorial)
    rows = run_guards(data_dir, suite_files())
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ledger = build(rows, editorial, pages, section_page, generated_at=now,
                   edition=meta.get("generated_at"))
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text(dumps(ledger), "utf-8")
    tmp.replace(out)
    s = ledger["summary"]
    print(f"claims ledger: {s['claims']} guards — {s['pass']} pass, "
          f"{s['fail']} fail, {s['skip']} skip; {s['measured']} measured, "
          f"{s['near']} within {NEAR_SHARE:.0%} of a bound -> {out}")
    return 1 if args.check and s["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
