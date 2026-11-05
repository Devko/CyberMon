#!/usr/bin/env python3
"""Browser interaction check for the Adversary Atlas (atlas.html).

tools/site_smoke.py proves the page loads clean; this proves it works. It
serves the committed site/, recomputes the expected numbers from
data/attack_atlas.json in Python, and asserts that:

  1. the page opens on one group's neighbourhood (not the whole graph):
     the canvas is drawn, the headline names the group the page opens on
     with its software and technique counts, and the table lists exactly
     that group's entries;
  2. the group picker finds a group by one of its aliases (keyboard only:
     type, Enter), the URL hash records it, and "Add techniques its
     software uses" adds exactly the techniques reached only through its
     software;
  3. comparing two groups shows the shared counts and Jaccard index the
     data gives, the table lists the union, and its CSV has the same rows;
  4. a click on the canvas centre selects the group (details with its
     ATT&CK link), and the keyboard selects a node (arrow, Enter) and
     records it in the hash;
  5. the closest-groups table ranks the group the data ranks first;
  6. the deep link atlas.html#g=…&vs=…&n=… restores the comparison and the
     selected node at phone width (390 px) with no horizontal overflow;
  7. no page errors along the way.

Usage: python3 tools/atlas_smoke.py   (needs playwright + chromium)
Exit code 0 = ok; 1 = a check failed (details on stdout). A checkout with
no attack_atlas.json is reported and passes — the page's empty state is
site_smoke's business.
"""
from __future__ import annotations

import json
import re
import sys
import threading
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from playwright.sync_api import sync_playwright

SITE = Path(__file__).resolve().parents[1] / "site"
TIMEOUT_MS = 20_000


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@contextmanager
def server(directory: Path):
    http = ThreadingHTTPServer(("127.0.0.1", 0),
                               partial(QuietHandler, directory=str(directory)))
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{http.server_port}"
    finally:
        http.shutdown()
        http.server_close()
        thread.join()


class Graph:
    """The export decoded the way atlas.js decodes it."""

    def __init__(self, data: dict):
        c = data["counts"]
        self.G, self.S = c["groups"], c["software"]
        self.ids, self.names = data["ids"], data["names"]
        self.aliases = data["aliases"]
        self.out = [[int(x) for x in r.split()] if r else []
                    for r in data["uses"]]
        self.version = data["version"]

    def soft(self, g: int) -> set[int]:
        return {x for x in self.out[g] if x < self.G + self.S}

    def tech(self, g: int) -> set[int]:
        return {x for x in self.out[g] if x >= self.G + self.S}

    def via(self, g: int) -> set[int]:
        reach = {t for s in self.soft(g) for t in self.out[s]}
        return reach - self.tech(g)

    def jaccard(self, a: set, b: set) -> float | None:
        union = len(a | b)
        return len(a & b) / union if union else None

    def default(self) -> int:
        return max(range(self.G), key=lambda g: (len(self.out[g]), -g))


def plural(n: int, one: str, many: str, none: str) -> str:
    return none if n == 0 else (one if n == 1 else many).format(n=f"{n:,}")


def software_n(n: int) -> str:
    return plural(n, "{n} software entry", "{n} software entries",
                  "no software entries")


def technique_n(n: int) -> str:
    return plural(n, "{n} technique", "{n} techniques", "no techniques")


def fmt_j(v: float | None) -> str:
    # JS toFixed(2) and Python's format agree except on exact binary ties,
    # which a Jaccard ratio of small integers does not produce here.
    return "—" if v is None else f"{v:.2f}"


def check(problems: list[str], ok: bool, message: str) -> None:
    if not ok:
        problems.append(message)


def main() -> int:
    path = SITE / "data" / "attack_atlas.json"
    if not path.exists():
        print("ok   attack_atlas.json is not committed yet — nothing to check")
        return 0
    m = Graph(json.loads(path.read_text("utf-8")))
    a0 = m.default()
    # A group other than the default one, findable by an alias that is not
    # part of its name, and the group the data ranks closest to it by
    # technique Jaccard.
    pick = next(g for g in sorted(range(m.G), key=lambda g: -len(m.out[g]))
                if g != a0 and any(len(al) >= 5 and al.lower() not in m.names[g].lower()
                       for al in m.aliases[g]) and m.via(g))
    alias = next(al for al in m.aliases[pick]
                 if len(al) >= 5 and al.lower() not in m.names[pick].lower())
    ranked = sorted((g for g in range(m.G) if g != pick
                     and m.tech(g) & m.tech(pick)),
                    key=lambda g: (-m.jaccard(m.tech(g), m.tech(pick)),
                                   -len(m.tech(g) & m.tech(pick)),
                                   m.names[g].lower()))
    other = ranked[0]
    problems: list[str] = []
    with server(SITE) as base, sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": 1440, "height": 900},
                                    accept_downloads=True)
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("console", lambda msg: errors.append(msg.text)
                    if msg.type == "error" else None)
            page.goto(f"{base}/atlas.html", wait_until="networkidle")
            page.wait_for_selector(".atlas-table tbody tr", timeout=TIMEOUT_MS)

            # ---- 1. the default view: one group's neighbourhood -----------
            head = page.locator("#s-atlas_graph .section-headline").inner_text()
            want = (f"ATT&CK v{m.version} links {m.names[a0]} to "
                    f"{software_n(len(m.soft(a0)))} and "
                    f"{technique_n(len(m.tech(a0)))}")
            check(problems, head.startswith(want),
                  f"default headline {head!r}, expected {want!r}…")
            rows = page.locator(".atlas-table tbody tr").count()
            check(problems, rows == len(m.out[a0]),
                  f"default table: {rows} rows, {len(m.out[a0])} entries")
            painted = page.evaluate("""() => {
              const c = document.querySelector('.atlas-canvas');
              const d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data;
              let n = 0; for (let i = 3; i < d.length; i += 4) if (d[i]) n++;
              return n; }""")
            check(problems, painted > 5000, f"canvas looks blank ({painted} px)")

            # ---- 2. pick by alias, keyboard only; via toggle --------------
            page.fill("#atlas-a", alias)
            page.wait_for_selector("#atlas-a-list:not([hidden])",
                                   timeout=TIMEOUT_MS)
            page.press("#atlas-a", "Enter")
            page.wait_for_function(
                "id => location.hash.includes('g=' + id)", arg=m.ids[pick],
                timeout=TIMEOUT_MS)
            head = page.locator("#s-atlas_graph .section-headline").inner_text()
            check(problems, f" {m.names[pick]} " in f" {head} ",
                  f"alias {alias!r} did not open {m.names[pick]}: {head!r}")
            n_direct = page.locator(".atlas-table tbody tr").count()
            check(problems, n_direct == len(m.out[pick]),
                  f"{m.ids[pick]}: {n_direct} rows, {len(m.out[pick])} entries")
            page.check("#atlas-via")
            page.wait_for_function("() => location.hash.includes('via=1')",
                                   timeout=TIMEOUT_MS)
            n_via = page.locator(".atlas-table tbody tr").count()
            check(problems, n_via == len(m.out[pick]) + len(m.via(pick)),
                  f"via: {n_via} rows, expected "
                  f"{len(m.out[pick]) + len(m.via(pick))}")
            page.uncheck("#atlas-via")

            # ---- 3. compare -------------------------------------------------
            page.fill("#atlas-b", m.ids[other])
            page.press("#atlas-b", "Enter")
            page.wait_for_function(
                "id => location.hash.includes('vs=' + id)", arg=m.ids[other],
                timeout=TIMEOUT_MS)
            ss = m.soft(pick) & m.soft(other)
            ts = m.tech(pick) & m.tech(other)
            head = page.locator("#s-atlas_graph .section-headline").inner_text()
            want = (f"{m.names[pick]} and {m.names[other]} share "
                    f"{software_n(len(ss))} and {technique_n(len(ts))}")
            check(problems, head.startswith(want),
                  f"compare headline {head!r}, expected {want!r}…")
            stat = page.locator("#s-atlas_graph .atlas-stat").inner_text()
            jt = fmt_j(m.jaccard(m.tech(pick), m.tech(other)))
            check(problems, f"techniques {jt} ({len(ts):,} of" in stat,
                  f"compare stat {stat!r} lacks technique Jaccard {jt}")
            union = set(m.out[pick]) | set(m.out[other])
            rows = page.locator(".atlas-table tbody tr").count()
            check(problems, rows == len(union),
                  f"compare table: {rows} rows, union is {len(union)}")
            with page.expect_download(timeout=TIMEOUT_MS) as dl_info:
                page.click("#s-atlas_table .atlas-btn")
            lines = Path(dl_info.value.path()).read_text("utf-8") \
                .strip().split("\n")
            check(problems, lines[0].startswith("attack_id,name,kind,tactics,"),
                  f"CSV header {lines[0]!r}")
            check(problems, len(lines) - 1 == len(union),
                  f"CSV has {len(lines) - 1} rows, union is {len(union)}")
            check(problems, f"_{m.ids[pick]}_vs_{m.ids[other]}.csv"
                  in dl_info.value.suggested_filename,
                  f"CSV name {dl_info.value.suggested_filename!r}")
            page.click(".atlas-combo-clear")
            page.wait_for_function("() => !location.hash.includes('vs=')",
                                   timeout=TIMEOUT_MS)

            # ---- 4. click the centre, then keyboard select ------------------
            # Leaving compare mode resizes the canvas; a click aimed at a
            # centre measured mid-resize can miss (CI run 116). Wait until
            # the canvas box holds still, and re-aim once if the first click
            # selected nothing.
            def settled_box():
                prev = None
                for _ in range(30):
                    cur = page.locator(".atlas-canvas").bounding_box()
                    if cur == prev:
                        return cur
                    prev = cur
                    page.wait_for_timeout(100)
                return prev
            for attempt in range(2):
                box = settled_box()
                page.mouse.click(box["x"] + box["width"] / 2,
                                 box["y"] + box["height"] / 2)
                try:
                    page.wait_for_selector(".atlas-detail-kind", timeout=5000)
                    break
                except Exception:
                    if attempt:
                        raise
            kind = page.locator(".atlas-detail-kind").inner_text()
            check(problems, kind.endswith(m.ids[pick]),
                  f"centre click selected {kind!r}, not {m.ids[pick]}")
            href = page.locator(".atlas-detail-link").get_attribute("href")
            check(problems, href == f"https://attack.mitre.org/groups/"
                  f"{m.ids[pick]}/", f"ATT&CK link is {href!r}")
            page.focus(".atlas-canvas")
            page.keyboard.press("ArrowRight")
            page.keyboard.press("ArrowRight")
            page.keyboard.press("Enter")
            page.wait_for_function("() => /[&#]n=[ST]\\d{4}/.test(location.hash)",
                                   timeout=TIMEOUT_MS)
            sel = re.search(r"n=([ST][\d.]+)", page.url).group(1)
            kind = page.locator(".atlas-detail-kind").inner_text()
            check(problems, kind.endswith(sel),
                  f"keyboard selection {sel} but details show {kind!r}")
            page.keyboard.press("Escape")
            page.wait_for_function("() => !location.hash.includes('n=')",
                                   timeout=TIMEOUT_MS)

            # ---- 5. closest groups ----------------------------------------
            first = page.locator(".atlas-closest tbody tr").first \
                .locator("td").first.inner_text()
            check(problems, first.startswith(m.names[other]),
                  f"closest table starts with {first!r}, data ranks "
                  f"{m.names[other]} first")
            if errors:
                problems.append(f"page errors: {errors}")
            page.close()

            # ---- 6. deep link at phone width -------------------------------
            shared = m.tech(pick) & m.tech(other)
            node = m.ids[min(shared)] if shared else m.ids[other]
            page = browser.new_page(viewport={"width": 390, "height": 844})
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(f"{base}/atlas.html#g={m.ids[pick]}&vs={m.ids[other]}"
                      f"&n={node}", wait_until="networkidle")
            page.wait_for_selector(".atlas-detail-kind", timeout=TIMEOUT_MS)
            head = page.locator("#s-atlas_graph .section-headline").inner_text()
            check(problems, head.startswith(f"{m.names[pick]} and "
                                            f"{m.names[other]} share"),
                  f"deep link headline {head!r}")
            kind = page.locator(".atlas-detail-kind").inner_text()
            check(problems, kind.endswith(node),
                  f"deep link details show {kind!r}, not {node}")
            overflow = page.evaluate(
                "document.documentElement.scrollWidth - "
                "document.documentElement.clientWidth")
            check(problems, overflow <= 0,
                  f"390 px: page overflows by {overflow}px")
            if errors:
                problems.append(f"page errors at 390 px: {errors}")
            page.close()
        finally:
            browser.close()

    if problems:
        print(f"FAIL atlas.html ({m.ids[pick]} vs {m.ids[other]})")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"ok   atlas.html — default {m.ids[a0]}; alias {alias!r} → "
          f"{m.ids[pick]}; compare with {m.ids[other]}; table, CSV, "
          f"selection, keyboard, deep link at 390 px")
    return 0


if __name__ == "__main__":
    sys.exit(main())
