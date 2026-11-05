#!/usr/bin/env python3
"""Browser interaction check for the Alias Graph (alias.html).

tools/site_smoke.py loads the module pages; the Alias Graph has no footer
edition stamp (it rides the Field's instrument shell), so this script is its
whole browser check. It serves the committed site/, picks real groups from
data/alias_graph.json and asserts that:

  1. the counters show the edition's group count and a coverage share;
  2. searching the group named by the most schemes pins it: the panel lists
     each of its schemes and every name in its ATT&CK entry, and the page
     address keeps it (#actor=…);
  3. searching an alias pins the group that lists it;
  4. hovering a drawn group shows its tooltip; a scheme in the legend
     highlights (aria-pressed, #scheme=…);
  5. Browse groups lists every group, sorts by a header (aria-sort), and a
     row's button pins that group and closes the table;
  6. with the graph focused, ] pins a group and Esc clears it;
  7. the deep link alias.html#actor=… pins the same group at phone width
     (390 px) with no horizontal page overflow, and the text with every
     <details> open has no {placeholder}, undefined, NaN or null;
  8. no console errors or page errors along the way.

Usage: python3 tools/alias_smoke.py   (needs playwright + chromium)
Exit code 0 = ok; 1 = a check failed (details on stdout). An edition with no
groups (headline null) is reported and passes: there is nothing to pick.
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
from urllib.parse import quote

from playwright.sync_api import sync_playwright

SITE = Path(__file__).resolve().parents[1] / "site"
TIMEOUT_MS = 20_000
PLACEHOLDER = re.compile(r"\{[a-z_]+\}|\bundefined\b|\bNaN\b|\bnull\b")


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


def pick(data: dict) -> tuple[dict, tuple[str, dict] | None]:
    """(the group with the most schemes, then most names, then name;
    an alias of another placed group that only that group's entry contains
    as a substring — so a search for it has exactly one hit)."""
    actors = data["actors"]
    top = max(actors, key=lambda a: (len(a["schemes"]), len(a["names"]),
                                     a["name"]))
    folded = [(a, [n["name"].lower() for n in a["names"]]) for a in actors]
    for a in sorted(actors, key=lambda a: (-len(a["schemes"]), a["name"])):
        if a is top or not a["schemes"]:
            continue
        for n in a["names"][1:]:
            q = n["name"].lower()
            hits = [b for b, names in folded if any(q in s for s in names)]
            if len(hits) == 1 and hits[0] is a and len(q) >= 4:
                return top, (n["name"], a)
    return top, None


def open_page(browser, base: str, path: str, width: int, height: int,
              errors: list[str]):
    page = browser.new_page(viewport={"width": width, "height": height})
    page.on("console", lambda m: errors.append(m.text)
            if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
    page.goto(f"{base}/{path}", wait_until="networkidle")
    page.wait_for_selector("body[data-ready='1']", timeout=TIMEOUT_MS)
    return page


def search(page, text: str) -> None:
    page.fill("#a-search", text)
    page.press("#a-search", "Enter")


def panel_title(page) -> str:
    if page.locator("#a-panel").is_hidden():
        return ""
    return page.locator("#a-panel .sel-head b").inner_text()


def main() -> int:
    data = json.loads((SITE / "data" / "alias_graph.json").read_text("utf-8"))
    if data["headline"] is None:
        print("ok   alias_graph.json has no groups yet — nothing to pick")
        return 0
    top, alias = pick(data)
    labels = {s["id"]: s["label"] for s in data["schemes"]}
    problems: list[str] = []
    errors: list[str] = []
    with server(SITE) as base, sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            page = open_page(browser, base, "alias.html", 1440, 900, errors)

            # ---- 1. counters ---------------------------------------------
            shown = page.locator("#a-actors").inner_text()
            if shown != f"{data['headline']['actors']:,}":
                problems.append(f"group counter shows {shown!r}")
            if not re.fullmatch(r"\d{1,3}%", page.locator("#a-coverage")
                                .inner_text()):
                problems.append("coverage counter is not a share")

            # ---- 2. search the top group ---------------------------------
            search(page, top["name"])
            page.wait_for_selector("#a-panel:not([hidden])",
                                   timeout=TIMEOUT_MS)
            if panel_title(page) != top["name"]:
                problems.append(f"search {top['name']!r} pinned "
                                f"{panel_title(page)!r}")
            text = page.locator("#a-panel").inner_text()
            for s in top["schemes"]:
                if labels[s].upper() not in text.upper():
                    problems.append(f"panel lacks scheme {labels[s]!r}")
            missing = [n["name"] for n in top["names"]
                       if n["name"] not in text]
            if missing:
                problems.append(f"panel lacks names {missing[:4]}")
            if f"actor={quote(top['name'], safe='')}" not in \
                    page.url.replace("+", "%20"):
                problems.append(f"pin not in the address ({page.url})")
            page.keyboard.press("Escape")
            if not page.locator("#a-panel").is_hidden():
                problems.append("Esc did not clear the pin")

            # ---- 3. search an alias --------------------------------------
            if alias is not None:
                name, owner = alias
                search(page, name)
                page.wait_for_selector("#a-panel:not([hidden])",
                                       timeout=TIMEOUT_MS)
                if panel_title(page) != owner["name"]:
                    problems.append(f"alias {name!r} pinned "
                                    f"{panel_title(page)!r}, not "
                                    f"{owner['name']!r}")
                page.keyboard.press("Escape")
            page.fill("#a-search", "")
            page.dispatch_event("#a-search", "input")
            page.wait_for_timeout(300)

            # ---- 4. hover + legend ---------------------------------------
            view = page.evaluate("window.aliasView()")
            box = page.locator("#a-canvas").bounding_box()
            node = next((n for n in view["nodes"]
                         if 0 < n["x"] < box["width"]
                         and 0 < n["y"] < box["height"]), None)
            if node is None:
                problems.append("no drawn group inside the canvas")
            else:
                page.mouse.move(box["x"] + node["x"], box["y"] + node["y"])
                page.wait_for_timeout(150)
                tip = page.locator("#a-tip")
                if tip.evaluate("e => getComputedStyle(e).opacity") != "1" \
                        or not tip.inner_text().strip():
                    problems.append(f"hovering {node['name']!r} shows no "
                                    f"tooltip")
                page.mouse.move(box["x"] + 2, box["y"] + 2)
            first = data["schemes"][0]["id"]
            btn = page.locator(f"#a-legend [data-scheme='{first}']")
            btn.click()
            if btn.get_attribute("aria-pressed") != "true" \
                    or f"scheme={first}" not in page.url:
                problems.append("legend did not highlight its scheme")
            btn.click()

            # ---- 5. table ------------------------------------------------
            page.click("#a-table-toggle")
            page.wait_for_selector("#a-table:not([hidden])",
                                   timeout=TIMEOUT_MS)
            rows = page.locator("#a-table-rows tr").count()
            if rows != len(data["actors"]):
                problems.append(f"table has {rows} rows, data has "
                                f"{len(data['actors'])} groups")
            th = page.locator("#a-table th[data-sort='names']")
            th.locator("button").click()
            if th.get_attribute("aria-sort") not in ("ascending",
                                                     "descending"):
                problems.append("sorting by names set no aria-sort")
            want = page.locator("#a-table-rows tr button").first.inner_text()
            page.locator("#a-table-rows tr button").first.click()
            if not page.locator("#a-table").is_hidden():
                problems.append("choosing a row left the table open")
            if panel_title(page) != want:
                problems.append(f"row {want!r} pinned {panel_title(page)!r}")
            page.keyboard.press("Escape")

            # ---- 6. keyboard ---------------------------------------------
            page.focus("#a-canvas")
            page.keyboard.press("]")
            if page.evaluate("window.aliasView().pinned") is None:
                problems.append("] pinned no group")
            page.keyboard.press("Escape")
            if page.evaluate("window.aliasView().pinned") is not None:
                problems.append("Esc after ] left a group pinned")
            page.close()

            # ---- 7. deep link at phone width -----------------------------
            page = open_page(browser, base,
                             f"alias.html#actor={quote(top['name'])}",
                             390, 844, errors)
            if panel_title(page) != top["name"]:
                problems.append(f"deep link pinned {panel_title(page)!r}")
            overflow = page.evaluate(
                "document.documentElement.scrollWidth - "
                "document.documentElement.clientWidth")
            if overflow > 0:
                problems.append(f"390 px: page overflows by {overflow}px")
            page.evaluate("document.querySelectorAll('details')"
                          ".forEach(d => d.open = true)")
            bad = PLACEHOLDER.findall(page.evaluate("document.body.innerText"))
            if bad:
                problems.append(f"rendered text has {sorted(set(bad))}")
            page.close()
        finally:
            browser.close()

    if errors:
        problems.append(f"console or page errors: {errors}")
    if problems:
        print(f"FAIL alias.html ({top['name']})")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"ok   alias.html — {top['name']}: {len(top['schemes'])} schemes; "
          f"search, alias search, hover, legend, table, keyboard, deep link "
          f"at 390 px")
    return 0


if __name__ == "__main__":
    sys.exit(main())
