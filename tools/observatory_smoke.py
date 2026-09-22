#!/usr/bin/env python3
"""Browser interaction check for the Mutation Observatory (observatory.html).

tools/site_smoke.py proves the page loads clean; this proves it works. It
serves the committed site/, picks a real CVE from data/observatory.json
(one whose trail crosses the most histories), and asserts that:

  1. searching it renders its trail — one timeline item per event on
     record, each dated "first observed", with a link to the same record
     in the Field;
  2. the deep link observatory.html#cve=… renders the same trail on load,
     at phone width (390 px), with no horizontal page overflow;
  3. the window table has rows and its "Download CSV" hands over a CSV
     whose header and row count match the window;
  4. no page errors along the way.

Usage: python3 tools/observatory_smoke.py   (needs playwright + chromium)
Exit code 0 = ok; 1 = a check failed (details on stdout). An edition with
no events (a fresh checkout before the nightly) is reported and passes —
the page's empty state is site_smoke's business.
"""
from __future__ import annotations

import json
import sys
import threading
from collections import defaultdict
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


def pick_cve(data: dict) -> tuple[str, int] | None:
    """The CVE whose trail crosses the most histories (then the longest
    trail, then the id) — a real record, never a synthetic one."""
    sources: dict[str, set] = defaultdict(set)
    counts: dict[str, int] = defaultdict(int)
    for s in data["events"]:
        _, cve, kind, _, _ = s.split("|")
        sources[cve].add(data["kind_source"][int(kind)])
        counts[cve] += 1
    if not counts:
        return None
    cve = max(counts, key=lambda c: (len(sources[c]), min(counts[c], 12),
                                     c))
    return cve, counts[cve]


def main() -> int:
    data = json.loads((SITE / "data" / "observatory.json").read_text("utf-8"))
    picked = pick_cve(data)
    if picked is None:
        print("ok   observatory.json has no events yet — nothing to search")
        return 0
    cve, n = picked
    problems: list[str] = []
    with server(SITE) as base, sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            # ---- 1. search at desktop width --------------------------------
            page = browser.new_page(viewport={"width": 1440, "height": 900},
                                    accept_downloads=True)
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(f"{base}/observatory.html", wait_until="networkidle")
            page.wait_for_selector("#obs-cve", timeout=TIMEOUT_MS)
            page.fill("#obs-cve", cve.lower())      # normalized by the page
            page.press("#obs-cve", "Enter")
            page.wait_for_selector("#obs-trail .obs-ev", timeout=TIMEOUT_MS)
            items = page.locator("#obs-trail .obs-ev")
            if items.count() != n:
                problems.append(f"search {cve}: {items.count()} trail items, "
                                f"{n} events on record")
            dates = items.locator(".obs-ev-date").all_text_contents()
            if not all(d.startswith("first observed ") for d in dates):
                problems.append(f"trail dates not labelled 'first observed': "
                                f"{dates[:3]}")
            href = page.locator("#obs-trail .obs-field-link") \
                .get_attribute("href") or ""
            if href != f"field.html#cve={cve}":
                problems.append(f"Field link is {href!r}")
            if f"#cve={cve}" not in page.url:
                problems.append(f"search did not set the deep link ({page.url})")

            # ---- 3. the window table + CSV ---------------------------------
            rows = page.locator(".obs-table tbody tr").count()
            context = page.locator("#s-obs_window .table-context").inner_text()
            if rows == 0 and not context.startswith("No events"):
                problems.append("window table is empty")
            if rows:
                with page.expect_download(timeout=TIMEOUT_MS) as dl_info:
                    page.click(".obs-download")
                text = Path(dl_info.value.path()).read_text("utf-8")
                lines = text.strip().split("\n")
                if lines[0] != "first_observed,cve,kind,source,change,dated_by":
                    problems.append(f"CSV header is {lines[0]!r}")
                window_n = int(context.split(" ")[0].replace(",", ""))
                if len(lines) - 1 != window_n:
                    problems.append(f"CSV has {len(lines) - 1} rows, window "
                                    f"says {window_n}")
            if errors:
                problems.append(f"page errors: {errors}")
            page.close()

            # ---- 2. deep link at phone width -------------------------------
            page = browser.new_page(viewport={"width": 390, "height": 844})
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(f"{base}/observatory.html#cve={cve}",
                      wait_until="networkidle")
            page.wait_for_selector("#obs-trail .obs-ev", timeout=TIMEOUT_MS)
            if page.locator("#obs-trail .obs-ev").count() != n:
                problems.append(f"deep link {cve}: trail item count differs")
            overflow = page.evaluate(
                "document.documentElement.scrollWidth - "
                "document.documentElement.clientWidth")
            if overflow > 0:
                problems.append(f"390 px: page overflows by {overflow}px")
            if errors:
                problems.append(f"page errors at 390 px: {errors}")
            page.close()
        finally:
            browser.close()

    if problems:
        print(f"FAIL observatory.html ({cve})")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"ok   observatory.html — {cve}: {n}-event trail, search + deep "
          f"link + table + CSV")
    return 0


if __name__ == "__main__":
    sys.exit(main())
