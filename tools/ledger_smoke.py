#!/usr/bin/env python3
"""Browser interaction check for the Claims Ledger (ledger.html).

tools/site_smoke.py proves the page loads clean; this proves it works. It
serves the committed site/, reads data/claims_ledger.json, and asserts that:

  1. the headline states the summary line ("N claims checked tonight, …")
     and the table lists one row per claim, smallest margin first (failing
     guards, then by margin share, then exact claims, then the unmeasured);
  2. the page filter keeps exactly the claims placed on that page, the
     result filter the claims with that result, and the margin filter the
     claims within 10% of a bound;
  3. clicking the Guard header sorts by guard name;
  4. a row's section link opens that section on its page;
  5. the deep link ledger.html#page=… filters on load at phone width
     (390 px), with no horizontal page overflow;
  6. no page errors along the way.

Usage: python3 tools/ledger_smoke.py   (needs playwright + chromium)
Exit code 0 = ok; 1 = a check failed (details on stdout). A ledger with no
claims (sample data) is reported and passes.
"""
from __future__ import annotations

import json
import sys
import threading
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from playwright.sync_api import sync_playwright

SITE = Path(__file__).resolve().parents[1] / "site"
TIMEOUT_MS = 20_000
ROWS = "#s-ledger_audit .ledger-table tbody tr"


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


def margin_key(c: dict) -> tuple:
    """The page's default order (ledger.js marginKey), page order aside."""
    m = c["measures"][c["tightest"]] if c["tightest"] is not None else None
    if c["status"] == "fail":
        return (0, m["share"] if m and m.get("share") is not None
                else float("-inf"))
    if m and m.get("share") is not None:
        return (1, m["share"])
    if m and m.get("exact"):
        return (2, 0)
    return (3, 0)


def row_count(page) -> int:
    return page.locator(ROWS).count()


def main() -> int:
    data = json.loads((SITE / "data" / "claims_ledger.json")
                      .read_text("utf-8"))
    claims = data["claims"]
    if not claims:
        print("ok   claims_ledger.json lists no claims (sample data?)")
        return 0
    s = data["summary"]
    on_page = {pid: sum(any(data["sections"][w["section"]]["page"] == pid
                            for w in c["where"]) for c in claims)
               for pid in data["pages"]}
    page_id = max((p for p in on_page if p != "home"), key=on_page.get)
    keys = sorted(margin_key(c) for c in claims)
    problems: list[str] = []

    with server(SITE) as base, sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            # ---- 1-4. desktop ----------------------------------------------
            page = browser.new_page(viewport={"width": 1440, "height": 900})
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(f"{base}/ledger.html", wait_until="networkidle")
            page.wait_for_selector(ROWS, timeout=TIMEOUT_MS)

            headline = page.locator("#s-ledger_audit .section-headline") \
                .inner_text()
            if not headline.startswith(f"{s['claims']:,} claims checked "
                                       f"tonight"):
                problems.append(f"headline is {headline!r}")
            if row_count(page) != len(claims):
                problems.append(f"{row_count(page)} rows for "
                                f"{len(claims)} claims")
            shown = page.eval_on_selector_all(
                ROWS, "rs => rs.map(r => r.id)")
            first = shown[0].removeprefix("claim-") if shown else ""
            want = [c for c in claims if margin_key(c) == keys[0]]
            firsts = {f"{c['suite'].removeprefix('test_')}.{c['guard']}"
                      for c in want}
            if not any(first == f or first.startswith(f + ".")
                       for f in firsts):
                problems.append(f"first row {first!r}, expected one of "
                                f"{sorted(firsts)[:3]}")

            # 2. filters
            page.select_option("#ledger-page", page_id)
            if row_count(page) != on_page[page_id]:
                problems.append(f"page filter {page_id}: {row_count(page)} "
                                f"rows, {on_page[page_id]} on record")
            if f"page={page_id}" not in page.url:
                problems.append(f"page filter not in the address: {page.url}")
            page.select_option("#ledger-page", "")
            for status in ("pass", "fail", "skip"):
                page.select_option("#ledger-result", status)
                n = row_count(page)
                if n != s[status]:
                    problems.append(f"result filter {status}: {n} rows, "
                                    f"{s[status]} on record")
                if n == 0 and not page.locator(".ledger-empty").is_visible():
                    problems.append(f"result filter {status}: no empty note")
            page.select_option("#ledger-result", "")
            page.check("#ledger-near")
            if row_count(page) != s["near"]:
                problems.append(f"margin filter: {row_count(page)} rows, "
                                f"{s['near']} within 10% on record")
            page.uncheck("#ledger-near")

            # 3. sort by guard
            page.click("#s-ledger_audit .ledger-th-guard .sort-btn")
            guards = page.eval_on_selector_all(
                ROWS + " .ledger-guard-link",
                "as => as.map(a => a.textContent)")
            if guards != sorted(guards):
                problems.append("Guard header does not sort by guard name")

            # 4. a section link lands on its section
            href = page.locator(ROWS + " .ledger-where a[href*='#s-']") \
                .first.get_attribute("href")
            page.goto(f"{base}/{href}", wait_until="networkidle")
            anchor = href.split("#", 1)[1]
            try:
                page.wait_for_selector(f"#{anchor}", timeout=TIMEOUT_MS)
            except Exception:
                problems.append(f"section link {href}: no #{anchor} there")
            if errors:
                problems.append(f"page errors: {errors}")
            page.close()

            # ---- 5. deep link at phone width ---------------------------------
            page = browser.new_page(viewport={"width": 390, "height": 844})
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(f"{base}/ledger.html#page={page_id}",
                      wait_until="networkidle")
            page.wait_for_selector(ROWS, timeout=TIMEOUT_MS)
            if row_count(page) != on_page[page_id]:
                problems.append(f"deep link #page={page_id}: "
                                f"{row_count(page)} rows")
            page.evaluate("document.querySelectorAll('details')"
                          ".forEach(d => d.open = true)")
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
        print("FAIL ledger.html")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"ok   ledger.html — {len(claims)} claims, order, filters "
          f"(#page={page_id}: {on_page[page_id]}), sort, section link, "
          f"390 px deep link")
    return 0


if __name__ == "__main__":
    sys.exit(main())
