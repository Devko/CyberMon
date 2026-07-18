#!/usr/bin/env python3
"""Front-end smoke test: load every page in a real headless browser.

The pipeline is well-tested; this covers the other half. It serves site/
with python's http.server, drives headless Chromium (Playwright) through
every page, and fails on the three things that mean "the site is broken for
a reader" regardless of what charts a page contains:

  1. any console error (strict — the pages currently produce zero, keep it
     that way; there is deliberately NO allowlist),
  2. any rendered .error-card (the data-failed-to-load fallback card),
  3. a missing footer edition stamp ("Edition generated …" in #footer-meta),
     which proves meta.json was fetched and the JS chrome actually ran.

Deliberately count-agnostic: it never asserts how many charts/sections a
page has, so adding a new chart never breaks it. Adding a new page? Add it
to PAGES below.

Usage: python3 tools/site_smoke.py   (needs: pip install playwright,
       then `playwright install chromium`)
Exit code 0 = all pages clean; 1 = at least one page failed (details on
stdout).
"""
from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

SITE_DIR = Path(__file__).resolve().parents[1] / "site"

# Every reader-facing page. Count-agnostic checks only — do NOT add
# per-chart assertions here (chart sections are added in parallel by
# other work; this test must not race them).
PAGES = [
    "index.html",
    "cve.html",
    "market.html",
    "kev.html",
    "concentration.html",
    "breaches.html",
    "extortion.html",
    "attack.html",
    "hygiene.html",
    "guards.html",
    "epss.html",
    "calendar.html",
    "rescores.html",
    "changelog.html",
    "naming.html",
    "top25.html",
    "adp.html",
    "epssvol.html",
]

# Generous ceiling for a local static server; hitting it means a fetch
# hung or the JS chrome never finished, both of which are failures.
PAGE_TIMEOUT_MS = 15_000


def free_port() -> int:
    """Ask the OS for an unused port (tiny bind race; fine for CI)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_server(port: int, deadline_s: float = 10.0) -> None:
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"http.server on port {port} never came up")


def check_page(page, base_url: str, name: str) -> list[str]:
    """Load one page; return a list of human-readable problems (empty = ok)."""
    problems: list[str] = []
    console_errors: list[str] = []
    page.on(
        "console",
        lambda msg: console_errors.append(msg.text) if msg.type == "error" else None,
    )
    # Uncaught JS exceptions don't always surface as console messages.
    page.on("pageerror", lambda exc: console_errors.append(f"pageerror: {exc}"))

    # networkidle waits for the data-fetch cascade (meta.json + chart JSON)
    # to finish, not just the HTML parse.
    page.goto(f"{base_url}/{name}", wait_until="networkidle", timeout=PAGE_TIMEOUT_MS)

    # (c) Footer edition stamp: proves meta.json loaded and JS chrome ran.
    # Waited on (not just read) because it renders from an async fetch.
    try:
        page.wait_for_function(
            "() => (document.getElementById('footer-meta')?.textContent || '')"
            ".includes('Edition generated')",
            timeout=PAGE_TIMEOUT_MS,
        )
    except Exception:
        stamp = page.locator("#footer-meta").text_content(timeout=1000) or "<missing>"
        problems.append(f"footer stamp missing 'Edition generated' (got: {stamp!r})")

    # (b) No data-failed-to-load cards anywhere on the page.
    error_cards = page.locator(".error-card").count()
    if error_cards:
        texts = page.locator(".error-card").all_text_contents()
        problems.append(f"{error_cards} .error-card element(s) rendered: {texts}")

    # (a) Zero console errors, no exceptions, no allowlist.
    if console_errors:
        problems.append(f"{len(console_errors)} console error(s): {console_errors}")

    return problems


def main() -> int:
    port = free_port()
    server = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port),
         "--bind", "127.0.0.1", "--directory", str(SITE_DIR)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    failed = False
    try:
        wait_for_server(port)
        base_url = f"http://127.0.0.1:{port}"
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                for name in PAGES:
                    # Fresh page per document so console listeners and DOM
                    # state never leak between pages.
                    page = browser.new_page()
                    try:
                        problems = check_page(page, base_url, name)
                    finally:
                        page.close()
                    if problems:
                        failed = True
                        print(f"FAIL {name}")
                        for p in problems:
                            print(f"  - {p}")
                    else:
                        print(f"ok   {name}")
            finally:
                browser.close()
    finally:
        server.terminate()
        server.wait(timeout=10)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
