#!/usr/bin/env python3
"""Print every module's LinkedIn carousel PDF from site/carousel.html.

Serves site/ with python's http.server, drives headless Chromium (Playwright)
through carousel.html?page=<module> for every module id the template reports
(window.__carouselModules — sourced from editorial.nav, so a module added to
the site nav is automatically expected here), waits for the template's ready
flag, and prints each slide stack to <out>/<module>.pdf — one 1080×1350 page
per slide, the LinkedIn document-post format.

The PDFs are deploy-time build products: CI runs this right before uploading
the Pages artifact, and site/carousels/ is gitignored so they never bloat git
history.

A module fails loudly on any of:
  - template-reported failures (bad page id, fetch/render errors),
  - a console error or uncaught exception,
  - a slide still overflowing its sheet after the template's fit pass
    (clipped text on a phone is a broken deck),
  - a PDF whose page count differs from the rendered slide count.

Usage: python3 tools/make_carousels.py [--out site/carousels]
       (needs: pip install playwright, then `playwright install chromium`)
Exit code 0 = every module printed clean; 1 = at least one failed (details
on stdout).
"""
from __future__ import annotations

import argparse
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

SITE_DIR = Path(__file__).resolve().parents[1] / "site"

# LinkedIn document-post portrait format, mirrored by @page in
# site/css/carousel.css. Chromium converts CSS px at 96 dpi.
PAGE_WIDTH = "1080px"
PAGE_HEIGHT = "1350px"

# Generous ceiling for a local static server; hitting it means a fetch hung
# or the template never signalled ready, both of which are failures.
PAGE_TIMEOUT_MS = 60_000

# Start above the dev-server range so a local `python -m http.server 8000`
# (or the site smoke test's OS-assigned port) never clashes.
PORT_RANGE = range(8920, 8970)


def free_port() -> int:
    for port in PORT_RANGE:
        try:
            with socket.socket() as s:
                s.bind(("127.0.0.1", port))
                return port
        except OSError:
            continue
    raise RuntimeError(f"no free port in {PORT_RANGE.start}-{PORT_RANGE.stop - 1}")


def wait_for_server(port: int, deadline_s: float = 10.0) -> None:
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"http.server on port {port} never came up")


def pdf_page_count(pdf_bytes: bytes) -> int | None:
    """Count pages without a PDF library.

    Chromium writes one uncompressed `/Type /Page` object per page; if that
    assumption ever breaks (zero matches), return None and skip the check
    rather than fail on a parsing artifact.
    """
    n = len(re.findall(rb"/Type\s*/Page[^s]", pdf_bytes))
    return n or None


def load_carousel(page, base_url: str, query: str) -> list[str]:
    """Navigate to carousel.html + query and wait for the template's flag.

    Returns the list of problems (template failures + console errors).
    """
    console_errors: list[str] = []
    page.on(
        "console",
        lambda msg: console_errors.append(msg.text) if msg.type == "error" else None,
    )
    page.on("pageerror", lambda exc: console_errors.append(f"pageerror: {exc}"))

    page.goto(f"{base_url}/carousel.html{query}", timeout=PAGE_TIMEOUT_MS)
    page.wait_for_function("() => window.__carouselDone === true", timeout=PAGE_TIMEOUT_MS)

    problems = list(page.evaluate("window.__carouselFailures || []"))
    problems += [f"console error: {e}" for e in console_errors]
    return problems


def print_module(page, base_url: str, module_id: str, out_dir: Path) -> list[str]:
    """Render one module and print its PDF; return problems (empty = ok)."""
    problems = load_carousel(page, base_url, f"?page={module_id}")

    overflows = page.evaluate("window.__carouselOverflows || []")
    for o in overflows:
        problems.append(f"slide {o['slide']} overflows its sheet by {o['px']}px ({o['id']})")

    if problems:
        return problems

    slide_count = page.evaluate("window.__carouselSlideCount")
    pdf_path = out_dir / f"{module_id}.pdf"
    page.pdf(
        path=str(pdf_path),
        width=PAGE_WIDTH,
        height=PAGE_HEIGHT,
        print_background=True,
    )

    pages = pdf_page_count(pdf_path.read_bytes())
    if pages is not None and pages != slide_count:
        problems.append(f"{pdf_path.name}: {pages} PDF pages for {slide_count} slides")
    else:
        size_kb = pdf_path.stat().st_size // 1024
        print(f"ok   {module_id}.pdf · {slide_count} slides · {size_kb} KB")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--out",
        default="site/carousels",
        help="output directory for the PDFs (default: %(default)s)",
    )
    args = parser.parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

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
                # A bare load exposes the printable module list (from
                # editorial.nav) — the template, not this script, owns it.
                probe = browser.new_page()
                try:
                    problems = load_carousel(probe, base_url, "")
                    modules = probe.evaluate("window.__carouselModules || []")
                finally:
                    probe.close()
                if problems or not modules:
                    print("FAIL carousel.html (module list probe)")
                    for p in problems or ["window.__carouselModules is empty"]:
                        print(f"  - {p}")
                    return 1

                for module_id in modules:
                    # Fresh page per module: 1080×1350 viewport matches the
                    # sheet; deviceScaleFactor 2 doubles the canvas backing
                    # store so ECharts text stays crisp in the printed PDF.
                    page = browser.new_page(
                        viewport={"width": 1080, "height": 1350},
                        device_scale_factor=2,
                    )
                    try:
                        problems = print_module(page, base_url, module_id, out_dir)
                    finally:
                        page.close()
                    if problems:
                        failed = True
                        print(f"FAIL {module_id}")
                        for p in problems:
                            print(f"  - {p}")
            finally:
                browser.close()
    finally:
        server.terminate()
        server.wait(timeout=10)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
