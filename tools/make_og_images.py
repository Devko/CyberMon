#!/usr/bin/env python3
"""Render one 1200×630 social preview PNG per page into site/og/<id>.png.

Serves site/ with python's http.server, loads the card template
(site/og.html) in headless Chromium (Playwright) once, and for every page id
calls window.__ogRender(id) and screenshots the card. The page list is the
union of:

  - what the template reports (window.__ogPages): `index`, every module in
    editorial.nav and every instrument in editorial.home.instruments, so a
    module added to the nav gets a card with no change here;
  - every reader page in site/*.html (no robots noindex) whose og:image
    points at og/<id>.png, so a page outside editorial.js (an instrument
    that keeps its own copy) still gets one, drawn from its own og:title.

The PNGs are deploy-time build products, like the carousel PDFs and motion
clips: site/og/ is gitignored and both deploy jobs build it, non-blocking,
right before the Pages artifact upload.

A card fails on any of:
  - a template-reported problem (no copy, a headline that does not fit at
    the smallest size, an unfilled placeholder),
  - a console error or uncaught exception,
  - a PNG that is not 1200×630, or is one flat colour.

--check runs the same render into a temporary directory and also checks the
page shells: every reader page must carry
  <meta property="og:image" content="https://devko.github.io/CyberMon/og/<id>.png">
  <meta name="twitter:image" content="(the same URL)">
  <meta name="twitter:card" content="summary_large_image">
with <id> its own file name (index for index.html), and every such image
must render. Cheap enough (~10 s) for the site-smoke CI job.

Usage: python3 tools/make_og_images.py [--out site/og] [--page <id>] [--check]
       (needs: pip install playwright, then `playwright install chromium`)
Exit code 0 = every card rendered clean; 1 = at least one failed (details on
stdout).
"""
from __future__ import annotations

import argparse
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
from html.parser import HTMLParser
from pathlib import Path

from playwright.sync_api import sync_playwright

SITE_DIR = Path(__file__).resolve().parents[1] / "site"

# The public site, as the page shells' og:url values spell it.
SITE_URL = "https://devko.github.io/CyberMon/"

WIDTH, HEIGHT = 1200, 630

PAGE_TIMEOUT_MS = 60_000

# Start above the dev-server range so a local `python -m http.server 8000`
# never clashes; offset from make_carousels.py (8920-8969) and
# make_motion.py (8970-9019) so all three can run at once.
PORT_RANGE = range(9020, 9070)

# A card carries a wordmark, rules and a headline; a PNG of one flat colour
# compresses to a few KB at this size (make_motion.py's size proxy).
FLAT_PNG_BYTES = 6_000


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


def png_size(png: bytes) -> tuple[int, int] | None:
    """(width, height) from the PNG's IHDR chunk, without an image library."""
    if png[:8] != b"\x89PNG\r\n\x1a\n" or png[12:16] != b"IHDR":
        return None
    return struct.unpack(">II", png[16:24])


# ---- page shells -------------------------------------------------------------

class _Meta(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.meta: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        if tag != "meta":
            return
        a = dict(attrs)
        key = a.get("property") or a.get("name")
        if key and "content" in a:
            self.meta.setdefault(key, a["content"] or "")


def page_meta(path: Path) -> dict[str, str]:
    parser = _Meta()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser.meta


def reader_pages(site: Path) -> dict[str, dict[str, str]]:
    """{page id: meta} for every page a reader can land on (no noindex)."""
    out = {}
    for path in sorted(site.glob("*.html")):
        meta = page_meta(path)
        if "noindex" in meta.get("robots", ""):
            continue  # capture templates (carousel, motion, og)
        out[path.stem] = meta
    return out


def declared_image_id(meta: dict[str, str]) -> str | None:
    m = re.fullmatch(re.escape(SITE_URL) + r"og/([\w-]+)\.png", meta.get("og:image", ""))
    return m.group(1) if m else None


def check_shells(pages: dict[str, dict[str, str]]) -> list[str]:
    """Every reader page names its own card, for Open Graph and Twitter."""
    problems = []
    for page_id, meta in pages.items():
        want = f"{SITE_URL}og/{page_id}.png"
        if meta.get("og:image") != want:
            problems.append(f"{page_id}.html: og:image is {meta.get('og:image')!r}, want {want!r}")
        if meta.get("twitter:image") != want:
            problems.append(f"{page_id}.html: twitter:image is {meta.get('twitter:image')!r}, want {want!r}")
        if meta.get("twitter:card") != "summary_large_image":
            problems.append(f"{page_id}.html: twitter:card is {meta.get('twitter:card')!r}, "
                            f"want 'summary_large_image'")
    return problems


# ---- rendering -----------------------------------------------------------------

def render_all(base_url: str, ids_extra: list[str], out_dir: Path,
               only: str | None) -> tuple[list[str], list[str]]:
    """Render every card; return (ids rendered clean, problems)."""
    problems: list[str] = []
    done: list[str] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": WIDTH, "height": HEIGHT},
                                    device_scale_factor=1)
            console: list[str] = []
            page.on("console", lambda m: console.append(m.text) if m.type == "error" else None)
            page.on("pageerror", lambda e: console.append(f"pageerror: {e}"))
            page.goto(f"{base_url}/og.html", timeout=PAGE_TIMEOUT_MS)
            page.wait_for_function("() => window.__ogReady === true", timeout=PAGE_TIMEOUT_MS)
            ids = list(page.evaluate("window.__ogPages"))
            ids += [i for i in ids_extra if i not in ids]
            if only:
                ids = [i for i in ids if i == only] or [only]
            for page_id in ids:
                console.clear()
                found = list(page.evaluate("(id) => window.__ogRender(id)", page_id))
                found += [f"{page_id}: console error: {e}" for e in console]
                if not found:
                    png = page.locator("#card").screenshot(type="png")
                    size = png_size(png)
                    if size != (WIDTH, HEIGHT):
                        found.append(f"{page_id}: PNG is {size}, want {(WIDTH, HEIGHT)}")
                    elif len(png) < FLAT_PNG_BYTES:
                        found.append(f"{page_id}: PNG looks blank ({len(png)} bytes)")
                    else:
                        (out_dir / f"{page_id}.png").write_bytes(png)
                        done.append(page_id)
                        print(f"ok   og/{page_id}.png · {len(png) // 1024} KB")
                if found:
                    print(f"FAIL {page_id}")
                    for p in found:
                        print(f"  - {p}")
                problems += found
        finally:
            browser.close()
    return done, problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="site/og",
                        help="output directory for the PNGs (default: %(default)s)")
    parser.add_argument("--page", help="render one page id only")
    parser.add_argument("--check", action="store_true",
                        help="render into a temporary directory and check every "
                             "page shell's og:image / twitter:image / twitter:card")
    args = parser.parse_args()

    pages = reader_pages(SITE_DIR)
    declared = [i for i in (declared_image_id(m) for m in pages.values()) if i]
    shell_problems = check_shells(pages) if args.check else []
    problems: list[str] = []

    tmp = tempfile.TemporaryDirectory() if args.check else None
    out_dir = Path(tmp.name) if tmp else Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    port = free_port()
    server = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port),
         "--bind", "127.0.0.1", "--directory", str(SITE_DIR)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_for_server(port)
        done, render_problems = render_all(f"http://127.0.0.1:{port}", declared,
                                           out_dir, args.page)
        problems += render_problems
    finally:
        server.terminate()
        server.wait(timeout=10)
        if tmp:
            tmp.cleanup()

    if args.check:
        if not args.page:
            shell_problems += [f"og/{i}.png is named by a page but did not render"
                               for i in sorted(set(declared) - set(done))]
        for p in shell_problems:
            print(f"FAIL {p}")
        problems += shell_problems
        print(f"{'ok' if not problems else 'FAIL'}   {len(done)} cards rendered, "
              f"{len(pages)} page shells checked")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
