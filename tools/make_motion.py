#!/usr/bin/env python3
"""Render every animated scene from site/motion.html into an MP4 (and GIF).

Serves site/ with python's http.server, drives headless Chromium (Playwright)
through motion.html?scene=<id> for every scene the template reports
(window.__motionScenes), and captures the 1080x1350 stage one frame at a time:
the page owns the frame math, this script only walks the index and shoots.

Capture is SEEK-DRIVEN, not a screen recording. window.__motionSeek(i) is a
pure function of i, so output does not depend on how fast the machine runs and
two runs of the same data produce the same frames. Screen-recording ECharts'
own animation on a shared CI runner would drop and duplicate frames instead.

Encoding uses the static ffmpeg binary bundled in the imageio-ffmpeg wheel, so
there is no system ffmpeg dependency and local and CI behave identically.

The clips are deploy-time build products, exactly like the carousel PDFs:
site/motion/ is gitignored and CI rebuilds them before uploading the Pages
artifact.

A scene fails loudly on any of:
  - template-reported failures (bad scene id, fetch/setup errors),
  - a console error or uncaught exception,
  - a captured frame that is a single flat colour (the scene never painted),
  - a first frame identical to the last (nothing actually animated).

Usage: python3 tools/make_motion.py [--out site/motion] [--scene <id>]
                                    [--fps 30] [--check] [--keep-frames]
       (needs: pip install playwright imageio-ffmpeg,
        then `playwright install chromium`)

--check runs the fast pre-flight only: load each scene, assert it reports no
failures and a sane frame count, sample three frames and verify they are
non-blank and actually differ. No encode, no full capture — cheap enough for
the normal CI job, where a full render is not.

Exit code 0 = every scene rendered clean; 1 = at least one failed (details on
stdout).
"""
from __future__ import annotations

import argparse
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import imageio_ffmpeg
from playwright.sync_api import sync_playwright

SITE_DIR = Path(__file__).resolve().parents[1] / "site"

# Portrait social sheet, mirrored by .stage in site/css/motion.css.
STAGE_WIDTH = 1080
STAGE_HEIGHT = 1350

# GIF is a fallback for surfaces that will not take video. Full-size 30fps GIF
# of a 15s clip runs to tens of MB, so it ships halved and decimated; the MP4
# is the primary artifact.
GIF_SCALE = 540
GIF_FPS = 15

PAGE_TIMEOUT_MS = 60_000

# Start above the dev-server range so a local `python -m http.server 8000`
# (or the site smoke test's OS-assigned port) never clashes. Offset from
# make_carousels.py's range so the two can run at once.
PORT_RANGE = range(8970, 9020)


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


def load_scene(page, base_url: str, query: str) -> list[str]:
    """Navigate to motion.html + query and wait for the template's flag.

    Returns the list of problems (template failures + console errors).
    """
    console_errors: list[str] = []
    page.on(
        "console",
        lambda msg: console_errors.append(msg.text) if msg.type == "error" else None,
    )
    page.on("pageerror", lambda exc: console_errors.append(f"pageerror: {exc}"))

    page.goto(f"{base_url}/motion.html{query}", timeout=PAGE_TIMEOUT_MS)
    page.wait_for_function("() => window.__motionDone === true", timeout=PAGE_TIMEOUT_MS)

    problems = list(page.evaluate("window.__motionFailures || []"))
    problems += [f"console error: {e}" for e in console_errors]
    return problems


def shoot(page, index: int) -> bytes:
    """Paint frame `index` and return the stage as PNG bytes."""
    page.evaluate("(i) => window.__motionSeek(i)", index)
    return page.locator("#stage").screenshot(type="png")


def is_flat(png: bytes) -> bool:
    """True if the frame looks like a single flat colour.

    A PNG of one uniform colour compresses to almost nothing, so size is a
    reliable proxy and needs no image library. The threshold sits far below any
    real frame (which carries type, rules and bars) and far above a blank one.
    """
    return len(png) < 3_000


def check_scene(page, base_url: str, scene_id: str) -> list[str]:
    """Fast pre-flight: load, sample three frames, no encode."""
    problems = load_scene(page, base_url, f"?scene={scene_id}")
    if problems:
        return problems

    frames = page.evaluate("window.__motionFrames")
    if not isinstance(frames, int) or frames < 2:
        return [f"{scene_id}: bad frame count {frames!r}"]

    samples = {i: shoot(page, i) for i in (0, frames // 2, frames - 1)}
    for i, png in samples.items():
        if is_flat(png):
            problems.append(f"{scene_id}: frame {i} is blank ({len(png)} B) — scene never painted")
    if samples[0] == samples[frames - 1]:
        problems.append(f"{scene_id}: first and last frame are identical — nothing animated")

    if not problems:
        print(f"ok   {scene_id} · {frames} frames · 3 sampled, non-blank, distinct")
    return problems


def encode(frame_dir: Path, out_dir: Path, scene_id: str, fps: int) -> list[str]:
    """Encode captured PNGs to MP4 + GIF. Returns problems (empty = ok)."""
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    pattern = str(frame_dir / "%05d.png")
    mp4 = out_dir / f"{scene_id}.mp4"
    gif = out_dir / f"{scene_id}.gif"
    problems: list[str] = []

    # H.264 High profile, yuv420p for universal playback; +faststart puts the
    # moov atom first so social platforms can start playing before the whole
    # file lands.
    run = subprocess.run(
        [ffmpeg, "-y", "-loglevel", "error", "-framerate", str(fps), "-i", pattern,
         "-c:v", "libx264", "-preset", "slow", "-crf", "18",
         "-pix_fmt", "yuv420p", "-movflags", "+faststart", str(mp4)],
        capture_output=True, text=True,
    )
    if run.returncode != 0:
        return [f"{scene_id}: mp4 encode failed — {run.stderr.strip()[:400]}"]

    # Two-pass palette: one global palette beats per-frame dithering badly on
    # flat dark grounds, which is most of this frame.
    palette = frame_dir / "palette.png"
    vf = f"fps={GIF_FPS},scale={GIF_SCALE}:-1:flags=lanczos"
    for args in (
        ["-vf", f"{vf},palettegen=stats_mode=diff", str(palette)],
        ["-i", str(palette), "-lavfi", f"{vf},paletteuse=dither=bayer:bayer_scale=3", str(gif)],
    ):
        run = subprocess.run(
            [ffmpeg, "-y", "-loglevel", "error", "-framerate", str(fps), "-i", pattern] + args,
            capture_output=True, text=True,
        )
        if run.returncode != 0:
            problems.append(f"{scene_id}: gif encode failed — {run.stderr.strip()[:400]}")
            break

    mp4_kb = mp4.stat().st_size // 1024
    gif_kb = gif.stat().st_size // 1024 if gif.exists() else 0
    print(f"ok   {scene_id}.mp4 · {mp4_kb} KB    {scene_id}.gif · {gif_kb} KB")
    return problems


def render_scene(page, base_url: str, scene_id: str, out_dir: Path,
                 fps: int, keep_frames: bool) -> list[str]:
    """Capture every frame of one scene and encode it."""
    problems = load_scene(page, base_url, f"?scene={scene_id}")
    if problems:
        return problems

    frames = page.evaluate("window.__motionFrames")
    if not isinstance(frames, int) or frames < 2:
        return [f"{scene_id}: bad frame count {frames!r}"]

    frame_dir = Path(tempfile.mkdtemp(prefix=f"motion-{scene_id}-"))
    try:
        started = time.monotonic()
        first = last = None
        for i in range(frames):
            png = shoot(page, i)
            if i == 0:
                first = png
            if i == frames - 1:
                last = png
            if is_flat(png):
                return [f"{scene_id}: frame {i} is blank ({len(png)} B) — scene never painted"]
            (frame_dir / f"{i:05d}.png").write_bytes(png)
        if first == last:
            return [f"{scene_id}: first and last frame are identical — nothing animated"]

        secs = frames / fps
        print(f"     {scene_id} · {frames} frames captured in "
              f"{time.monotonic() - started:.1f}s → {secs:.1f}s @ {fps}fps")
        return encode(frame_dir, out_dir, scene_id, fps)
    finally:
        if keep_frames:
            print(f"     frames kept in {frame_dir}")
        else:
            shutil.rmtree(frame_dir, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="site/motion",
                        help="output directory for the clips (default: %(default)s)")
    parser.add_argument("--scene", help="render only this scene id (default: all)")
    parser.add_argument("--fps", type=int, default=30,
                        help="output frame rate (default: %(default)s)")
    parser.add_argument("--check", action="store_true",
                        help="pre-flight only: sample frames, no capture or encode")
    parser.add_argument("--keep-frames", action="store_true",
                        help="leave the captured PNGs on disk for inspection")
    args = parser.parse_args()

    out_dir = Path(args.out)
    if not args.check:
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
                # A bare load exposes the scene list — the template, not this
                # script, owns which scenes exist.
                probe = browser.new_page()
                try:
                    problems = load_scene(probe, base_url, "")
                    scenes = probe.evaluate("window.__motionScenes || []")
                finally:
                    probe.close()
                if problems or not scenes:
                    print("FAIL motion.html (scene list probe)")
                    for p in problems or ["window.__motionScenes is empty"]:
                        print(f"  - {p}")
                    return 1

                if args.scene:
                    if args.scene not in scenes:
                        print(f"FAIL unknown scene {args.scene!r} — known: {', '.join(scenes)}")
                        return 1
                    scenes = [args.scene]

                for scene_id in scenes:
                    # Fresh page per scene: the viewport matches the stage, and
                    # deviceScaleFactor stays 1 so a captured pixel is an output
                    # pixel (the encoder wants no rescale).
                    page = browser.new_page(
                        viewport={"width": STAGE_WIDTH, "height": STAGE_HEIGHT},
                        device_scale_factor=1,
                    )
                    try:
                        if args.check:
                            problems = check_scene(page, base_url, scene_id)
                        else:
                            problems = render_scene(page, base_url, scene_id, out_dir,
                                                    args.fps, args.keep_frames)
                    finally:
                        page.close()
                    if problems:
                        failed = True
                        print(f"FAIL {scene_id}")
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
