# Animated statistics exports — design

**Status:** implemented 2026-08-06 (three scenes live)
**Scope:** build-time animated clips (MP4 + GIF) of CyberMon's deepest
time series, distributed the same way the LinkedIn carousel PDFs are.

## Why

The site already turns each module into a carousel PDF for LinkedIn document
posts. Several datasets carry enough temporal depth that their story is better
told as motion than as a static frame — a ranking that changes hands, a stack
that fills, two lines that diverge. Nothing new needs collecting; the payloads
are already committed.

## What ships

Three hand-designed scenes, chosen for depth *and* for having an arc:

| Scene | Payload | Span | The move |
|---|---|---|---|
| `hype-race` | `market_hype.json` | 48 monthly steps | Ransomware leads, Agentic AI overtakes |
| `severity-flood` | `nine_eight_flood.json` | 28 years | The Critical band goes from rounding error to the top of the stack |
| `cna-concentration` | `cna_concentration.json` | 28 years | CNA count climbs as top-5 share falls; the lines cross |

Output: 1080×1350 portrait, 30fps, ~14–17s. MP4 (H.264 High, yuv420p,
`+faststart`) is the primary artifact; GIF ships halved to 540px and decimated
to 15fps as a fallback for surfaces that refuse video.

Deliberately **not** shipped: a generic treatment auto-applied to every chart
with a time axis. Each of these three needed a different visual form, and a
one-size animation would have suited none of them.

## Architecture

```
site/motion.html                      capture template, ?scene=<id>, noindex
site/css/motion.css                   the 1080×1350 sheet
site/js/motion.js                     scene registry + harness contract
site/js/motion/chrome.js              shared furniture, frame plan, chart factory
site/js/motion/hype_race.js           scene
site/js/motion/severity_flood.js      scene
site/js/motion/cna_concentration.js   scene
tools/make_motion.py                  Playwright capture → imageio-ffmpeg encode
site/motion/<scene>.{mp4,gif}         gitignored build product
```

This mirrors `carousel.html` / `make_carousels.py` deliberately, down to the
`window.__motion*` flag names, so the two build products read as siblings.

### Capture is seek-driven, not recorded

`window.__motionSeek(i)` is a **pure function of `i`**. The driver loads a
scene once, then walks frames: `evaluate(seek(i))` → screenshot → advance.

This is the load-bearing decision. Screen-recording an animation on a shared CI
runner drops and duplicates frames depending on machine load, so output would
vary run to run and no cheap check could be trusted. Because seeking is pure:

- re-running a capture reproduces the same frames,
- `--check` can sample three frames and mean something,
- a scene's motion can be reasoned about without encoding anything.

Everything follows from it. `css/motion.css` carries **no** transition,
keyframe or animation — every moving value is written as an inline style by
`seek()`. `mkMotionChart()` wraps ECharts' `setOption` to force
`animation: false` permanently, rather than passing the flag once where a later
call could silently re-enable tweening.

### Interpolation lives in the scene

Values lerp linearly (constant flow); positions ease. `framePlan()` gives every
scene the same intro-hold → per-step travel → outro-hold shape and a pure
`frame → (step, t)` mapping.

`FRAMES_PER_STEP` is **odd** on purpose so `t` never lands exactly on `0.5` —
the one instant two crossing elements would be perfectly coincident.

The race additionally uses a hold–swap–hold ease (travel confined to the middle
40% of a step) so a rank change reads as a deliberate overtake rather than a
slow drift through ambiguity. Rows are opaque and z-ordered by rank, so an
overtake shows one row sliding over another instead of two labels blending.

### Two charting facts worth recording

**The race is DOM, not ECharts.** Bars must sit at *fractional* rank positions
to glide past each other; ECharts category axes snap between slots. DOM rows
moved by an inline `translateY` do it exactly, and render real text rather than
canvas text.

**The stacked area computes its own stack.** ECharts' `stack` aligns series by
data *index*, which only means anything on a category axis. The flood scene
needs a value x-axis (so the drawing tip can sit at a fractional year), and on
one the bands silently collapse into flat lines. So cumulative sums are computed
in the scene and each band is drawn as its own area filling to zero, largest
first; what stays visible between `cum[k]` and `cum[k-1]` is band `k`. Bands
must be fully opaque or the colours mix into something meaningless.

## Editorial and honesty constraints

All user-facing copy lives in `editorial.motion.scenes.<id>` — no string is
hardcoded in a scene file — and every claim is audited by
`pipeline/tests/test_claims_motion.py` against the committed data.

A clip is the project's most exposed copy: it travels **without** its
methodology block, caption or tooltips. Two consequences shaped the design:

1. **No span figures in headlines.** A clip's window grows every night, so
   "four years of…" goes stale silently. Where a span or count belongs on the
   sheet it renders from data as a `{placeholder}`.
2. **Caveats must be on the sheet, not in the caption.** The flood scene's
   pre-2018 records were scored in NVD's database rather than in the CVE record
   this chart reads; unmarked, the growing stack asserts something false. The
   scene shades that era *and* states it in the footer. Likewise both year-based
   scenes hold their final frame on a part-written year whose stack drops off a
   cliff — marked with an axis asterisk that the footer line defines, so the
   closing frame cannot be read as "publishing collapsed".

The race uses raw GDELT article counts, never the payload's `index` field:
`index` is normalized to each term's own five-year peak, so a term peaking at 43
mentions scores 100 exactly like one peaking at 3,262. Racing on it would
compare nothing. A claims check guards that `index` still means what that
reasoning assumes.

Smoothing is a judgement call worth recording: ranked by raw monthly counts the
race board churns ~11.8 rank-positions per step (unreadable); on a trailing
12-month sum it churns 1.86. The race therefore starts at the first **complete**
twelve-month window, so no bar is ever drawn from a partial sum.

## CI

- `ci.yml` **site-smoke** job: `make_motion.py --check` — a hard gate. Loads
  each scene, asserts no reported failures and a sane frame count, samples three
  frames and asserts they are non-blank and mutually distinct. ~4s, no encode.
  A scene that cannot render is a code bug and costs nothing to catch here.
- `ci.yml` **deploy** and `nightly.yml` **refresh**: full render before the
  artifact upload, `continue-on-error: true`, matching the carousel steps. The
  nightly's non-blocking rule exists because a social build product once held
  the site on stale data for two days; clips inherit it. Failures still leave a
  paper trail on the `nightly-failure` issue.

`site_smoke.py` is untouched — `motion.html` is a capture template, not a reader
page, exactly as `carousel.html` is excluded.

## Cost

~1 min capture per scene, ~3.5 min for all three, inside the nightly's
120-minute budget. MP4s run 0.7–0.9 MB, GIFs ~1 MB.

## Encoder

`imageio-ffmpeg` (pip wheel, static binary) rather than a system ffmpeg, so
local machines and CI runners share one pinned encoder instead of tracking
whatever the runner image ships.

## Deferred

- **Tier C datasets** — `nvd_decay` (22 points), `nvd_throughput` (19),
  `cna_roster` (13), `botnet_weather` (10 days), `epss_volatility` (12). These
  are the append-only irreplaceable histories; they become good animation
  candidates in 6–12 months. A 10-frame clip reads as broken.
- **Tier B stories** — DNSSEC adoption (154 months, the site's longest series,
  and the strongest remaining candidate), CWE share race, time-to-PoC IQR band,
  breach class shares, extortion quarters, the CVE weekday radar.
- **Log scale for the race.** The linear axis squashes the tail early on
  (57.6k against 114). Kept linear: it resolves as the race flattens, and all
  14 terms show with no silent truncation.
