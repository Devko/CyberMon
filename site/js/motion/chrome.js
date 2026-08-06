// =============================================================================
// chrome.js — shared scaffolding for every motion scene.
//
// Holds the three things all scenes agree on:
//   1. the 1080×1350 sheet's furniture (wordmark, kicker, headline, footer
//      meta, clock, progress hairline),
//   2. the frame plan (intro hold → per-step travel → outro hold) and the
//      pure frame → (step, t) mapping every seek() needs,
//   3. an ECharts factory with animation forced OFF.
//
// That last point is the load-bearing one. Capture is seek-driven: frame i must
// paint identically no matter how fast the machine runs. ECharts' own
// transitions are wall-clock timers, so a chart left animating would paint
// mid-tween at capture time and the clip would differ run to run. Scenes tween
// by writing data per frame instead; ECharts only ever draws a static state.
// =============================================================================
import { el } from "../dom.js";
import { editorial } from "../editorial.js";

export const lerp = (a, b, t) => a + (b - a) * t;

// Hold, swap, hold: travel is confined to the middle SWAP_WINDOW of a step.
// Used where a value crossing must read as a deliberate move rather than a
// slow drift through ambiguity (the race's rank swaps, above all).
export const SWAP_WINDOW = 0.4;
export const easeSwap = (t) => {
  const u = Math.min(1, Math.max(0, (t - (1 - SWAP_WINDOW) / 2) / SWAP_WINDOW));
  return u * u * (3 - 2 * u);
};

// Plain smoothstep, for scenes whose motion is a continuous draw rather than a
// discrete swap.
export const easeSmooth = (t) => t * t * (3 - 2 * t);

/**
 * Frame plan shared by every scene.
 *
 * @param {number} steps   data columns (months, years, …)
 * @param {number} intro   held frames on the opening state
 * @param {number} perStep frames of travel between two columns — keep ODD so
 *                         t never lands exactly on 0.5, the one instant two
 *                         crossing elements would be perfectly coincident
 * @param {number} outro   held frames on the closing state, so the final board
 *                         can actually be read
 */
export function framePlan({ steps, intro, perStep, outro }) {
  const last = steps - 1;
  const travel = last * perStep;
  const frames = intro + travel + outro;
  return {
    frames,
    // Pure: same frame index always yields the same position.
    at(frame) {
      let s, t;
      if (frame < intro) {
        s = 0; t = 0;
      } else if (frame < intro + travel) {
        const k = frame - intro;
        s = Math.floor(k / perStep);
        t = (k % perStep) / perStep;
      } else {
        s = last; t = 0;
      }
      return { s, s2: Math.min(s + 1, last), t, progress: (frame + 1) / frames };
    },
  };
}

/**
 * Build the sheet furniture and return the handles a scene needs.
 * Copy comes from editorial.motion.scenes[<id>] — never hardcoded here, so the
 * claims audit can reach every user-facing string.
 */
export function buildChrome(stage, sceneId, metaText) {
  const ed = editorial.motion.scenes[sceneId];
  if (!ed) throw new Error(`no editorial.motion.scenes["${sceneId}"] copy`);

  const head = el("div");
  head.append(
    el("p", "m-wordmark", editorial.motion.wordmark),
    el("div", "m-rule"),
    el("p", "m-kicker", ed.kicker),
    el("h1", "m-headline", ed.headline)
  );

  const body = el("div", "m-body");

  // Clock block: the big period stamp, plus an optional smaller readout under
  // it for a scene's headline number (a running total, a current share).
  const clock = el("div", "m-clock");
  const sub = el("div", "m-sub");
  const clockBlock = el("div", "m-clock-block");
  clockBlock.append(clock, sub);

  const meta = el("p", "m-meta");
  meta.append(el("strong", null, ed.source), " — ", metaText);
  const foot = el("div", "m-foot");
  foot.append(meta, clockBlock);

  const fill = el("div", "m-progress-fill");
  const progress = el("div", "m-progress");
  progress.append(fill);

  stage.append(head, body, foot, progress);

  return {
    body,
    setClock: (text) => { clock.textContent = text; },
    setSub: (text) => { sub.textContent = text; },
    setProgress: (p) => { fill.style.width = `${(p * 100).toFixed(3)}%`; },
  };
}

/**
 * ECharts instance for a motion scene: animation off, permanently.
 *
 * setOption is wrapped rather than merely passed `animation: false` once —
 * a later setOption without the flag would silently re-enable tweening, which
 * is exactly the kind of regression that only shows up as a flickering clip.
 * (carousel.js:280 wraps setOption the same way for the same reason.)
 */
export function mkMotionChart(node) {
  const chart = window.echarts.init(node, null, { renderer: "canvas" });
  const setOption = chart.setOption.bind(chart);
  chart.setOption = (option, ...rest) => setOption({ ...option, animation: false }, ...rest);
  return chart;
}

// Type sizes for charts on the 1080×1350 sheet. theme.js's 10–12px are sized
// for a reader page at desktop width; at video scale they vanish.
export const MOTION_FONT = { axis: 19, name: 17, legend: 21 };
