// =============================================================================
// hype_race.js — animated scene: four years of security's news cycle, ranked.
//
// Contract: site/data/market_hype.json (the Market module's payload).
//
// WHY RAW COUNTS, NOT THE INDEX
// -----------------------------
// Every term in market_hype.json carries an `index` normalized to THAT TERM'S
// own five-year peak — which is the right axis for the site's per-term hype
// curves, and the wrong one for a race. Indexed against itself, a term with 43
// mentions at its peak scores 100 exactly like a term with 3,262. Racing on
// `index` would compare nothing. This scene races the raw GDELT article count
// `n`, which is one source measured one way, so the bars are comparable.
//
// WHY A TRAILING TWELVE MONTHS
// ----------------------------
// Single-month counts are noisy enough to be unreadable in motion: ranked by
// raw month, the board reshuffles ~11.8 positions per step. A trailing
// twelve-month sum churns 1.86 — still alive, actually legible. The race
// therefore starts at the first month with a COMPLETE twelve-month window
// (the twelfth), so no bar is ever drawn from a partial sum.
//
// WHY DOM AND NOT ECHARTS
// -----------------------
// A race needs bars at fractional rank positions so two swapping bars glide
// past each other; an ECharts category axis snaps between slots. DOM rows moved
// by an inline translateY do it exactly, and give real text rendering rather
// than canvas text. The other planned scenes (stacked area, dual-axis lines)
// are real charting and stay on ECharts.
// =============================================================================
import { el } from "../dom.js";
import { editorial, tpl } from "../editorial.js";
import { buildChrome, framePlan, lerp, easeSwap } from "./chrome.js";

const SOURCE = "gdelt";      // news article volume — the one cross-term measure
const WINDOW = 12;           // months summed per bar
const ROW_PITCH = 63;        // px between row baselines
const TRACK_W = 580;         // px, mirrors .m-track in css/motion.css

// Frame budget @ 30fps: 24 + 47*9 + 60 = 507 frames ≈ 16.9s. FRAMES_PER_STEP is
// odd on purpose — see framePlan() in chrome.js.
const INTRO_HOLD = 24;
const FRAMES_PER_STEP = 9;
const OUTRO_HOLD = 60;

const MONTHS = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN",
                "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];

const fmtClock = (ym) => {
  const [y, m] = ym.split("-");
  return `${MONTHS[Number(m) - 1]} ${y}`;
};

// Rank order (0 = largest) of every term for one column of values.
function ranksOf(values) {
  const order = values
    .map((v, i) => [v, i])
    .sort((a, b) => b[0] - a[0] || a[1] - b[1]); // index breaks ties: stable
  const ranks = new Array(values.length);
  order.forEach(([, i], r) => { ranks[i] = r; });
  return ranks;
}

export const scene = {
  id: "hype-race",
  data: "data/market_hype.json",

  setup(stage, data) {
    const terms = (data.terms || []).filter((t) => (t.series?.[SOURCE] || []).length);
    if (terms.length < 2) throw new Error(`hype-race: need 2+ terms with ${SOURCE} data, got ${terms.length}`);

    const months = terms[0].series[SOURCE].map((p) => p.month);
    if (months.length <= WINDOW) {
      throw new Error(`hype-race: need >${WINDOW} months, got ${months.length}`);
    }
    // Every term must share the month grid, or a trailing sum would silently
    // compare different spans across bars.
    for (const t of terms) {
      const m = t.series[SOURCE].map((p) => p.month);
      if (m.length !== months.length || m.some((v, i) => v !== months[i])) {
        throw new Error(`hype-race: "${t.label}" has a different ${SOURCE} month grid`);
      }
    }

    // Trailing WINDOW-month sums, keeping only the complete windows.
    const steps = months.slice(WINDOW - 1);
    const series = terms.map((t) => {
      const n = t.series[SOURCE].map((p) => p.n);
      const out = [];
      for (let i = WINDOW - 1; i < n.length; i++) {
        let s = 0;
        for (let k = i - WINDOW + 1; k <= i; k++) s += n[k];
        out.push(s);
      }
      return out;
    });

    // Precompute per-step ranks and axis maxima — seek() stays pure lookup+lerp.
    const ranks = steps.map((_, s) => ranksOf(series.map((v) => v[s])));
    const maxima = steps.map((_, s) => Math.max(...series.map((v) => v[s]), 1));

    // ---- DOM ----------------------------------------------------------------
    const ed = editorial.motion.scenes[this.id];
    const chrome = buildChrome(stage, this.id, tpl(ed.meta, { terms: terms.length }));

    const race = el("div", "m-race");
    chrome.body.append(race);
    const rows = terms.map((t) => {
      const row = el("div", "m-row");
      const bar = el("div", "m-bar");
      const track = el("div", "m-track");
      track.append(bar);
      const value = el("div", "m-value");
      const label = el("div", "m-label", t.label);
      row.append(label, track, value);
      race.append(row);
      return { row, bar, label, value };
    });

    const plan = framePlan({
      steps: steps.length, intro: INTRO_HOLD,
      perStep: FRAMES_PER_STEP, outro: OUTRO_HOLD,
    });
    this._m = { rows, steps, series, ranks, maxima, chrome, plan };
    return { frames: plan.frames };
  },

  // Pure function of `frame`: same index always paints the same pixels.
  seek(frame) {
    const { rows, steps, series, ranks, maxima, chrome, plan } = this._m;
    const { s, s2, t, progress } = plan.at(frame);
    const et = easeSwap(t);

    const axisMax = lerp(maxima[s], maxima[s2], t);

    for (let i = 0; i < rows.length; i++) {
      const v = lerp(series[i][s], series[i][s2], t);
      const pos = lerp(ranks[s][i], ranks[s2][i], et);
      const { row, bar, label, value } = rows[i];

      row.style.transform = `translateY(${(pos * ROW_PITCH).toFixed(2)}px)`;
      bar.style.width = `${((v / axisMax) * TRACK_W).toFixed(2)}px`;
      value.textContent = Math.round(v).toLocaleString("en-US");
      // Leader by interpolated position, so the accent hands over exactly when
      // the bars cross rather than when the underlying month ticks.
      row.classList.toggle("is-leader", pos < 0.5);
      // Higher rank paints on top, so an overtake reads as one row sliding over
      // another instead of two texts blending. .m-row is opaque for this to
      // work, which is also why the fade below is applied per child: opacity on
      // the row itself would make its background translucent and let the row
      // underneath show through mid-swap.
      row.style.zIndex = String(1000 - Math.round(pos * 10));
      // Rank 0 reads full strength; the tail fades but never disappears.
      const fade = (1 - Math.min(pos, rows.length - 1) / (rows.length - 1) * 0.55).toFixed(3);
      bar.style.opacity = fade;
      label.style.opacity = fade;
      value.style.opacity = fade;
    }

    chrome.setClock(fmtClock(steps[t < 0.5 ? s : s2]));
    chrome.setProgress(progress);
  },
};
