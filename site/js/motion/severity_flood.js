// =============================================================================
// severity_flood.js — animated scene: the severity stack filling up, year by
// year. Contract: site/data/nine_eight_flood.json (the CVE module's payload).
//
// WHY A VALUE X-AXIS, NOT A CATEGORY AXIS
// ---------------------------------------
// The stack draws in from the left, and the drawing tip has to sit at a
// FRACTIONAL year — x = year + t — or the line jumps a whole year at a time and
// the growth reads as a staircase. Category axes only address integer slots, so
// this scene puts years on a value axis and feeds [x, y] pairs.
//
// WHY THE STACK IS COMPUTED HERE, NOT BY `stack:`
// -----------------------------------------------
// ECharts' `stack` option aligns series by data INDEX, which only means
// anything on a category axis. On the value axis this scene needs, it silently
// mis-renders — bands collapse into flat lines. So the cumulative sums are
// computed here and each band is drawn as its own area filling to zero, largest
// first, so later (smaller) bands paint over earlier ones. What stays visible
// between cum[k] and cum[k-1] is exactly band k. Bands must be fully opaque for
// this to hold: any transparency lets the band underneath bleed through and the
// colours mix into something that means nothing.
//
// THE ERA CAVEAT IS LOAD-BEARING
// ------------------------------
// Before record_era.year, CVEs were mostly scored in NVD's database rather than
// in the CVE record this chart reads. The wide "No score in record" band on the
// left is therefore a fact about the record FORMAT, not evidence that old
// vulnerabilities were harmless. The site's static chart marks that with a
// vertical rule; this scene carries the same marker AND states it in the footer
// meta, because a clip gets shared without its caption.
// =============================================================================
import { C, MONO, fmtInt } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";
import { buildChrome, framePlan, lerp, mkMotionChart, MOTION_FONT } from "./chrome.js";

// Stacking order: bottom -> top; Critical crowns the stack in accent red.
// Mirrors BUCKETS in charts/flood.js so the clip and the site agree.
const BUCKETS = [
  { key: "unscored", label: "No score in record" },
  { key: "low", label: "Low" },
  { key: "medium", label: "Medium" },
  { key: "high", label: "High" },
  { key: "critical", label: "Critical (≥9.0)" },
];

// Frame budget @ 30fps: 20 + 27*13 + 55 = 426 frames ≈ 14.2s.
const INTRO_HOLD = 20;
const FRAMES_PER_STEP = 13;  // odd — see framePlan() in chrome.js
const OUTRO_HOLD = 55;

export const scene = {
  id: "severity-flood",
  data: "data/nine_eight_flood.json",

  setup(stage, data) {
    const years = data.years || [];
    if (years.length < 3) throw new Error(`severity-flood: need 3+ years, got ${years.length}`);

    const xs = years.map((d) => d.year);
    const genYear = Number(data.generated_at.slice(0, 4));
    const eraYear = data.record_era?.year ?? null;

    // cum[k][i] = buckets 0..k summed for year i. cum[last] is the year total.
    const cum = [];
    for (let k = 0; k < BUCKETS.length; k++) {
      cum.push(years.map((d, i) =>
        (cum[k - 1] ? cum[k - 1][i] : 0) + (d[BUCKETS[k].key] || 0)));
    }
    const totals = cum[BUCKETS.length - 1];
    const yMax = Math.max(...totals, 1);

    // Painted largest-first so smaller bands overlay them; see the header note.
    const paintOrder = BUCKETS.map((_, k) => k).reverse();

    // Start of the part-written trailing segment, or null when the last year on
    // the axis is a complete one.
    const partialFrom = xs.length > 1 && xs[xs.length - 1] === genYear
      ? xs[xs.length - 2]
      : null;

    const ed = editorial.motion.scenes[this.id];
    const chrome = buildChrome(stage, this.id, tpl(ed.meta, {
      era: eraYear ?? "the marker",
      gen: genYear,
    }));

    const node = el("div", "m-chart");
    chrome.body.append(node);
    const chart = mkMotionChart(node);

    const axisLabel = { color: C.muted, fontFamily: MONO, fontSize: MOTION_FONT.axis };

    chart.setOption({
      grid: { left: 108, right: 34, top: 64, bottom: 56 },
      legend: {
        data: BUCKETS.map((b) => b.label),
        textStyle: { color: C.muted, fontFamily: MONO, fontSize: MOTION_FONT.legend },
        inactiveColor: C.faint,
        itemWidth: 22, itemHeight: 4, icon: "rect",
        top: 0, left: 0, itemGap: 22,
      },
      xAxis: {
        type: "value",
        min: xs[0], max: xs[xs.length - 1],
        // Whole years only: a value axis will happily invent 2012.5 ticks.
        interval: 5,
        // Asterisk on the part-written year, same convention as the site's
        // static chart (charts/flood.js). The footer meta defines it.
        axisLabel: {
          ...axisLabel,
          formatter: (v) => `${Math.round(v)}${Math.round(v) === genYear ? "*" : ""}`,
        },
        axisLine: { lineStyle: { color: C.rule } },
        axisTick: { show: false },
        splitLine: { show: false },
      },
      yAxis: {
        type: "value",
        min: 0, max: yMax,
        axisLabel: { ...axisLabel, formatter: (v) => (v >= 1000 ? `${Math.round(v / 1000)}k` : String(v)) },
        axisLine: { show: false },
        axisTick: { show: false },
        splitLine: { lineStyle: { color: C.rule, type: [2, 4] } },
      },
      // Legend keeps the reading order (bottom band first); the SERIES are
      // ordered by paint requirements, and ECharts matches the two by name.
      series: paintOrder.map((k, slot) => ({
        name: BUCKETS[k].label,
        type: "line",
        data: [],
        symbol: "none",
        lineStyle: { width: 0 },
        color: C.sev[BUCKETS[k].key],                 // legend swatch
        areaStyle: { color: C.sev[BUCKETS[k].key], opacity: 1 },
        // The era shading rides on the first-painted series so it sits behind
        // the stack. A tinted region reads at a glance where a vertical rule's
        // rotated label does not.
        markArea: slot === 0 ? {
          silent: true,
          itemStyle: { color: "rgba(233, 228, 216, 0.05)" },
          label: {
            color: C.muted, fontFamily: MONO, fontSize: MOTION_FONT.name,
            position: "insideTop", distance: 10, rotate: 0,
          },
          data: [
            ...(eraYear ? [[
              { xAxis: xs[0], name: ed.eraMarker },
              { xAxis: eraYear },
            ]] : []),
            // The trailing segment into a part-written year, tinted but
            // unlabelled — the band is only ~35px wide, so a label would spill
            // off the sheet. The axis asterisk names it instead. Only drawn when
            // the last year on the axis IS the generation year; run the pipeline
            // in early January and it may not be.
            ...(partialFrom !== null ? [[
              { xAxis: partialFrom, itemStyle: { color: "rgba(255, 74, 63, 0.09)" } },
              { xAxis: xs[xs.length - 1] },
            ]] : []),
          ],
        } : undefined,
      })),
    });

    const plan = framePlan({
      steps: years.length, intro: INTRO_HOLD,
      perStep: FRAMES_PER_STEP, outro: OUTRO_HOLD,
    });
    this._m = { chart, xs, cum, totals, paintOrder, chrome, plan, genYear };
    return { frames: plan.frames };
  },

  seek(frame) {
    const { chart, xs, cum, totals, paintOrder, chrome, plan, genYear } = this._m;
    const { s, s2, t, progress } = plan.at(frame);

    // Draw every complete year, then one interpolated tip at x = year + t so
    // the stack's leading edge slides along the real segment.
    const tipX = lerp(xs[s], xs[s2], t);

    chart.setOption({
      series: paintOrder.map((k) => {
        const vals = cum[k];
        const pts = [];
        for (let i = 0; i <= s; i++) pts.push([xs[i], vals[i]]);
        if (s2 !== s) pts.push([tipX, lerp(vals[s], vals[s2], t)]);
        return { name: BUCKETS[k].label, data: pts };
      }),
    });

    // The clock names the year actually reached, and flags the generation year
    // as partial the moment it appears — its bar is short because the year is
    // half-written, not because publishing slowed down.
    const shown = t < 0.5 ? xs[s] : xs[s2];
    chrome.setClock(shown === genYear ? `${shown}*` : String(shown));
    chrome.setProgress(progress);

    // Headline number for the year on screen: how many CVEs it published.
    chrome.setSub(`${fmtInt(Math.round(lerp(totals[s], totals[s2], t)))} published`);
  },
};
