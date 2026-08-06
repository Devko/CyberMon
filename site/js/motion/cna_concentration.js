// =============================================================================
// cna_concentration.js — animated scene: two forces pulling apart. The share of
// CVEs issued by the five largest CNAs falls while the number of CNAs issuing
// anything at all climbs. Contract: site/data/cna_concentration.json.
//
// The story is the DIVERGENCE, so both series draw simultaneously on their own
// axes and the gap between them opens on screen. Drawing them one after another
// would show two trends; drawing them together shows one.
//
// Same fractional-x trick as severity_flood.js: years live on a value axis so
// the drawing tip can sit between two years instead of hopping a year per step.
// =============================================================================
import { C, MONO, fmtInt, fmtPct } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";
import { buildChrome, framePlan, lerp, mkMotionChart, MOTION_FONT } from "./chrome.js";

// Frame budget @ 30fps: 20 + 27*13 + 55 = 426 frames ≈ 14.2s — deliberately the
// same shape as severity_flood so the two cut together.
const INTRO_HOLD = 20;
const FRAMES_PER_STEP = 13;  // odd — see framePlan() in chrome.js
const OUTRO_HOLD = 55;

export const scene = {
  id: "cna-concentration",
  data: "data/cna_concentration.json",

  setup(stage, data) {
    const years = data.years || [];
    if (years.length < 3) throw new Error(`cna-concentration: need 3+ years, got ${years.length}`);

    const xs = years.map((d) => d.year);
    const shares = years.map((d) => d.top5_share);
    const counts = years.map((d) => d.cna_count);
    const genYear = Number(data.generated_at.slice(0, 4));
    const countMax = Math.max(...counts, 1);

    const ed = editorial.motion.scenes[this.id];
    const chrome = buildChrome(stage, this.id, tpl(ed.meta, { gen: genYear }));

    const node = el("div", "m-chart");
    chrome.body.append(node);
    const chart = mkMotionChart(node);

    const axisLabel = { color: C.muted, fontFamily: MONO, fontSize: MOTION_FONT.axis };
    const axisName = { color: C.faint, fontFamily: MONO, fontSize: MOTION_FONT.name };

    chart.setOption({
      grid: { left: 96, right: 104, top: 64, bottom: 56 },
      legend: {
        data: [ed.shareLabel, ed.countLabel],
        textStyle: { color: C.muted, fontFamily: MONO, fontSize: MOTION_FONT.legend },
        inactiveColor: C.faint,
        itemWidth: 22, itemHeight: 4, icon: "rect",
        top: 0, left: 0, itemGap: 26,
      },
      xAxis: {
        type: "value",
        min: xs[0], max: xs[xs.length - 1],
        interval: 5,  // whole years only; a value axis invents 2012.5 otherwise
        // Asterisk on the part-written year (footer meta defines it), matching
        // the site's static charts and severity_flood.js.
        axisLabel: {
          ...axisLabel,
          formatter: (v) => `${Math.round(v)}${Math.round(v) === genYear ? "*" : ""}`,
        },
        axisLine: { lineStyle: { color: C.rule } },
        axisTick: { show: false },
        splitLine: { show: false },
      },
      yAxis: [
        {
          type: "value", min: 0, max: 100,
          name: "share", nameTextStyle: axisName,
          axisLabel: { ...axisLabel, formatter: "{value}%" },
          axisLine: { show: false }, axisTick: { show: false },
          splitLine: { lineStyle: { color: C.rule, type: [2, 4] } },
        },
        {
          type: "value", min: 0, max: countMax,
          name: "CNAs", nameTextStyle: axisName,
          axisLabel,
          axisLine: { show: false }, axisTick: { show: false },
          splitLine: { show: false },  // one set of gridlines is enough
        },
      ],
      series: [
        {
          name: ed.shareLabel, type: "line", yAxisIndex: 0, data: [],
          color: C.accent, symbol: "none", lineStyle: { width: 4 },
          areaStyle: { color: C.accentSoft }, z: 5,
        },
        {
          name: ed.countLabel, type: "line", yAxisIndex: 1, data: [],
          color: C.ink, symbol: "none", lineStyle: { width: 3, type: [7, 5] }, z: 4,
        },
      ],
    });

    const plan = framePlan({
      steps: years.length, intro: INTRO_HOLD,
      perStep: FRAMES_PER_STEP, outro: OUTRO_HOLD,
    });
    this._m = { chart, xs, shares, counts, chrome, plan, genYear, ed };
    return { frames: plan.frames };
  },

  seek(frame) {
    const { chart, xs, shares, counts, chrome, plan, genYear, ed } = this._m;
    const { s, s2, t, progress } = plan.at(frame);

    const tipX = lerp(xs[s], xs[s2], t);
    const draw = (vals) => {
      const pts = [];
      for (let i = 0; i <= s; i++) pts.push([xs[i], vals[i]]);
      if (s2 !== s) pts.push([tipX, lerp(vals[s], vals[s2], t)]);
      return pts;
    };

    chart.setOption({
      series: [
        { name: ed.shareLabel, data: draw(shares) },
        { name: ed.countLabel, data: draw(counts) },
      ],
    });

    const shown = t < 0.5 ? xs[s] : xs[s2];
    chrome.setClock(shown === genYear ? `${shown}*` : String(shown));
    // Both current values, so the sheet always states the two numbers whose
    // divergence is the whole point.
    chrome.setSub(
      `${fmtPct(lerp(shares[s], shares[s2], t))} · ` +
      `${fmtInt(Math.round(lerp(counts[s], counts[s2], t)))} CNAs`
    );
    chrome.setProgress(progress);
  },
};
