// 02 — monthly AI-credited CVEs, one kind at a time. Contract:
// site/data/ai_credits.json (kinds.<kind>.months). The toggle swaps the
// whole series set: labs and vendors are counted under different rules and
// must never share a stack. A CVE crediting two labs ticks both lanes, so
// the tooltip reports the month's distinct-CVE total separately.
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid,
  fmtInt, tooltipRows, tooltipFootnote,
} from "../theme.js";
import { editorial } from "../editorial.js";
import { el, clear } from "../dom.js";
import { mkToggle } from "../ui.js";

const KINDS = ["llm", "vendor"];

// Newsprint-neutral lanes. Accent stays off this chart on purpose: no lab
// gets the site's one alarm colour.
const LANE_COLORS = {
  anthropic: C.sev.high,
  openai: C.versions.v3,
  google: C.versions.v4,
  other_llm: C.sev.unscored,
  vendor: C.versions.v4,
};

export function render(slots, data) {
  const ed = editorial.sections.credits_lanes;
  const available = KINDS.filter((k) => data.kinds[k].months.length);
  if (!available.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }

  let chart = null;
  function draw(kind) {
    const k = data.kinds[kind];
    if (!k.months.length) {
      chart?.dispose();
      chart = null;
      clear(slots.chart).append(el("div", "nodata-card", ed.nodata));
      return;
    }
    if (!chart) {
      clear(slots.chart);
      chart = mkChart(slots.chart);
    }
    const months = k.months;
    const totals = Object.fromEntries(k.lanes.map((lane) =>
      [ed.laneLabels[lane], months.reduce((n, m) => n + m[lane], 0)]));
    chart.setOption({
      grid: { ...baseGrid, left: 46, top: 40, bottom: 40 },
      legend: {
        ...baseLegend,
        itemHeight: 8,
        show: k.lanes.length > 1,
        // The four lab tones differ mostly in brightness; the total beside
        // each name lets the legend be read without matching colours.
        formatter: (name) => `${name} · ${fmtInt(totals[name] ?? 0)}`,
      },
      tooltip: {
        ...baseTooltip,
        trigger: "axis",
        axisPointer: { type: "shadow" },
        formatter: (params) => {
          const m = months[params[0]?.dataIndex];
          return tooltipRows(params.filter((p) => p.value), fmtInt) +
            (m ? tooltipFootnote([`${fmtInt(m.total)} distinct CVEs`]) : "");
        },
      },
      xAxis: catAxis(months.map((m) => m.month), {
        axisLabel: {
          color: C.muted, fontFamily: MONO, fontSize: 11, interval: 0,
          // A short monthly axis: label January (the year) and each quarter.
          formatter: (val, idx) => {
            const [year, mo] = String(val).split("-");
            if (idx === 0 || mo === "01") return year;
            return ["04", "07", "10"].includes(mo) ? mo : "";
          },
        },
      }),
      yAxis: valAxis({
        minInterval: 1,
        name: ed.yAxis,
        nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
      }),
      series: k.lanes.map((lane) => ({
        name: ed.laneLabels[lane],
        type: "bar",
        stack: kind,
        barWidth: "68%",
        itemStyle: { color: LANE_COLORS[lane], borderColor: C.panel, borderWidth: 1 },
        data: months.map((m) => m[lane]),
      })),
    }, { notMerge: true });
  }

  const start = Math.max(0, KINDS.indexOf(available[0]));
  slots.controls.append(mkToggle(ed.toggleLabels, (i) => draw(KINDS[i]), start));
  draw(KINDS[start]);
}
