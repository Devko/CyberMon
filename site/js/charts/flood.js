// Chart 2 — the 9.8 flood. Contract: site/data/nine_eight_flood.json
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, tooltipRows, fmtInt, fmtPct } from "../theme.js";
import { editorial } from "../editorial.js";
import { mkToggle } from "../ui.js";

const BUCKETS = [
  // stacking order: bottom -> top; Critical crowns the stack in accent red.
  { key: "unscored", label: "Unscored" },
  { key: "low", label: "Low" },
  { key: "medium", label: "Medium" },
  { key: "high", label: "High" },
  { key: "critical", label: "Critical (≥9.0)" },
];

export function render(slots, data) {
  const ed = editorial.sections.flood;
  const years = data.years.map((d) => String(d.year));

  const mkSeries = (normalized) =>
    BUCKETS.map(({ key, label }) => ({
      name: label,
      type: "line",
      stack: "sev",
      areaStyle: { color: C.sev[key], opacity: key === "critical" ? 0.9 : 0.75 },
      lineStyle: { width: 0 },
      color: C.sev[key],
      symbol: "none",
      emphasis: { focus: "series" },
      data: data.years.map((row) => {
        if (!normalized) return row[key];
        const total = BUCKETS.reduce((s, b) => s + row[b.key], 0);
        return total ? +((row[key] / total) * 100).toFixed(2) : 0;
      }),
    }));

  const chart = mkChart(slots.chart);

  const setMode = (normalized) => {
    chart.setOption(
      {
        grid: { ...baseGrid, left: 54, top: 44 },
        legend: { ...baseLegend, data: BUCKETS.map((b) => b.label).reverse(), icon: "rect", itemHeight: 8 },
        tooltip: {
          ...baseTooltip,
          trigger: "axis",
          order: "seriesDesc",
          formatter: (params) =>
            tooltipRows(params, (v) => (normalized ? fmtPct(v) : fmtInt(v))),
        },
        xAxis: catAxis(years, { boundaryGap: false }),
        yAxis: valAxis(
          normalized
            ? { max: 100, axisLabel: { color: C.muted, fontFamily: baseLegend.textStyle.fontFamily, fontSize: 11, formatter: "{value}%" } }
            : { max: null, axisLabel: { color: C.muted, fontFamily: baseLegend.textStyle.fontFamily, fontSize: 11, formatter: (v) => (v >= 1000 ? `${v / 1000}k` : v) } }
        ),
        series: mkSeries(normalized),
      },
      { replaceMerge: ["series", "yAxis"] }
    );
  };

  slots.controls.append(
    mkToggle([ed.toggleAbsolute, ed.toggleShare], (idx) => setMode(idx === 1))
  );
  setMode(false);
}
