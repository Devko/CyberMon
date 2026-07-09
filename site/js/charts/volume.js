// Chart 6 — volume curve. Contract: site/data/volume_curve.json
import { C, mkChart, catAxis, baseTooltip, baseLegend, baseGrid, tooltipRows, fmtInt } from "../theme.js";
import { editorial } from "../editorial.js";
import { mkToggle } from "../ui.js";

export function render(slots, data) {
  const ed = editorial.sections.volume;
  const years = data.years.map((d) => String(d.year));

  const chart = mkChart(slots.chart);

  const setScale = (log) => {
    chart.setOption(
      {
        grid: { ...baseGrid, left: 54, top: 44 },
        legend: { ...baseLegend, data: ["Published", "Rejected"] },
        tooltip: { ...baseTooltip, trigger: "axis", formatter: (p) => tooltipRows(p, fmtInt) },
        xAxis: catAxis(years, { boundaryGap: false }),
        yAxis: {
          type: log ? "log" : "value",
          logBase: 10,
          min: log ? 1 : 0,
          axisLine: { show: false },
          axisLabel: {
            color: C.muted, fontFamily: baseLegend.textStyle.fontFamily, fontSize: 11,
            formatter: (v) => (v >= 1000 ? `${v / 1000}k` : String(v)),
          },
          splitLine: { lineStyle: { color: C.rule, type: [2, 4] } },
        },
        series: [
          {
            name: "Published", type: "line",
            data: data.years.map((d) => d.published),
            color: C.ink, symbol: "none", lineStyle: { width: 2 },
            areaStyle: { color: C.ink, opacity: 0.05 },
          },
          {
            name: "Rejected", type: "line",
            data: data.years.map((d) => d.rejected),
            color: C.accent, symbol: "none", lineStyle: { width: 1.5, type: [5, 3] },
          },
        ],
      },
      { replaceMerge: ["yAxis", "series"] }
    );
  };

  slots.controls.append(mkToggle([ed.toggleLinear, ed.toggleLog], (idx) => setScale(idx === 1)));
  setScale(false);
}
