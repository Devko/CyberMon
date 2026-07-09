// Concentration 2 — first-year CNAs (bars) vs. the active roster (line),
// both counts on ONE integer axis (volume.js twin-series idiom).
// Contract: site/data/cna_concentration.json (shared by all three
// concentration sections; concentration.js fetches it once).
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, tooltipRows, fmtInt } from "../theme.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const years = data.years || [];
  if (!years.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = years.map((d) => (d.year === genYear ? `${d.year}*` : String(d.year)));

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 44 },
    legend: { ...baseLegend, data: ["First-year CNAs", "Active CNAs"] },
    tooltip: { ...baseTooltip, trigger: "axis", formatter: (p) => tooltipRows(p, fmtInt) },
    xAxis: catAxis(cats),
    yAxis: valAxis({
      min: 0,
      minInterval: 1, // counts — never fractional gridlines
      axisLabel: { color: C.muted, fontFamily: baseLegend.textStyle.fontFamily, fontSize: 11 },
    }),
    series: [
      {
        name: "First-year CNAs", type: "bar",
        data: years.map((d) => d.newcomer_count),
        color: C.accent, itemStyle: { opacity: 0.75 },
        barMaxWidth: 18,
      },
      {
        name: "Active CNAs", type: "line",
        data: years.map((d) => d.cna_count),
        color: C.ink, symbol: "none", lineStyle: { width: 2 }, z: 5,
      },
    ],
  });
}
