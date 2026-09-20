// 05 — what AI finds: weakness families for labs and vendors against the
// baseline. Contract: site/data/ai_credits.json (weaknesses.families).
// Shares, not counts (the populations differ by two orders of magnitude);
// the baseline is a tick on each family's row, not a third bar, so the eye
// reads "above or below everyone else" rather than three-way bar heights.
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid,
  fmtInt, fmtPct, escapeHtml,
} from "../theme.js";
import { editorial } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.credits_weakness;
  const families = data.weaknesses?.families || [];
  if (!families.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }

  // ECharts draws a category y-axis bottom-up; reverse so the registry's
  // first family (memory safety) sits on top.
  const rows = [...families].reverse();
  const series = (name, key, color) => ({
    name, type: "bar", barWidth: 9, barGap: "30%",
    itemStyle: { color },
    data: rows.map((f) => f[key].pct),
  });

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 8, right: 28, top: 40, bottom: 34, containLabel: true },
    legend: { ...baseLegend, itemHeight: 8 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params) => {
        const f = rows[params[0].dataIndex];
        const line = (label, cell) =>
          `<div style="display:flex;gap:14px;justify-content:space-between;">` +
          `<span>${escapeHtml(label)}</span>` +
          `<span><strong>${fmtPct(cell.pct)}</strong> ` +
          `<span style="color:${C.muted};">${fmtInt(cell.n)}</span></span></div>`;
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(f.label)}</div>` +
          line(ed.seriesLabels.llm, f.llm) +
          line(ed.seriesLabels.vendor, f.vendor) +
          line(ed.seriesLabels.baseline, f.baseline)
        );
      },
    },
    xAxis: valAxis({
      name: ed.xAxis,
      nameLocation: "middle",
      nameGap: 24,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: "{value}%" },
    }),
    yAxis: catAxis(rows.map((f) => f.label), {
      axisLabel: { color: C.ink, fontFamily: MONO, fontSize: 11 },
    }),
    series: [
      series(ed.seriesLabels.llm, "llm", C.sev.high),
      series(ed.seriesLabels.vendor, "vendor", C.versions.v4),
      {
        // the baseline as a tick spanning both bars of its row
        name: ed.seriesLabels.baseline,
        type: "scatter",
        symbol: "rect",
        symbolSize: [2, 30],
        itemStyle: { color: C.ink },
        z: 5,
        data: rows.map((f) => f.baseline.pct),
      },
    ],
  });
}
