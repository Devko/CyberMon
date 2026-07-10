// Hygiene 2 — the fixed ten-economy set, quarterly validation-rate lines.
// Contract: site/data/dnssec_adoption.json. The payload arrives ranked by
// current rate; the palette follows that ranking (light = leading), with
// the accent reserved for the bottom of the table — the laggard giant is
// the story. The world aggregate rides along as a dashed reference.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, tooltipRows, fmtPct, MONO } from "../theme.js";
import { editorial } from "../editorial.js";
import { el } from "../dom.js";

// Rank-ordered line colors, best rate first. Grays would blur together at
// ten lines; a few warm newsprint tones keep neighbors tellable-apart.
// The last (lowest) series is overridden to the accent below.
const RAMP = ["#ded7c2", "#c9b98a", "#c08a45", "#b3ab96", "#96907f",
              "#8a6f4d", "#77715f", "#68624f", "#5d594e", "#4b473d"];

export function render(slots, data) {
  const economies = data.economies || [];
  if (!economies.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // Category axis = the union of every economy's sampled months.
  const monthSet = new Set();
  for (const economy of economies)
    for (const point of economy.series) monthSet.add(point.month);
  const months = [...monthSet].sort();
  const index = new Map(months.map((m, i) => [m, i]));

  const alignSeries = (series) => {
    const values = new Array(months.length).fill(null);
    for (const point of series) values[index.get(point.month)] = point.validating_pc;
    return values;
  };

  const series = economies.map((economy, i) => ({
    name: economy.name,
    type: "line",
    data: alignSeries(economy.series),
    color: i === economies.length - 1 ? C.accent : RAMP[i % RAMP.length],
    symbol: "circle", symbolSize: 3,
    lineStyle: { width: i === economies.length - 1 ? 2 : 1.5 },
    connectNulls: true, // quarterly grids can start at different months
  }));

  // World aggregate as a dashed reference, filtered to the axis months so
  // its monthly sampling never adds categories the economies don't have.
  const worldRows = (data.world?.series || []).filter((r) => index.has(r.month));
  if (worldRows.length) {
    series.push({
      name: editorial.sections.economies.worldLine,
      type: "line",
      data: alignSeries(worldRows),
      color: C.muted, symbol: "none",
      lineStyle: { width: 1, type: [4, 4] },
      connectNulls: true,
    });
  }

  // Label the first sampled month of each year (hygiene_world.js pattern).
  const firstOfYear = new Set();
  const seenYears = new Set();
  for (const m of months) {
    const year = m.slice(0, 4);
    if (!seenYears.has(year)) {
      seenYears.add(year);
      firstOfYear.add(m);
    }
  }

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 46, top: 56 },
    legend: { ...baseLegend, type: "scroll" },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => tooltipRows(params, fmtPct),
    },
    xAxis: catAxis(months, {
      boundaryGap: false,
      axisLabel: {
        color: C.muted, fontFamily: MONO, fontSize: 10,
        interval: 0,
        formatter: (v) => (firstOfYear.has(v) ? v.slice(0, 4) : ""),
      },
    }),
    yAxis: valAxis({
      min: 0,
      max: 100,
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series,
  });
}
