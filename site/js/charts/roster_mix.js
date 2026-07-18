// Roster 3 — today's roster composition, by organization type. Contract:
// site/data/cna_roster.json (roster_mix section). This is the one section
// that is fully real from day one: a horizontal bar per CNA type, tallied
// across every organization on the roster tonight. An org can hold several
// types, so the bars sum above the roster total (the caption says so).
import {
  C, MONO, mkChart, catAxis, valAxis, baseGrid, baseTooltip, fmtInt,
  escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.roster_mix;
  const mix = data.roster_mix || {};
  const h = data.headline;
  const byType = mix.by_type || [];

  if (!byType.length || !h) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }

  // Context stat: roster size, country reach, the two top-level roots — all
  // from the data file, never hardcoded.
  slots.stat.append(el("div", "table-context", tpl(ed.statTemplate, {
    total: fmtInt(h.roster_total),
    countries: fmtInt(h.country_count),
    mitre: fmtInt(h.mitre_n),
    cisa: fmtInt(h.cisa_n),
  })));

  // ECharts plots the first category at the bottom, so reverse the
  // count-descending list to put the largest type on top.
  const rows = byType.slice().reverse();
  const maxN = h.top_type_n || 1;

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 150, right: 32, top: 12, bottom: 36 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params) => {
        const p = params[0];
        if (!p) return "";
        const pct = mix.total ? (100 * p.value) / mix.total : 0;
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(p.axisValue)}</div>` +
          `<strong>${fmtInt(p.value)}</strong> organizations ` +
          `<span style="color:${C.muted}">(${pct.toFixed(0)}% of roster)</span>`
        );
      },
    },
    xAxis: valAxis({
      name: ed.xAxis,
      nameLocation: "middle",
      nameGap: 24,
      minInterval: 1,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
    }),
    yAxis: catAxis(rows.map((r) => r.label), {
      axisLabel: { ...catAxis([]).axisLabel, fontSize: 11 },
    }),
    series: [
      {
        name: "Organizations",
        type: "bar",
        barWidth: "62%",
        data: rows.map((r) => ({
          value: r.n,
          // The largest type reads in accent; the rest stay newsprint-neutral.
          itemStyle: { color: r.n === maxN ? C.accent : C.versions.v3 },
        })),
        label: {
          show: true,
          position: "right",
          color: C.muted,
          fontFamily: MONO,
          fontSize: 11,
          formatter: (p) => fmtInt(p.value),
        },
      },
    ],
  });
}
