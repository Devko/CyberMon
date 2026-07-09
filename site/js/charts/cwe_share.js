// Chart 8 — bug-class inertia. Contract: site/data/cwe_distribution.json
// Stacked shares of the year's CWE-tagged records: top-8 classes by decade
// volume, biggest at the bottom, "Other" capping the stack in the faintest
// ink. Shares sum to ~100 per year, so the stack reads as a full bar.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, fmtPct, escapeHtml } from "../theme.js";
import { editorial } from "../editorial.js";
import { el } from "../dom.js";

// Newsprint ramp for up to 8 classes (volume order: loudest inks first).
const RAMP = ["#ded7c2", "#c08a45", "#a89f8a", "#8a6f4d",
              "#847e6d", "#77715f", "#5d594e", "#4b473d"];
const OTHER_COLOR = "#312f2a";

export function render(slots, data) {
  const ed = editorial.sections.cwe;
  const rows = data.years || [];
  const top = data.top_cwes || [];
  if (!rows.length || !top.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  const bands = top.map((t, i) => ({
    key: t.id,
    // Unmapped ids have name === id; don't print "CWE-1321 · CWE-1321".
    label: t.name === t.id ? t.id : `${t.id} · ${t.name}`,
    color: RAMP[i % RAMP.length],
  }));
  bands.push({ key: "other", label: ed.otherLabel, color: OTHER_COLOR });

  const chart = mkChart(slots.chart);
  chart.setOption({
    // 9 series (8 classes + Other) wrap to several legend rows; leave room.
    grid: { ...baseGrid, left: 50, top: 96 },
    legend: { ...baseLegend, data: bands.map((b) => b.label), icon: "rect", itemHeight: 8 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      order: "seriesDesc",
      formatter: (params) => {
        const r = params.length && rows[params[0].dataIndex];
        if (!r) return "";
        const head =
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(r.year))}` +
          ` · ${fmtInt(r.n_tagged)} tagged (${fmtPct(r.pct_tagged)} of ${fmtInt(r.n_published)} published)</div>`;
        const body = params
          .filter((p) => p.value !== null && p.value !== undefined)
          .map((p) =>
            `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
            `<span>${p.marker} ${escapeHtml(p.seriesName)}</span>` +
            `<strong style="font-family:inherit">${fmtPct(p.value)}</strong></div>`)
          .join("");
        return head + body;
      },
    },
    xAxis: catAxis(rows.map((r) => String(r.year)), { boundaryGap: false }),
    yAxis: valAxis({
      min: 0, max: 100,
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series: bands.map(({ key, label, color }) => ({
      name: label,
      type: "line",
      stack: "cwe",
      color,
      areaStyle: { color, opacity: key === "other" ? 0.55 : 0.8 },
      lineStyle: { width: 0 },
      symbol: "none",
      emphasis: { focus: "series" },
      data: rows.map((r) => r.shares[key] ?? 0),
    })),
  });
}
