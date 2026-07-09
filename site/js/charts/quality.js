// Chart 7 — advisory quality. Contract: site/data/advisory_quality.json
// Three lines: share of the year's published records missing a CWE, a CVSS
// base score, and usable affected-version data. Newsprint-neutral palette —
// this is a gap report, not an alarm, so the accent stays in its holster.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, fmtPct, escapeHtml } from "../theme.js";
import { editorial } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.quality;
  const rows = data.years || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = rows.map((r) => (r.year === genYear ? `${r.year}*` : String(r.year)));

  const LINES = [
    { key: "cwe", name: ed.legendCwe, color: "#c08a45" },
    { key: "cvss", name: ed.legendCvss, color: "#ded7c2" },
    { key: "affected", name: ed.legendAffected, color: "#847e6d" },
  ];

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 44 },
    legend: { ...baseLegend, data: LINES.map((l) => l.name) },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const r = params.length && rows[params[0].dataIndex];
        if (!r) return "";
        const head =
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(String(params[0].axisValueLabel ?? params[0].name))}` +
          ` · ${fmtInt(r.n)} records</div>`;
        const body = LINES.map(({ key, name, color }) =>
          `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
          `<span><span style="display:inline-block;width:8px;height:8px;background:${color};margin-right:6px;"></span>` +
          `${escapeHtml(name)}</span>` +
          `<strong style="font-family:inherit">${fmtPct(r[`pct_missing_${key}`])} · ${fmtInt(r[`missing_${key}`])}</strong></div>`
        ).join("");
        return head + body;
      },
    },
    xAxis: catAxis(cats, { boundaryGap: false }),
    yAxis: valAxis({
      min: 0, max: 100,
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series: LINES.map(({ key, name, color }) => ({
      name, type: "line", color,
      data: rows.map((r) => r[`pct_missing_${key}`]),
      symbol: "circle", symbolSize: 4,
      lineStyle: { width: 2 },
    })),
  });
}
