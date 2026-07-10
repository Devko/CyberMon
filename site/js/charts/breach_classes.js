// Breach 3 — what leaks. Contract: site/data/breach_ledger.json (shared;
// breaches.js fetches it once). One line per top data class: the share of
// each year's cohort breaches listing that class. Multi-label, so the
// lines are independent — deliberately NOT a 100% stack (quality.js
// idiom, not cwe_share.js).
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, fmtPct, escapeHtml } from "../theme.js";
import { el } from "../dom.js";

// Newsprint ramp for up to 6 classes, loudest inks first (the class list
// arrives ranked by all-time frequency).
const RAMP = ["#ded7c2", "#c08a45", "#a89f8a", "#8a6f4d", "#847e6d", "#77715f"];

export function render(slots, data) {
  const shares = data.class_shares || {};
  const classes = shares.classes || [];
  const rows = shares.years || [];
  if (!rows.length || !classes.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = rows.map((r) => (r.year === genYear ? `${r.year}*` : String(r.year)));

  const lines = classes.map((name, i) => ({ name, color: RAMP[i % RAMP.length] }));

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 66 }, // 6 legend entries wrap to two rows
    legend: { ...baseLegend, data: lines.map((l) => l.name) },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const r = params.length && rows[params[0].dataIndex];
        if (!r) return "";
        const head =
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(String(params[0].axisValueLabel ?? params[0].name))}` +
          ` · ${fmtInt(r.n)} breaches</div>`;
        const body = lines.map(({ name, color }) =>
          `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
          `<span><span style="display:inline-block;width:8px;height:8px;background:${color};margin-right:6px;"></span>` +
          `${escapeHtml(name)}</span>` +
          `<strong style="font-family:inherit">${fmtPct(r.shares[name] ?? 0)}</strong></div>`
        ).join("");
        return head + body;
      },
    },
    xAxis: catAxis(cats, { boundaryGap: false }),
    yAxis: valAxis({
      min: 0, max: 100,
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series: lines.map(({ name, color }) => ({
      name, type: "line", color,
      data: rows.map((r) => r.shares[name] ?? 0),
      symbol: "circle", symbolSize: 4,
      lineStyle: { width: 2 },
      emphasis: { focus: "series" },
    })),
  });
}
