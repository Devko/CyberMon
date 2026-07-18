// EPSS Volatility 2 — material churn per week. Contract:
// site/data/epss_volatility.json (churn section). Grouped bars: how many
// CVEs crossed each material probability threshold (0.1% / 1% / 5%) in a
// week — a percentile reshuffle underneath a static probability is NOT a
// decision change, a threshold crossing is. The current ISO week is starred
// like the partial week/year on the sibling modules. Empty log -> one honest
// nodata card, never a fake bar.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, escapeHtml } from "../theme.js";
import { editorial } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.epssvol_churn;
  const weeks = data.churn.weeks || [];

  if (!weeks.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", ed.emptyChart));
    return;
  }

  // ISO week label ("2026-W29") of the generation date, so the still-open
  // week is starred like the partial year/month on the sibling modules.
  const gen = new Date(data.generated_at);
  const d = new Date(Date.UTC(gen.getUTCFullYear(), gen.getUTCMonth(), gen.getUTCDate()));
  d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7)); // ISO: Thursday decides the year
  const isoYear = d.getUTCFullYear();
  const weekNo = Math.ceil(((d - Date.UTC(isoYear, 0, 1)) / 86400000 + 1) / 7);
  const genWeek = `${isoYear}-W${String(weekNo).padStart(2, "0")}`;

  // Three thresholds, faint -> accent as the crossing gets more material.
  const SERIES = [
    { name: ed.legendLo, color: C.versions.v2, value: (w) => w.crossed_lo },
    { name: ed.legendMid, color: C.sev.high, value: (w) => w.crossed_mid },
    { name: ed.legendHi, color: C.accent, value: (w) => w.crossed_hi },
  ];

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 52, top: 40 },
    legend: { ...baseLegend, data: SERIES.map((s) => s.name), icon: "rect", itemHeight: 8 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const w = params.length && weeks[params[0].dataIndex];
        if (!w) return "";
        const head =
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(w.week)} · ${fmtInt(w.days)} night${w.days === 1 ? "" : "s"}</div>`;
        const body = SERIES.map(({ name, color, value }) =>
          `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
          `<span><span style="display:inline-block;width:8px;height:8px;background:${color};margin-right:6px;"></span>` +
          `${escapeHtml(name)}</span>` +
          `<strong style="font-family:inherit">${fmtInt(value(w))}</strong></div>`
        ).join("");
        return head + body;
      },
    },
    xAxis: catAxis(weeks.map((w) => (w.week === genWeek ? `${w.week}*` : w.week)), {
      axisLabel: { ...catAxis([]).axisLabel, rotate: weeks.length > 16 ? 45 : 0 },
    }),
    yAxis: valAxis({
      name: ed.yAxisLabel,
      nameTextStyle: { color: C.faint, fontSize: 10 },
    }),
    series: SERIES.map(({ name, color, value }) => ({
      name,
      type: "bar",
      color,
      barMaxWidth: 22,
      emphasis: { focus: "series" },
      data: weeks.map(value),
    })),
  });
}
