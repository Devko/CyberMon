// Changelog 2 — the ransomware flag arrives late. Contract:
// site/data/kev_changelog.json (shared; changelog.js fetches it once).
// Bars: Unknown->Known flips observed per month; line: the cumulative
// count. The stat renders honestly when thin: below min_n the pipeline
// ships a null median and the note says so instead of inventing one.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.flagflip;
  const flips = data.flips || {};
  const lag = flips.lag || {};

  // ---- stat (hygiene_spread statBig pattern) -------------------------------
  const stat = el("div", "hero-stat");
  const row = el("div", "hero-stat-row");
  row.append(
    el("span", "hero-num accent", tpl(ed.statBig, { n: fmtInt(flips.total ?? 0) })),
    el("span", "hero-when", ed.statLead)
  );
  stat.append(row);
  stat.append(el("div", "hero-stat-label",
    lag.median_days !== null && lag.median_days !== undefined
      ? tpl(ed.statNote, { median: fmtInt(lag.median_days) })
      : ed.statNoteThin));
  slots.stat.append(stat);

  // ---- chart ----------------------------------------------------------------
  const rows = flips.by_month || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  const genMonth = data.generated_at.slice(0, 7);
  const cats = rows.map((r) => (r.month === genMonth ? `${r.month}*` : r.month));

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, right: 50, top: 40, bottom: 48 },
    legend: { ...baseLegend, data: [ed.legendMonthly, ed.legendCumulative] },
    tooltip: {
      ...baseTooltip,
      formatter: (p) => {
        const r = rows[p.dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(p.name))}</div>` +
          `${escapeHtml(ed.legendMonthly)} <strong>${fmtInt(r.flips)}</strong><br>` +
          `${escapeHtml(ed.legendCumulative)} <strong>${fmtInt(r.cumulative)}</strong>`
        );
      },
    },
    xAxis: catAxis(cats, {
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 10, rotate: 45 },
    }),
    yAxis: [
      valAxis(),
      valAxis({ splitLine: { show: false } }),
    ],
    series: [
      {
        name: ed.legendMonthly,
        type: "bar",
        yAxisIndex: 0,
        data: rows.map((r) => r.flips),
        itemStyle: { color: "#77715f", opacity: 0.85 },
      },
      {
        name: ed.legendCumulative,
        type: "line",
        yAxisIndex: 1,
        data: rows.map((r) => r.cumulative),
        symbol: "none",
        lineStyle: { color: C.accent, width: 2 },
        itemStyle: { color: C.accent },
      },
    ],
  });
}
