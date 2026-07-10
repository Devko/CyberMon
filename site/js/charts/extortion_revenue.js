// Extortion 1 (hero) — confirmed ransom revenue per quarter. Contract:
// site/data/extortion_ledger.json (shared by all three sections;
// extortion.js fetches it once). Bars: USD at historical day-of-transfer
// rates, summed by the UTC quarter of the on-chain timestamp. The hero
// stat carries the floor caveat: this is a lower bound, never the market.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";
import { fmtUSD, fmtUSDCompact, fmtQuarter } from "./extortion_fmt.js";

export function render(slots, data) {
  const ed = editorial.sections.revenue;

  // ---- headline stat: the all-time confirmed floor ---------------------------
  const h = data.headline || {};
  const catalog = data.catalog || {};
  const stat = el("div", "hero-stat");
  stat.append(el("div", "hero-stat-label", ed.statLabel));
  const row = el("div", "hero-stat-row");
  row.append(
    el("span", "hero-num accent", fmtUSDCompact(h.total_usd ?? 0)),
    el("span", "hero-when", tpl(ed.statNote, {
      payments: fmtInt(catalog.payments ?? 0),
      addresses: fmtInt(catalog.addresses ?? 0),
    }))
  );
  stat.append(row);
  slots.stat.append(stat);

  // ---- chart ------------------------------------------------------------------
  const rows = data.revenue_by_quarter || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = rows.map((r) => fmtQuarter(r, genYear));

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 58, top: 24 },
    tooltip: {
      ...baseTooltip,
      formatter: (p) => {
        const r = rows[p.dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(p.name))}</div>` +
          `<strong>${fmtUSD(r.usd)}</strong> confirmed ransom revenue<br>` +
          `dollars at day-of-transfer rates · lower bound`
        );
      },
    },
    xAxis: catAxis(cats),
    yAxis: valAxis({
      axisLabel: { ...valAxis().axisLabel, formatter: (v) => fmtUSDCompact(v) },
    }),
    series: [{
      type: "bar",
      barWidth: "62%",
      data: rows.map((r) => r.usd),
      itemStyle: { color: C.accent, opacity: 0.85 },
    }],
  });
}
