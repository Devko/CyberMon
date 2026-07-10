// Guards 1 (hero) — the guard share. Contract: site/data/kev_guards.json
// (shared by all three guards sections; guards.js fetches it once). Bars:
// share of each year's new KEV listings classified as security products.
// Accent ink on purpose — the bar measures the products sold as the
// defense. The headline stat is the whole-catalog share, with the
// classifier revision riding along so the number is auditable.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.guards;

  // ---- headline stat: whole-catalog guard share -----------------------------
  const cat = data.catalog || {};
  const stat = el("div", "hero-stat");
  stat.append(el("div", "hero-stat-label", ed.statLabel));
  const row = el("div", "hero-stat-row");
  if (Number.isFinite(cat.pct_security)) {
    row.append(
      el("span", "hero-num accent", fmtPct(cat.pct_security)),
      el("span", "hero-when", tpl(ed.statNote, {
        security: fmtInt(cat.security),
        total: fmtInt(cat.total),
        version: cat.classifier_version,
        rules: fmtInt(cat.classifier_rules),
      }))
    );
  } else {
    row.append(el("span", "hero-when muted", "Not enough data yet."));
  }
  stat.append(row);
  slots.stat.append(stat);

  // ---- chart ----------------------------------------------------------------
  const rows = data.years || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = rows.map((r) => (r.year === genYear ? `${r.year}*` : String(r.year)));

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 24 },
    tooltip: {
      ...baseTooltip,
      formatter: (p) => {
        const r = rows[p.dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(p.name))}</div>` +
          `<strong>${fmtPct(r.pct_security)}</strong> security products<br>` +
          `${fmtInt(r.security)} of ${fmtInt(r.total)} entries added`
        );
      },
    },
    xAxis: catAxis(cats),
    yAxis: valAxis({
      // no fixed max: the share lives in the low tens, and a 0–100 axis
      // would flatten the real year-to-year movement
      min: 0,
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series: [{
      type: "bar",
      barWidth: "55%",
      data: rows.map((r) => r.pct_security),
      itemStyle: { color: C.accent, opacity: 0.85 },
      label: {
        show: true, position: "top",
        color: C.muted, fontFamily: MONO, fontSize: 11,
        formatter: (p) => fmtPct(p.value),
      },
    }],
  });
}
