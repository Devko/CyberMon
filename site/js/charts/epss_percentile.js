// EPSS 3 — the ranking view: day-before percentile distribution across the
// graded cohort. Contract: site/data/epss_report.json. Percentiles are the
// one scale comparable across model eras (each day's percentile ranks that
// day's whole scored corpus), so this chart pools eras deliberately where
// the distribution chart splits them. Accent ink on the bottom-half
// buckets — a confirmed-exploited CVE the model ranked behind half the
// corpus is this section's headline fact.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

const BOTTOM_HALF = new Set(["0-25", "25-50"]);

export function render(slots, data) {
  const ed = editorial.sections.percentile;
  const pct = data.percentiles || {};
  const rows = pct.buckets || [];

  // ---- stat (spread-style big fraction) --------------------------------------
  if (pct.n > 0 && pct.bottom_half) {
    const stat = el("div", "hero-stat");
    const row = el("div", "hero-stat-row");
    row.append(
      el("span", "hero-num accent",
         tpl(ed.statBig, { n: fmtInt(pct.bottom_half.n), total: fmtInt(pct.n) })),
      el("span", "hero-when", ed.statLead)
    );
    stat.append(row);
    if (Number.isFinite(pct.median_percentile)) {
      stat.append(el("div", "hero-stat-label",
                     tpl(ed.statNote, { median: fmtPct(pct.median_percentile) })));
    }
    slots.stat.append(stat);
  }

  // ---- chart ----------------------------------------------------------------
  if (!rows.length || !pct.n) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 30 },
    tooltip: {
      ...baseTooltip,
      formatter: (p) => {
        const r = rows[p.dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">day-before percentile ${escapeHtml(String(r.bucket))}</div>` +
          `<strong>${fmtPct(r.pct)}</strong> of the ranked cohort<br>` +
          `${fmtInt(r.n)} of ${fmtInt(pct.n)} graded entries`
        );
      },
    },
    xAxis: catAxis(rows.map((r) => r.bucket)),
    yAxis: valAxis({
      name: ed.yAxisLabel,
      nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series: [{
      type: "bar",
      barWidth: "55%",
      data: rows.map((r) => ({
        value: r.pct,
        itemStyle: {
          color: BOTTOM_HALF.has(r.bucket) ? C.accent : "#77715f",
          opacity: 0.88,
        },
      })),
      label: {
        show: true, position: "top",
        color: C.muted, fontFamily: MONO, fontSize: 11,
        formatter: (p) => fmtPct(p.value),
      },
    }],
  });
}
