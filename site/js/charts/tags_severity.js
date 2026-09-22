// Record Tags 3 — severity mix of tagged records against two baselines (the
// same CNAs' other records, and every record in the window), as 100%
// stacked horizontal bars. Contract: site/data/cve_tags.json (shared;
// tags.js fetches it once). Shares are computed here from the counts.
import { C, MONO, mkChart, catAxis, baseTooltip, baseLegend, baseGrid, fmtInt, fmtPct, escapeHtml } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

const TAGS = ["unsupported-when-assigned", "disputed"];
// Critical first so the accent segment starts every bar at the axis.
const BUCKETS = ["critical", "high", "medium", "low", "unscored"];

export function render(slots, data) {
  const ed = editorial.sections.tags_severity;
  const sev = data.severity || {};
  const w = data.window || {};

  const rows = [];
  for (const tag of TAGS) {
    const block = sev[tag];
    if (!block) continue;
    rows.push({ label: tpl(ed.rowLabels.tagged, { tag }), counts: block.tagged, strong: true });
    rows.push({ label: `↳ ${ed.rowLabels.same_cnas_untagged}`, counts: block.same_cnas_untagged });
  }
  if (sev.all) {
    rows.push({ label: `${ed.rowLabels.all} ${w.from ?? ""}–${w.to ?? ""}`, counts: sev.all });
  }
  const total = (c) => BUCKETS.reduce((s, k) => s + (c?.[k] ?? 0), 0);
  if (!rows.length || !total(rows[0].counts)) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }

  const narrow = slots.chart.clientWidth > 0 && slots.chart.clientWidth < 520;
  const left = narrow ? 118 : 196;
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left, right: 16, top: 40, bottom: 24 },
    legend: { ...baseLegend, data: BUCKETS.map((k) => ed.severityLabels[k]), icon: "rect", itemHeight: 8 },
    tooltip: {
      ...baseTooltip,
      trigger: "item",
      formatter: (p) => {
        const r = rows[p.dataIndex];
        const key = BUCKETS[p.seriesIndex];
        return `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(r.label)}</div>` +
          `${p.marker} ${escapeHtml(p.seriesName)} <strong>${fmtPct(p.value)}</strong><br>` +
          `<span style="color:${C.muted};">${escapeHtml(tpl(ed.tooltipRow, { n: fmtInt(r.counts[key]) }))} of ${fmtInt(total(r.counts))}</span>`;
      },
    },
    xAxis: {
      type: "value", max: 100,
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: "{value}%" },
      splitLine: { lineStyle: { color: C.rule, type: [2, 4] } },
    },
    yAxis: catAxis(rows.map((r) => r.label), {
      inverse: true,
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: {
        color: C.ink, fontFamily: MONO, fontSize: narrow ? 10 : 11,
        width: left - 12, overflow: "break", lineHeight: 13,
      },
    }),
    series: BUCKETS.map((key) => ({
      name: ed.severityLabels[key],
      type: "bar",
      stack: "sev",
      barWidth: 16,
      color: C.sev[key],
      // a panel-colored hairline keeps the neutral segments apart
      itemStyle: { opacity: key === "critical" ? 0.95 : 0.85, borderColor: C.panel, borderWidth: 1 },
      emphasis: { focus: "series" },
      data: rows.map((r) => {
        const t = total(r.counts);
        return t ? +((r.counts[key] / t) * 100).toFixed(2) : 0;
      }),
      label: key === "critical" && !narrow
        ? { show: true, position: "insideLeft", color: C.bg, fontFamily: MONO, fontSize: 10,
            formatter: (p) => (p.value >= 6 ? `${p.value.toFixed(1)}%` : "") }
        : undefined,
    })),
  });
}
