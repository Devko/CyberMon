// Advisories Without a CVE 3 — GitHub's severity rating, with vs without a CVE.
// Contract: site/data/advisory_gap.json (severity[]). Two 100%-stacked
// horizontal bars (one per group), segments by rating, Critical in accent
// as everywhere on the site. "No rating" is drawn only when it holds any.
import {
  C, MONO, mkChart, catAxis, valAxis, baseGrid, baseLegend, baseTooltip,
  fmtInt, fmtPct, escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { fillRef, noEdition } from "./osv_shared.js";

const LEVEL_COLORS = {
  CRITICAL: C.sev.critical,
  HIGH: C.sev.high,
  MODERATE: C.versions.v3,
  LOW: C.sev.low,
  UNRATED: C.sev.unscored,
};

export function render(slots, data, refs) {
  const ed = editorial.sections.gap_severity;
  const cat = data.catalog || {};
  const sev = data.severity || [];
  if (!cat.advisories || !sev.length) {
    noEdition(slots, ed.nodata, refs);
    return;
  }
  const crit = sev.find((s) => s.level === "CRITICAL") || {};
  fillRef(refs?.caption, {
    crit_without: fmtPct(crit.without_cve_pct),
    crit_with: fmtPct(crit.with_cve_pct),
  });

  const levels = sev.filter((s) => s.level !== "UNRATED" || s.with_cve + s.without_cve > 0);
  // Row order bottom -> top: ECharts draws the first category lowest.
  const rows = [
    { key: "without_cve", label: ed.rowWithout },
    { key: "with_cve", label: ed.rowWith },
  ];
  slots.chart.style.height = "220px";
  // Segments too narrow for their number leave it to the tooltip.
  const minLabel = slots.chart.clientWidth < 600 ? 16 : 8;
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 112, right: 24, top: 40, bottom: 34 },
    legend: { ...baseLegend, data: levels.map((s) => ed.levels[s.level]), icon: "rect", itemHeight: 8 },
    tooltip: {
      ...baseTooltip,
      trigger: "item",
      formatter: (p) => {
        const s = levels[p.seriesIndex];
        const row = rows[p.dataIndex];
        return escapeHtml(tpl(ed.tooltip, {
          level: ed.levels[s.level],
          n: fmtInt(s[row.key]),
          pct: fmtPct(s[`${row.key}_pct`]),
        }));
      },
    },
    xAxis: valAxis({
      max: 100,
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: "{value}%" },
    }),
    yAxis: catAxis(rows.map((r) => r.label)),
    series: levels.map((s) => ({
      name: ed.levels[s.level],
      type: "bar",
      stack: "sev",
      barWidth: "56%",
      color: LEVEL_COLORS[s.level],
      itemStyle: { borderColor: C.panel, borderWidth: 1 },
      data: rows.map((r) => s[`${r.key}_pct`] ?? 0),
      label: {
        show: true,
        color: s.level === "MODERATE" ? C.bg : C.ink,
        fontFamily: MONO,
        fontSize: 11,
        // Only segments wide enough to hold their number get one.
        formatter: (p) => (p.value >= minLabel ? fmtPct(p.value) : ""),
      },
    })),
  });
}
