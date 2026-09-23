// Malicious Packages 2 — each year's reports by registry, as shares.
// Contract: site/data/registry_malware.json (years[].by_ecosystem). 100%
// stacked bars, one per publication year; the registries past the fourth
// fold into Other (same fixed colours as the hero). The partial year is
// starred — a share is comparable mid-year, a count is not.
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid,
  fmtInt, fmtPct, escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import {
  FOLDED, REGISTRY_COLORS, ecoLabel, fillRef, fold, noEdition,
} from "./osv_shared.js";

const KEYS = [...FOLDED, "other"];

export function render(slots, data, refs) {
  const ed = editorial.sections.mal_share;
  const years = (data.years || []).filter((y) => y.total > 0);
  const cat = data.catalog || {};
  if (!cat.reports || !years.length) {
    noEdition(slots, ed.nodata, refs);
    return;
  }
  const npm = (data.ecosystems || []).find((e) => e.ecosystem === "npm");
  const current = years.find((y) => y.partial);
  fillRef(refs?.caption, {
    npm_share: fmtPct(npm ? (100 * npm.reports) / cat.reports : 0),
    ruby_share: current
      ? fmtPct((100 * (current.by_ecosystem.RubyGems ?? 0)) / current.total)
      : "—",
  });

  const folded = years.map((y) => fold(y.by_ecosystem));
  const present = KEYS.filter((k) => folded.some((f) => f[k] > 0));
  const labels = years.map((y) => (y.partial ? `${y.year}*` : String(y.year)));

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 48, top: slots.chart.clientWidth < 600 ? 66 : 44, bottom: 30 },
    legend: { ...baseLegend, data: present.map(ecoLabel), icon: "rect", itemHeight: 8 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params) => {
        const i = params.length ? params[0].dataIndex : -1;
        const y = years[i];
        if (!y) return "";
        const rows = present
          .filter((k) => folded[i][k] > 0)
          .map((k) => `<div><span style="display:inline-block;width:8px;height:8px;background:${REGISTRY_COLORS[k]};margin-right:6px;"></span>` +
            escapeHtml(tpl(ed.tooltip, {
              name: ecoLabel(k), n: fmtInt(folded[i][k]),
              pct: fmtPct((100 * folded[i][k]) / y.total),
            })) + `</div>`)
          .join("");
        return `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(labels[i])} · ${fmtInt(y.total)} reports</div>` + rows;
      },
    },
    xAxis: catAxis(labels),
    yAxis: valAxis({
      max: 100,
      name: ed.yAxis,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11, align: "left" },
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: "{value}%" },
    }),
    series: present.map((k) => ({
      name: ecoLabel(k),
      type: "bar",
      stack: "share",
      barMaxWidth: 56,
      color: REGISTRY_COLORS[k],
      itemStyle: { borderColor: C.panel, borderWidth: 1 },
      emphasis: { focus: "series" },
      data: folded.map((f, i) => Math.round((1000 * f[k]) / years[i].total) / 10),
    })),
  });
}
