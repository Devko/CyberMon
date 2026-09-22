// Advisory Gap 2 — the no-CVE share per ecosystem, all publication years.
// Contract: site/data/advisory_gap.json (ecosystems[]). One horizontal bar
// per ecosystem that clears the min_n floor, sorted by share; the rest are
// named below the chart, never ranked on a handful of advisories.
import {
  C, MONO, mkChart, catAxis, valAxis, baseGrid, baseTooltip, fmtInt, fmtPct,
  escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";
import { ecoLabel, fillRef, noEdition } from "./osv_shared.js";

export function render(slots, data, refs) {
  const ed = editorial.sections.gap_ecosystems;
  const ecos = data.ecosystems || [];
  if (!ecos.length) {
    noEdition(slots, ed.nodata, refs);
    return;
  }
  fillRef(refs?.methodText, { min_n: fmtInt(data.min_n) });

  const ranked = ecos.filter((e) => e.without_cve_pct !== null)
    .sort((a, b) => a.without_cve_pct - b.without_cve_pct
      || b.total - a.total); // ascending: ECharts draws the first at the bottom
  const small = ecos.filter((e) => e.without_cve_pct === null);

  // Taller canvas for many rows: 30 px a bar keeps labels apart.
  slots.chart.style.height = `${Math.max(260, ranked.length * 30 + 60)}px`;
  // Phone width: the bar label keeps only the share (the counts stay in
  // the tooltip) so the plot is not squeezed to a sliver.
  const narrow = slots.chart.clientWidth < 600;
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: narrow ? 116 : 128, right: narrow ? 48 : 150, top: 8, bottom: 40 },
    tooltip: {
      ...baseTooltip,
      trigger: "item",
      formatter: (p) => {
        const e = ranked[p.dataIndex];
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(ecoLabel(e.ecosystem))}</div>` +
          escapeHtml(tpl(ed.tooltip, {
            without: fmtInt(e.without_cve), total: fmtInt(e.total),
            young: fmtInt(e.without_cve_young), days: data.young_days,
          }))
        );
      },
    },
    xAxis: valAxis({
      name: ed.xAxis,
      nameLocation: "middle",
      nameGap: 24,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
      splitNumber: narrow ? 3 : 5,
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: "{value}%" },
    }),
    yAxis: catAxis(ranked.map((e) => ecoLabel(e.ecosystem))),
    series: [{
      type: "bar",
      barWidth: "58%",
      // Accent marks the highest share (the headline's ecosystem).
      data: ranked.map((e, i) => ({
        value: e.without_cve_pct,
        itemStyle: { color: i === ranked.length - 1 ? C.accent : C.versions.v2 },
      })),
      label: {
        show: true,
        position: "right",
        color: C.muted,
        fontFamily: MONO,
        fontSize: 11,
        formatter: (p) => {
          const e = ranked[p.dataIndex];
          if (narrow) return fmtPct(e.without_cve_pct);
          return tpl(ed.barLabel, {
            pct: fmtPct(e.without_cve_pct),
            without: fmtInt(e.without_cve),
            total: fmtInt(e.total),
          });
        },
      },
    }],
  });

  if (small.length) {
    slots.extra.append(el("p", "table-context", tpl(ed.smallNote, {
      min_n: fmtInt(data.min_n),
      list: small.map((e) => `${ecoLabel(e.ecosystem)} (${fmtInt(e.total)})`).join(", "),
    })));
  }
}
