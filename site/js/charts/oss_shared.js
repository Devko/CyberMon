// Open-Source Maintainers 2 — how many of a registry's 250 packages the
// accounts with the most publish rights can publish between them. Contract:
// site/data/oss_maintainers.json (ecosystems[].shared). Grouped horizontal
// bars: one group per registry, one bar per k (1, 5, 10, 25 accounts), the
// value the share of the registry's measured packages those k accounts reach
// (a package reachable by several counts once). Accounts are ranked within
// a registry only; no account is named anywhere.
import {
  C, MONO, mkChart, catAxis, valAxis, baseGrid, baseLegend, baseTooltip,
  fmtInt, fmtPct, escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import {
  fillRef, fitLegend, noEdition, regLabel, tally, universeVars,
} from "./oss_common.js";

// Colour follows k, never the rank of the bar: the single busiest account
// in accent, wider groups in progressively darker neutrals.
const K_COLORS = { 1: C.accent, 5: "#ded7c2", 10: "#a89f8a", 25: "#6f6958" };

export function render(slots, data, refs) {
  const ed = editorial.sections.oss_shared;
  const L = ed.labels;
  const ecos = data.ecosystems || [];
  if (!ecos.length) {
    noEdition(slots, ed.nodata, refs);
    return;
  }
  fillRef(refs?.methodText, universeVars(data));

  const ks = (ecos[0].shared?.top || []).map((t) => t.k);
  // ECharts draws the first category at the bottom (reverse the registries
  // so the first is on top) and, in a horizontal group, the first series on
  // top: kept in k order, each group reads 1 account first, like the legend.
  const rows = ecos.slice().reverse();
  const order = ks;
  const point = (e, k) => (e.shared?.top || []).find((t) => t.k === k) || {};

  // Four bars per registry: ~22 px each plus the gap between registries.
  const top = fitLegend(slots.chart, ks.map((k) => L.series[k]), rows.length * 104);
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 84, right: 52, top, bottom: 40 },
    legend: {
      ...baseLegend,
      data: ks.map((k) => L.series[k]),
      itemHeight: 8,
    },
    tooltip: {
      ...baseTooltip,
      trigger: "item",
      formatter: (p) => {
        const e = rows[p.dataIndex];
        const k = order[p.seriesIndex];
        const t = point(e, k);
        return escapeHtml(tpl(L.tip, {
          registry: regLabel(e.id),
          k: fmtInt(k),
          n: fmtInt(t.n),
          measured: fmtInt(e.measured),
          pct: fmtPct(t.pct),
        }));
      },
    },
    xAxis: valAxis({
      min: 0,
      max: 100,
      name: ed.xAxis,
      nameLocation: "middle",
      nameGap: 26,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: "{value}%" },
    }),
    yAxis: catAxis(rows.map((e) => regLabel(e.id)), {
      axisLabel: { ...catAxis([]).axisLabel, fontSize: 12 },
    }),
    series: order.map((k) => ({
      name: L.series[k],
      type: "bar",
      barGap: "18%",
      barCategoryGap: "28%",
      color: K_COLORS[k] ?? C.muted,
      data: rows.map((e) => point(e, k).pct ?? null),
      label: {
        show: true,
        position: "right",
        color: C.muted,
        fontFamily: MONO,
        fontSize: 10,
        formatter: (p) => (p.value === null ? "" : fmtPct(p.value)),
      },
    })),
  });

  slots.extra.append(tally(ed.distinctLabel, ecos.map((e) => tpl(ed.distinctTemplate, {
    name: regLabel(e.id),
    n: fmtInt(e.shared?.distinct_accounts),
  }))));
}
