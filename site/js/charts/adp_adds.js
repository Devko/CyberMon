// Second chart — what Vulnrichment adds. Contract: site/data/adp_coverage.json
// Of the records CISA enriched, the share carrying each machine-readable
// addition: an SSVC decision (near-universal, drawn in accent), a CVSS score,
// a CWE class (selective patch-ins). Independent shares — a record can carry
// all three — so the bars never sum to 100.
import { editorial } from "../editorial.js";
import {
  C, MONO, mkChart, catAxis, valAxis, baseGrid, baseTooltip, fmtInt, fmtPct,
  escapeHtml,
} from "../theme.js";

export function render(slots, data) {
  const ed = editorial.sections.adp_adds;
  const adds = data.adds || {};
  if (!adds.total) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(document.createTextNode(ed.nodata));
    return;
  }

  // SSVC first (the near-universal contribution); accent reserved for it.
  const bars = [
    { key: "ssvc", label: ed.labelSsvc, accent: true },
    { key: "cvss", label: ed.labelCvss, accent: false },
    { key: "cwe", label: ed.labelCwe, accent: false },
  ];

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, bottom: 46, left: 48 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const p = params[0];
        const bar = bars[p.dataIndex];
        if (!bar) return "";
        const n = adds[bar.key] ?? 0;
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(bar.label)}</div>` +
          `<strong>${fmtPct(p.value)}</strong> of CISA-ADP records<br>` +
          `<span style="color:${C.muted};">${fmtInt(n)} of ${fmtInt(adds.total)}</span>`
        );
      },
    },
    xAxis: catAxis(bars.map((b) => b.label)),
    yAxis: valAxis({
      max: 100,
      name: ed.yAxis,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: "{value}%" },
    }),
    series: [
      {
        name: "Share",
        type: "bar",
        barWidth: "52%",
        data: bars.map((b) => ({
          value: adds[`pct_${b.key}`] ?? 0,
          itemStyle: { color: b.accent ? C.accent : C.versions.v4 },
        })),
      },
    ],
  });
}
