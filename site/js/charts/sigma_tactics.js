// Detection Rules 4 — Sigma coverage by ATT&CK tactic today. Contract:
// site/data/sigma_coverage.json (tactics, attack). One horizontal bar per
// tactic in ATT&CK's own matrix order (first tactic on top): the share of its
// techniques tagged by at least one active rule, with "covered/total" at the
// bar end. Bars share one 0–100% scale.
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, fmtPct,
  escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { fillRef, noEdition } from "./sigma_shared.js";

export function render(slots, data, refs) {
  const ed = editorial.sections.sigma_tactics;
  const L = ed.labels;
  const tactics = data.tactics || [];
  if (!tactics.length) {
    noEdition(slots, ed.nodata, refs);
    return;
  }
  fillRef(refs?.caption, { version: data.attack?.version }, tpl);

  // ECharts plots the first category at the bottom; reverse so ATT&CK's
  // first tactic (reconnaissance) sits on top, as in the matrix.
  const rows = tactics.slice().reverse();
  // Phones only: a narrower label column and three ticks.
  const narrow = slots.chart.clientWidth < 420;
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: narrow ? 132 : 150, right: 52, top: 16, bottom: 40 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params) => {
        const r = params.length && rows[params[0].dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(r.name)}</div>` +
          `<strong>${fmtPct(r.pct)}</strong> ` +
          `<span style="color:${C.muted};">${escapeHtml(tpl(L.tipCovered, {
            covered: fmtInt(r.covered), techniques: fmtInt(r.techniques),
          }))}</span>`
        );
      },
    },
    xAxis: valAxis({
      min: 0, max: 100,
      splitNumber: narrow ? 2 : 5,
      name: L.xAxis,
      nameLocation: "middle",
      nameGap: 26,
      nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: "{value}%" },
    }),
    yAxis: catAxis(rows.map((r) => r.name), {
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: narrow ? 10 : 11, width: narrow ? 124 : 140, overflow: "truncate" },
    }),
    series: [{
      type: "bar",
      name: "_coverage",
      barMaxWidth: 14,
      itemStyle: { color: C.versions.v3 },
      data: rows.map((r) => r.pct),
      label: {
        show: true,
        position: "right",
        color: C.muted,
        fontFamily: MONO,
        fontSize: 11,
        formatter: (p) => {
          const r = rows[p.dataIndex];
          return r ? `${fmtInt(r.covered)}/${fmtInt(r.techniques)}` : "";
        },
      },
    }],
  });
}
