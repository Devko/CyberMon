// ATT&CK 3 — the catalog behind the matrix: active groups (intrusion sets)
// and software (malware + tools) per release. Contract:
// site/data/attack_churn.json (shared fetch, attack.js). Same real-time
// x-axis and step-line idiom as the hero — counts hold between releases.
import { C, mkChart, timeAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, escapeHtml, MONO } from "../theme.js";
import { editorial } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.catalog;
  const rows = data.versions || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 36 },
    legend: { ...baseLegend, data: [ed.legendSoftware, ed.legendGroups] },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const r = params[0] && rows[params[0].dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(`v${r.version} · ${r.released}`)}</div>` +
          `${escapeHtml(ed.legendSoftware)} <strong>${fmtInt(r.software)}</strong><br>` +
          `${escapeHtml(ed.legendGroups)} <strong>${fmtInt(r.groups)}</strong>`
        );
      },
    },
    xAxis: timeAxis(),
    yAxis: valAxis({
      name: "active entries",
      nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
    }),
    series: [
      {
        name: ed.legendSoftware, type: "line", step: "end",
        data: rows.map((r) => [r.released, r.software]),
        color: C.versions.v3,
        symbol: "circle", symbolSize: 4,
        lineStyle: { width: 2 }, z: 4,
      },
      {
        name: ed.legendGroups, type: "line", step: "end",
        data: rows.map((r) => [r.released, r.groups]),
        color: C.sev.high,
        symbol: "circle", symbolSize: 4,
        lineStyle: { width: 2 }, z: 5,
      },
    ],
  });
}
