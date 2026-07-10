// ATT&CK 2 — churn per release: techniques and sub-techniques added vs
// retired (deprecated + revoked) by each release, diffed by STIX id.
// Contract: site/data/attack_churn.json (shared fetch, attack.js).
// A category axis IS the right tool here — the unit is a release, not a
// calendar interval, so bars sit at release order (the methodology says
// so out loud). The first indexed release has no predecessor: no bar.
import { C, mkChart, catAxis, valAxis, baseText, baseTooltip, baseLegend, baseGrid, fmtInt, escapeHtml, MONO } from "../theme.js";
import { editorial } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.churn;
  const rows = (data.versions || []).filter((v) => v.churn);
  if (!rows.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  const cats = rows.map((r) => `v${r.version}`);
  const chart = mkChart(slots.chart);
  chart.setOption({
    // Extra bottom room: ~40 rotated release labels need it.
    grid: { ...baseGrid, left: 50, top: 36, bottom: 52 },
    legend: { ...baseLegend, data: [ed.legendAdded, ed.legendRetired] },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const r = params[0] && rows[params[0].dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(`v${r.version} · ${r.released}`)}</div>` +
          `${escapeHtml(ed.legendAdded)} <strong>${fmtInt(r.churn.added)}</strong><br>` +
          `${escapeHtml(ed.legendRetired)} <strong>${fmtInt(r.churn.deprecated + r.churn.revoked)}</strong> ` +
          `<span style="color:${C.muted};">(${fmtInt(r.churn.deprecated)} deprecated · ` +
          `${fmtInt(r.churn.revoked)} revoked)</span>`
        );
      },
    },
    xAxis: catAxis(cats, {
      // ~40 release labels: rotate so they never collide.
      axisLabel: { ...baseText, rotate: 45 },
    }),
    yAxis: valAxis({
      name: "techniques + sub-techniques",
      nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
    }),
    series: [
      {
        name: ed.legendAdded, type: "bar", barGap: "10%",
        data: rows.map((r) => r.churn.added),
        itemStyle: { color: C.versions.v3, opacity: 0.9 },
      },
      {
        name: ed.legendRetired, type: "bar",
        data: rows.map((r) => r.churn.deprecated + r.churn.revoked),
        itemStyle: { color: C.accent, opacity: 0.85 },
      },
    ],
  });
}
