// Guards 3 — ransomware overlap. Contract: site/data/kev_guards.json
// (shared by all three guards sections; guards.js fetches it once). Two
// bars: the share of entries flagged "Known" for ransomware campaign
// use, security products vs the rest of the catalog. Accent ink on the
// security bar — the overrepresentation is the story.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { editorial } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.overlap;
  const LABELS = [ed.barSecurity, ed.barOther];
  const r = data.ransomware || {};
  const blocks = [r.security, r.other];
  if (blocks.some((b) => !b || !b.total)) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 24 },
    tooltip: {
      ...baseTooltip,
      formatter: (p) => {
        const b = blocks[p.dataIndex];
        if (!b) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(p.name))}</div>` +
          `<strong>${fmtPct(b.pct_known)}</strong> flagged for ransomware use<br>` +
          `${fmtInt(b.known)} of ${fmtInt(b.total)} catalog entries`
        );
      },
    },
    xAxis: catAxis(LABELS),
    yAxis: valAxis({
      min: 0, max: 100,
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series: [{
      type: "bar",
      barWidth: "40%",
      data: blocks.map((b, i) => ({
        value: b.pct_known,
        itemStyle: { color: i === 0 ? C.accent : C.faint, opacity: 0.85 },
      })),
      label: {
        show: true, position: "top",
        color: C.muted, fontFamily: MONO, fontSize: 12,
        formatter: (p) => fmtPct(p.value),
      },
    }],
  });
}
