// KEV 4 — ransomware share. Contract: site/data/kev_ransomware.json
// (its own file — unlike the other three KEV sections, this one needs no
// CVE join, so kev.js fetches it separately). Bars: share of each year's
// new listings flagged "Known" for ransomware campaign use. Accent ink on
// purpose — the flag marks the catalog's costliest tail.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const rows = data.years || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = rows.map((r) => (r.year === genYear ? `${r.year}*` : String(r.year)));

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 24 },
    tooltip: {
      ...baseTooltip,
      formatter: (p) => {
        const r = rows[p.dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(p.name))}</div>` +
          `<strong>${fmtPct(r.pct_known)}</strong> flagged for ransomware use<br>` +
          `${fmtInt(r.known)} of ${fmtInt(r.total)} entries added`
        );
      },
    },
    xAxis: catAxis(cats),
    yAxis: valAxis({
      min: 0, max: 100,
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series: [{
      type: "bar",
      barWidth: "55%",
      data: rows.map((r) => r.pct_known),
      itemStyle: { color: C.accent, opacity: 0.85 },
      label: {
        show: true, position: "top",
        color: C.muted, fontFamily: MONO, fontSize: 11,
        formatter: (p) => fmtPct(p.value),
      },
    }],
  });
}
