// Calendar 3 — Patch Tuesday. Contract: site/data/cve_calendar.json
// (patch_tuesday section). Bars: share of each year's dated records
// published on the month's second Tuesday (12 days/year), with a dashed
// baseline at the uniform-calendar share those days would hold if
// publication ignored the calendar. Accent ink on purpose — the release
// train is the chart's subject.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.patchtuesday;
  const rows = data.patch_tuesday.years || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }
  const baseline = data.patch_tuesday.calendar_pct;

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = rows.map((r) => (r.year === genYear ? `${r.year}*` : String(r.year)));

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 28 },
    tooltip: {
      ...baseTooltip,
      formatter: (p) => {
        const r = rows[p.dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(p.name))}</div>` +
          `<strong>${escapeHtml(tpl(ed.tooltipShare, { pct: fmtPct(r.pct) }))}</strong><br>` +
          `${escapeHtml(tpl(ed.tooltipCount, { on_pt: fmtInt(r.on_pt), n: fmtInt(r.n) }))}` +
          `<div style="margin-top:6px;padding-top:6px;border-top:1px dashed ${C.rule};color:${C.muted};">` +
          `${escapeHtml(tpl(ed.tooltipTopDay, { date: r.top_day.date, n: fmtInt(r.top_day.n) }))}</div>`
        );
      },
    },
    xAxis: catAxis(cats),
    yAxis: valAxis({
      min: 0,
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series: [{
      type: "bar",
      barWidth: "55%",
      data: rows.map((r) => r.pct),
      itemStyle: { color: C.accent, opacity: 0.85 },
      markLine: {
        silent: true,
        symbol: "none",
        lineStyle: { color: C.ink, type: [4, 4], width: 1, opacity: 0.7 },
        label: {
          color: C.muted, fontFamily: MONO, fontSize: 10,
          formatter: () => tpl(ed.baselineLabel, { pct: fmtPct(baseline) }),
          // left-anchored: the early years' bars are short, the recent
          // years' tall — an end-anchored label would sit inside them.
          position: "insideStartTop", distance: 6,
        },
        data: [{ yAxis: baseline }],
      },
    }],
  });
}
