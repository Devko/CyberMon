// Calendar 2 — the weekly beat. Contract: site/data/cve_calendar.json
// (weekday section). Grouped bars over Mon..Sun: each charted year's share
// of dated records per weekday, comparing the payload-named latest complete
// year against its payload-named baseline year. Newsprint-neutral baseline,
// warm ink for the current shape.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, fmtPct, escapeHtml } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.weekbeat;
  const rows = data.weekday.years || [];
  const comp = data.weekday.comparison;
  if (!rows.length || !comp) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  const byYear = new Map(rows.map((r) => [r.year, r]));
  // baseline first so the older shape sits behind/left of the newer one;
  // when the record is thin both names can point at the same year — chart
  // it once rather than twice.
  const years = comp.baseline_year === comp.latest_year
    ? [comp.latest_year]
    : [comp.baseline_year, comp.latest_year];
  const SERIES_COLORS = years.length === 1 ? ["#c08a45"] : ["#847e6d", "#c08a45"];

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 44 },
    legend: {
      ...baseLegend,
      data: years.map((y) => tpl(ed.seriesYearLabel, { year: y })),
    },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const day = params.length ? params[0].axisValueLabel ?? params[0].name : "";
        const head = `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(day))}</div>`;
        const body = params.map((p) => {
          const r = byYear.get(years[p.seriesIndex]);
          const count = r ? r.counts[p.dataIndex] : null;
          return (
            `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
            `<span>${p.marker} ${escapeHtml(String(p.seriesName))}</span>` +
            `<strong style="font-family:inherit">${fmtPct(p.value)}` +
            `${count === null ? "" : ` · ${fmtInt(count)}`}</strong></div>`
          );
        }).join("");
        const foot = years.map((y) => {
          const r = byYear.get(y);
          return r
            ? `<div style="color:${C.muted};">${escapeHtml(tpl(ed.tooltipN, { n: fmtInt(r.n), year: y }))}</div>`
            : "";
        }).join("");
        return head + body +
          `<div style="margin-top:6px;padding-top:6px;border-top:1px dashed ${C.rule};">${foot}</div>`;
      },
    },
    xAxis: catAxis(ed.weekdayLabels),
    yAxis: valAxis({
      min: 0,
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series: years.map((year, i) => ({
      name: tpl(ed.seriesYearLabel, { year }),
      type: "bar",
      barGap: "10%",
      barWidth: years.length === 1 ? "45%" : "32%",
      data: byYear.get(year).pct,
      itemStyle: { color: SERIES_COLORS[i], opacity: 0.85 },
    })),
  });
}
