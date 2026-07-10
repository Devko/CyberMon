// Hygiene 1 (hero) — world DNSSEC validation rate, monthly since 2013.
// Contract: site/data/dnssec_adoption.json (shared by all three sections;
// hygiene.js fetches it once). One accent line with a soft area under it:
// the twenty-years-late adoption curve. Stat: newest month vs the
// payload-authoritative decade-ago baseline (never derived client-side).
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.validation;
  const world = data.world;
  const rows = world.series || [];

  // ---- headline stat --------------------------------------------------------
  const stat = el("div", "hero-stat");
  stat.append(el("div", "hero-stat-label", ed.statLabel));
  const row = el("div", "hero-stat-row");
  const latest = world.latest || {};
  const baseline = world.baseline || {};
  if (Number.isFinite(latest.validating_pc) && Number.isFinite(baseline.validating_pc)) {
    row.append(
      el("span", "hero-num accent", fmtPct(latest.validating_pc)),
      el("span", "hero-when", tpl(ed.statLatest, { latest_month: latest.date.slice(0, 7) })),
      el("span", "hero-vs", "vs"),
      el("span", "hero-num", fmtPct(baseline.validating_pc)),
      // baseline comes from the payload: the month 120 months before the
      // newest one when APNIC's record reaches back that far, else the
      // record's first month.
      el("span", "hero-when", tpl(ed.statAgo, { ago_month: baseline.month }))
    );
  } else {
    row.append(el("span", "hero-when muted", "Not enough data yet."));
  }
  stat.append(row);
  slots.stat.append(stat);

  // ---- chart ----------------------------------------------------------------
  if (!rows.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // Label the first sampled month of each year, so the axis reads as years
  // regardless of which months the series happens to contain.
  const firstOfYear = new Set();
  const seenYears = new Set();
  for (const r of rows) {
    const year = r.month.slice(0, 4);
    if (!seenYears.has(year)) {
      seenYears.add(year);
      firstOfYear.add(r.month);
    }
  }

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 46, top: 24 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const p = params[0];
        const r = p && rows[p.dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(r.month)}</div>` +
          `<strong>${fmtPct(r.validating_pc)}</strong> of users behind validating resolvers`
        );
      },
    },
    xAxis: catAxis(rows.map((r) => r.month), {
      boundaryGap: false,
      axisLabel: {
        color: C.muted, fontFamily: MONO, fontSize: 10,
        interval: 0,
        formatter: (v) => (firstOfYear.has(v) ? v.slice(0, 4) : ""),
      },
    }),
    yAxis: valAxis({
      min: 0,
      max: 100,
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series: [{
      name: "Validating", type: "line",
      data: rows.map((r) => r.validating_pc),
      color: C.accent, symbol: "none",
      lineStyle: { width: 2 },
      areaStyle: { color: C.accent, opacity: 0.09 },
      // A quiet reference at 100%: the distance to done.
      markLine: {
        silent: true, symbol: "none",
        label: {
          color: C.faint, fontFamily: MONO, fontSize: 10,
          formatter: ed.everyoneLabel, position: "insideEndTop",
        },
        lineStyle: { color: C.faint, type: [2, 6], width: 1 },
        data: [{ yAxis: 100 }],
      },
    }],
  });
}
