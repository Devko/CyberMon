// Roster 2 — onboardings vs departures per month. Contract:
// site/data/cna_roster.json (roster_flux section). Diverging bars:
// organizations that joined above the axis (accent), that left below
// (muted); scope changes to existing orgs ride along as a separate muted
// bar — visible, never conflated with join/leave. Empty at launch: with no
// accreditation dates published, the churn log starts now.
import {
  C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt,
  escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.roster_flux;
  const flux = data.roster_flux || {};
  const first = flux.first_observed;

  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    noteEl.textContent = flux.events_total > 0
      ? tpl(ed.note, { events: fmtInt(flux.events_total), first_date: first })
      : ed.noteEmpty;
  }

  const months = flux.months || [];
  if (!months.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", ed.emptyChart));
    return;
  }

  // Summary stat: joined vs left across the whole record (from the data).
  const t = flux.totals || {};
  const stat = el("div", "hero-stat-row");
  stat.append(
    el("span", "hero-num accent", fmtInt(t.onboarded || 0)),
    el("span", "hero-when", tpl(ed.statOnboarded, {
      departed: fmtInt(t.departed || 0),
    }))
  );
  slots.stat.append(frag(stat));

  const SERIES = [
    { name: ed.legendOnboarded, stack: "flux", color: C.accent,
      value: (m) => m.onboarded },
    { name: ed.legendDeparted, stack: "flux", color: C.versions.v3,
      value: (m) => -m.departed },
    { name: ed.legendScope, stack: "context", color: C.sev.medium,
      value: (m) => m.scope_changed },
  ];

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 40 },
    legend: { ...baseLegend, data: SERIES.map((s) => s.name), icon: "rect", itemHeight: 8 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const m = params.length && months[params[0].dataIndex];
        if (!m) return "";
        const head =
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(m.month)}</div>`;
        const counts = [m.onboarded, m.departed, m.scope_changed];
        const body = SERIES.map(({ name, color }, i) =>
          `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
          `<span><span style="display:inline-block;width:8px;height:8px;background:${color};margin-right:6px;"></span>` +
          `${escapeHtml(name)}</span>` +
          `<strong style="font-family:inherit">${fmtInt(counts[i])}</strong></div>`
        ).join("");
        return head + body;
      },
    },
    xAxis: catAxis(months.map((m) => m.month), {
      axisLabel: { ...catAxis([]).axisLabel, rotate: months.length > 12 ? 45 : 0 },
    }),
    yAxis: valAxis({
      minInterval: 1,
      axisLabel: { ...valAxis().axisLabel, formatter: (v) => fmtInt(Math.abs(v)) },
    }),
    series: SERIES.map(({ name, stack, color, value }) => ({
      name,
      type: "bar",
      stack,
      color,
      barMaxWidth: 26,
      emphasis: { focus: "series" },
      data: months.map(value),
    })),
  });
}
