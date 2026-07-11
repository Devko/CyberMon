// Rescores 1 (hero) — edits per week. Contract: site/data/rescore_log.json
// (weeks section; rescores.js fetches the file once for all three sections).
// Diverging bars: scores raised above the axis (accent), lowered below;
// first_score / version_shift / score_removed ride along as a separate
// muted stack — visible, never conflated with an up/down reading (a
// version shift has no direction by design; see the methodology).
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, escapeHtml } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.edits;
  const first = data.catalog.first_observed;

  // The static note carries a {first_date} placeholder — fill it from the
  // log's actual start (decay.js pattern); before any event exists, the
  // launch-night variant renders instead. Thin is a fact, not a bug.
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    noteEl.textContent = first
      ? tpl(ed.note, { first_date: first })
      : ed.noteEmpty;
  }

  // ---- headline stat: how much record exists (from data, never faked) ----
  if (data.catalog.events_total > 0) {
    const stat = el("div", "hero-stat");
    const row = el("div", "hero-stat-row");
    row.append(
      el("span", "hero-num accent", fmtInt(data.catalog.events_total)),
      el("span", "hero-when", tpl(ed.statSince, { first_date: first }))
    );
    stat.append(el("div", "hero-stat-label", ed.statLabel), frag(row));
    slots.stat.append(stat);
  }

  const weeks = data.weeks || [];
  if (!weeks.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", ed.emptyChart));
    return;
  }

  // Rescores diverge around zero in one stack; the direction-free change
  // types stack separately in muted inks so they can never read as up/down.
  const SERIES = [
    { name: ed.legendUp, stack: "rescore", color: C.accent,
      value: (w) => w.rescore_up },
    { name: ed.legendDown, stack: "rescore", color: C.versions.v3,
      value: (w) => -w.rescore_down },
    { name: ed.legendFirst, stack: "context", color: C.sev.medium,
      value: (w) => w.first_score },
    { name: ed.legendShift, stack: "context", color: C.sev.low,
      value: (w) => w.version_shift },
    { name: ed.legendRemoved, stack: "context", color: C.sev.unscored,
      value: (w) => w.score_removed },
  ];

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 48 },
    legend: { ...baseLegend, data: SERIES.map((s) => s.name), icon: "rect", itemHeight: 8 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const w = params.length && weeks[params[0].dataIndex];
        if (!w) return "";
        const head =
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(w.week)}</div>`;
        // counts, not signed plot values — "lowered" reads as a count
        const counts = [w.rescore_up, w.rescore_down, w.first_score,
                        w.version_shift, w.score_removed];
        const body = SERIES.map(({ name, color }, i) =>
          `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
          `<span><span style="display:inline-block;width:8px;height:8px;background:${color};margin-right:6px;"></span>` +
          `${escapeHtml(name)}</span>` +
          `<strong style="font-family:inherit">${fmtInt(counts[i])}</strong></div>`
        ).join("");
        return head + body;
      },
    },
    xAxis: catAxis(weeks.map((w) => w.week), {
      axisLabel: { ...catAxis([]).axisLabel, rotate: weeks.length > 16 ? 45 : 0 },
    }),
    yAxis: valAxis({
      axisLabel: { ...valAxis().axisLabel, formatter: (v) => fmtInt(Math.abs(v)) },
    }),
    series: SERIES.map(({ name, stack, color, value }) => ({
      name,
      type: "bar",
      stack,
      color,
      barMaxWidth: 26,
      emphasis: { focus: "series" },
      data: weeks.map(value),
    })),
  });
}
