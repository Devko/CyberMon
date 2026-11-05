// Support Windows 2 — products that separate active support from security
// support: the median time from release to the end of each phase, by release
// year. Contract: site/data/support_windows.json (phases). Medians are
// Kaplan–Meier estimates from the pipeline; provisional years draw hollow
// points, a thin or unreached year plots no point.
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid,
  fmtInt, escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";
import { toYears, yearsLabel, medianTip, noData, yearPoint } from "./eol_shared.js";

const ACTIVE_COLOR = C.versions.v3;

export function render(slots, data) {
  const ed = editorial.sections.eol_phases;
  const L = ed.labels;
  const na = editorial.ui.na;
  const ph = data.phases || {};
  const rows = ph.years || [];

  const partial = rows.find((r) => r.partial);
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    const text = tpl(ed.note, { year: partial ? partial.year : "" });
    noteEl.textContent = partial ? text : text.replace(/^\*[^.]*\.\s*/, "");
  }

  if (!ph.products || !rows.length) {
    noteEl?.remove();
    noData(slots, ed.nodata);
    return;
  }

  // ---- headline stat: pooled medians -----------------------------------------
  const stat = el("div", "hero-stat");
  const row = el("div", "hero-stat-row");
  row.append(
    el("span", "hero-num accent",
      yearsLabel(L, ph.security_median_days, ph.security_median_at_least, na)),
    el("span", "hero-when", ed.statSecurity),
    el("span", "hero-vs", editorial.ui.vs),
    el("span", "hero-num",
      yearsLabel(L, ph.active_median_days, ph.active_median_at_least, na)),
    el("span", "hero-when", ed.statActive)
  );
  stat.append(el("div", "hero-stat-label", ed.statLabel), frag(row));
  slots.stat.append(stat);

  // ---- chart --------------------------------------------------------------------
  const cats = rows.map((r) => (r.partial ? `${r.year}*` : String(r.year)));
  const chart = mkChart(slots.chart);
  chart.setOption({
    // the legend wraps to two rows on phones
    grid: { ...baseGrid, left: 44, top: slots.chart.clientWidth < 600 ? 64 : 48, bottom: 30 },
    legend: { ...baseLegend, data: [ed.legendSecurity, ed.legendActive] },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const i = params.length ? params[0].dataIndex : -1;
        const r = rows[i];
        if (!r) return "";
        const line = (name, color, days, atLeast) =>
          `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
          `<span><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${color};margin-right:6px;"></span>` +
          `${escapeHtml(name)}</span><strong style="font-family:inherit">` +
          `${escapeHtml(medianTip(L, days, atLeast, na))}</strong></div>`;
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(cats[i])}` +
          `${r.provisional ? ` · ${escapeHtml(L.provisional)}` : ""}</div>` +
          line(ed.legendSecurity, C.accent, r.security_median_days, r.security_median_at_least) +
          line(ed.legendActive, ACTIVE_COLOR, r.active_median_days, r.active_median_at_least) +
          `<div style="color:${C.muted};margin-top:4px;">` +
          `${escapeHtml(tpl(L.tipLines, { lines: fmtInt(r.lines), products: fmtInt(r.products) }))}</div>`
        );
      },
    },
    xAxis: catAxis(cats, { boundaryGap: false }),
    yAxis: valAxis({
      min: 0,
      name: ed.yAxis,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11, align: "left" },
    }),
    series: [
      {
        name: ed.legendSecurity,
        type: "line",
        color: C.accent,
        lineStyle: { width: 2.5, color: C.accent },
        z: 5,
        data: rows.map((r) =>
          yearPoint(toYears(r.security_median_days), r.provisional, C.accent)),
      },
      {
        name: ed.legendActive,
        type: "line",
        color: ACTIVE_COLOR,
        lineStyle: { width: 1.5, color: ACTIVE_COLOR },
        z: 3,
        data: rows.map((r) =>
          yearPoint(toYears(r.active_median_days), r.provisional, ACTIVE_COLOR)),
      },
    ],
  });
}
