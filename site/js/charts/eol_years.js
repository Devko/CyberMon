// Support Windows 1 (hero) — the median support window of release lines by
// release year, for every tracked product and for the fixed panel (products
// with lines in both comparison periods). Contract:
// site/data/support_windows.json (years, periods, panel). Medians are
// Kaplan–Meier estimates computed by the pipeline; a year whose median was
// not reached plots no point and its tooltip gives the lower bound.
// Provisional years (still running, or too many lines with no announced end)
// draw hollow points.
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid,
  fmtInt, escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";
import { toYears, yearsLabel, medianTip, noData, yearPoint } from "./eol_shared.js";

const ALL_COLOR = C.versions.v2;

export function render(slots, data) {
  const ed = editorial.sections.eol_years;
  const L = ed.labels;
  const na = editorial.ui.na;
  const rows = data.years || [];
  const panel = data.panel || {};
  const pan = data.periods?.panel || {};

  // ---- panel note: partial year, provisional rule ----------------------------
  const partial = rows.find((r) => r.partial);
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    const text = tpl(ed.note, {
      year: partial ? partial.year : "",
      threshold: fmtInt(data.provisional_open_pct),
    });
    noteEl.textContent = partial ? text : text.replace(/^\*[^.]*\.\s*/, "");
  }

  // ---- headline stat: the panel's two pooled periods --------------------------
  const stat = el("div", "hero-stat");
  const row = el("div", "hero-stat-row");
  row.append(
    el("span", "hero-num accent",
      yearsLabel(L, pan.late?.median_days, pan.late?.median_at_least, na)),
    el("span", "hero-when", tpl(ed.statLate, { from: pan.late?.from ?? na, to: pan.late?.to ?? na })),
    el("span", "hero-vs", editorial.ui.vs),
    el("span", "hero-num",
      yearsLabel(L, pan.early?.median_days, pan.early?.median_at_least, na)),
    el("span", "hero-when", tpl(ed.statEarly, { from: pan.early?.from ?? na, to: pan.early?.to ?? na }))
  );
  stat.append(
    el("div", "hero-stat-label", tpl(ed.statLabel, { panel: fmtInt(panel.products) })),
    frag(row)
  );
  slots.stat.append(stat);

  if (!rows.length) {
    noData(slots, ed.nodata);
    return;
  }

  // ---- chart --------------------------------------------------------------------
  const cats = rows.map((r) => (r.partial ? `${r.year}*` : String(r.year)));
  const idx = (y) => rows.findIndex((r) => r.year === y);
  const band = (span, label) => {
    const a = idx(span?.[0]);
    const b = idx(span?.[1]);
    return a >= 0 && b >= 0 ? [{ xAxis: cats[a], name: label }, { xAxis: cats[b] }] : null;
  };
  const bands = [band(panel.early, L.periodEarly), band(panel.late, L.periodLate)].filter(Boolean);

  const chart = mkChart(slots.chart);
  chart.setOption({
    // the legend wraps to two rows on phones
    grid: { ...baseGrid, left: 44, top: slots.chart.clientWidth < 600 ? 64 : 48, bottom: 30 },
    legend: { ...baseLegend, data: [ed.legendPanel, ed.legendAll] },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const i = params.length ? params[0].dataIndex : -1;
        const r = rows[i];
        if (!r) return "";
        const block = (name, color, days, atLeast, lines, products) =>
          `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
          `<span><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${color};margin-right:6px;"></span>` +
          `${escapeHtml(name)}</span><strong style="font-family:inherit">` +
          `${escapeHtml(medianTip(L, days, atLeast, na))}</strong></div>` +
          `<div style="color:${C.muted};text-align:right;">` +
          `${escapeHtml(tpl(L.tipLines, { lines: fmtInt(lines), products: fmtInt(products) }))}</div>`;
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(cats[i])}` +
          `${r.provisional ? ` · ${escapeHtml(L.provisional)}` : ""}</div>` +
          block(ed.legendPanel, C.accent, r.panel_median_days, r.panel_median_at_least,
            r.panel_lines, r.panel_products) +
          block(ed.legendAll, ALL_COLOR, r.median_days, r.median_at_least, r.lines, r.products) +
          `<div style="color:${C.muted};margin-top:4px;">` +
          `${escapeHtml(tpl(L.tipOpen, { n: fmtInt(r.open) }))}<br>` +
          `${escapeHtml(tpl(L.tipUndated, { n: fmtInt(r.ended_undated) }))}</div>`
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
        name: ed.legendPanel,
        type: "line",
        color: C.accent,
        lineStyle: { width: 2.5, color: C.accent },
        connectNulls: false,
        z: 5,
        data: rows.map((r) =>
          yearPoint(toYears(r.panel_median_days), r.provisional, C.accent)),
        markArea: bands.length ? {
          silent: true,
          itemStyle: { color: "rgba(233, 228, 216, 0.05)" },
          label: { color: C.faint, fontFamily: MONO, fontSize: 10, position: "insideBottom" },
          data: bands,
        } : undefined,
      },
      {
        name: ed.legendAll,
        type: "line",
        color: ALL_COLOR,
        lineStyle: { width: 1.5, color: ALL_COLOR },
        connectNulls: false,
        z: 3,
        data: rows.map((r) => yearPoint(toYears(r.median_days), r.provisional, ALL_COLOR)),
      },
    ],
  });
}
