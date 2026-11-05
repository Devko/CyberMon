// Detection Rules 1 (hero) — SigmaHQ rules added and deprecated per quarter.
// Contract: site/data/sigma_coverage.json (quarters + years; sigma.js fetches
// the file once for all four sections). Added rules stand above the axis (by
// the date written in each rule), deprecated rules hang below it (by their
// last edit). The current quarter is partial and drawn pale with an
// asterisk; quarters with no rules are empty slots, never closed up.
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid,
  fmtInt, escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";
import { fillRef, noEdition, quarterName, yearLabel } from "./sigma_shared.js";

export function render(slots, data, refs) {
  const ed = editorial.sections.sigma_churn;
  const L = ed.labels;
  const quarters = data.quarters || [];
  const cat = data.catalog || {};
  if (!quarters.length || !cat.rules) {
    noEdition(slots, ed.nodata, refs);
    return;
  }

  fillRef(refs?.caption, { rules: fmtInt(cat.rules) }, tpl);
  const partial = quarters.find((q) => q.partial);
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    const text = tpl(ed.note, {
      commit: (data.source?.commit || "").slice(0, 12),
      commit_date: data.source?.commit_date ?? "—",
      quarter: partial ? quarterName(partial.quarter) : "",
    });
    // No partial quarter (an edition on a quarter's last day): drop the
    // asterisk sentence, keep the commit line.
    noteEl.textContent = partial ? text : text.replace(/\s*\*[^.]*\.$/, "");
  }

  // ---- headline stat: the last complete year against the peak year ----------
  const years = (data.years || []).filter((y) => !y.partial);
  if (years.length) {
    const last = years[years.length - 1];
    const peak = years.reduce((a, b) => (b.added > a.added ? b : a));
    const stat = el("div", "hero-stat");
    const row = el("div", "hero-stat-row");
    row.append(el("span", "hero-num accent", fmtInt(last.added)));
    if (peak.year !== last.year) {
      row.append(el("span", "hero-when", tpl(ed.statWhen, {
        peak_n: fmtInt(peak.added), peak_year: peak.year,
      })));
    }
    stat.append(el("div", "hero-stat-label", tpl(ed.statLabel, { year: last.year })), frag(row));
    slots.stat.append(stat);
  }

  const labels = quarters.map((q) => (q.partial ? `${q.quarter}*` : q.quarter));
  const paleAdded = "rgba(222, 215, 194, 0.38)";
  const paleDep = "rgba(192, 138, 69, 0.38)";
  // Phones: one year label in two, or ~10 labels collide.
  const narrow = slots.chart.clientWidth < 600;
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 52, top: 44, bottom: 34 },
    legend: { ...baseLegend, data: [L.legendAdded, L.legendDeprecated], icon: "rect", itemHeight: 8 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params) => {
        const i = params.length ? params[0].dataIndex : -1;
        const q = quarters[i];
        if (!q) return "";
        const line = (color, name, v) =>
          `<div style="display:flex;gap:10px;justify-content:space-between;">` +
          `<span><span style="display:inline-block;width:8px;height:8px;background:${color};margin-right:6px;"></span>` +
          `${escapeHtml(name)}</span><strong style="font-family:inherit">${fmtInt(v)}</strong></div>`;
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(quarterName(q.quarter))}` +
          `${q.partial ? ` · ${escapeHtml(L.tipPartial)}` : ""}</div>` +
          line(C.versions.v3, L.legendAdded, q.added) +
          line(C.sev.high, L.legendDeprecated, q.deprecated)
        );
      },
    },
    xAxis: catAxis(labels, {
      // One label per year (the Q1 slot) keeps ~40 quarters readable.
      axisLabel: {
        color: C.muted, fontFamily: MONO, fontSize: 11, interval: 0,
        formatter: (v) => yearLabel(v, narrow),
      },
    }),
    yAxis: valAxis({
      name: L.yAxis,
      nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
      axisLabel: {
        color: C.muted, fontFamily: MONO, fontSize: 11,
        formatter: (v) => fmtInt(Math.abs(v)),
      },
    }),
    series: [
      {
        name: L.legendAdded, type: "bar", stack: "churn", barMaxWidth: 16,
        color: C.versions.v3,
        data: quarters.map((q) => ({
          value: q.added,
          itemStyle: { color: q.partial ? paleAdded : C.versions.v3 },
        })),
      },
      {
        name: L.legendDeprecated, type: "bar", stack: "churn", barMaxWidth: 16,
        color: C.sev.high,
        data: quarters.map((q) => ({
          value: q.deprecated ? -q.deprecated : 0,
          itemStyle: { color: q.partial ? paleDep : C.sev.high },
        })),
      },
    ],
  });
}
