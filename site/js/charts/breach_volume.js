// Breach 2 — volume. Contract: site/data/breach_ledger.json (shared;
// breaches.js fetches it once). Bars: breaches catalogued per year (left,
// linear counts). Line: accounts exposed per year (right, log axis — one
// mega-dump outweighs an ordinary year). The bars carry the pace
// projection as a hollow ghost extension (concentration_entrants.js
// idiom); the accounts line is never projected.
import { C, mkChart, catAxis, baseTooltip, baseLegend, baseGrid, tooltipFootnote, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

// Compact account counts for the log axis: 2B, 40M, 300k.
const fmtCompact = (v) =>
  v >= 1e9 ? `${v / 1e9}B` : v >= 1e6 ? `${v / 1e6}M` : v >= 1e3 ? `${v / 1e3}k` : String(v);

export function render(slots, data) {
  const ed = editorial.sections.exposure;
  const edp = editorial.projection;
  const rows = data.volume_by_year || [];

  // ---- cohort audit trail (panel-note template, breach_lag.js pattern) ------
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    const cat = data.catalog || {};
    const excluded = cat.excluded || {};
    if (Number.isFinite(cat.total) && Number.isFinite(cat.cohort)) {
      noteEl.textContent = tpl(ed.catalogNote, {
        cohort: fmtInt(cat.cohort),
        total: fmtInt(cat.total),
        fabricated: fmtInt(excluded.fabricated ?? 0),
        spam_list: fmtInt(excluded.spam_list ?? 0),
        malware: fmtInt(excluded.malware ?? 0),
        stealer_log: fmtInt(excluded.stealer_log ?? 0),
      });
    } else {
      noteEl.remove(); // never show a template with holes in it
    }
  }

  if (!rows.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = rows.map((r) => (r.year === genYear ? `${r.year}*` : String(r.year)));

  // Optional pace projection of the breach flow: hollow ghost stacked on
  // the current-year bar, from the actual top to the projected height.
  const proj = data.projection;
  const projIdx = proj ? rows.findIndex((r) => r.year === proj.year) : -1;
  const ghost = projIdx >= 0 ? proj.breaches - rows[projIdx].breaches : 0;
  const hasProj = projIdx >= 0 && ghost > 0;

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, right: 54, top: 44 },
    legend: { ...baseLegend, data: [ed.legendBreaches, ed.legendRecords] },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const r = params.length && rows[params[0].dataIndex];
        if (!r) return "";
        let html =
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(params[0].axisValueLabel ?? params[0].name))}</div>` +
          `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
          `<span>${escapeHtml(ed.legendBreaches)}</span><strong style="font-family:inherit">${fmtInt(r.breaches)}</strong></div>` +
          `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
          `<span>${escapeHtml(ed.legendRecords)}</span><strong style="font-family:inherit">${fmtInt(r.records)}</strong></div>`;
        if (hasProj && params.some((p) => p.dataIndex === projIdx)) {
          html += tooltipFootnote([
            tpl(edp.tooltipProjected, { name: ed.legendBreaches, n: fmtInt(proj.breaches) }),
            tpl(edp.tooltipElapsed, { pct: fmtPct(proj.elapsed * 100) }),
          ]);
        }
        return html;
      },
    },
    xAxis: catAxis(cats),
    yAxis: [
      { // breaches per year: plain counts
        type: "value",
        min: 0,
        minInterval: 1, // counts — never fractional gridlines
        axisLine: { show: false },
        axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11 },
        splitLine: { lineStyle: { color: C.rule, type: [2, 4] } },
      },
      { // accounts exposed: log scale, its own axis
        type: "log",
        logBase: 10,
        axisLine: { show: false },
        axisLabel: {
          color: C.faint, fontFamily: MONO, fontSize: 10,
          formatter: fmtCompact,
        },
        splitLine: { show: false },
      },
    ],
    series: [
      {
        name: ed.legendBreaches, type: "bar", stack: "breaches",
        yAxisIndex: 0,
        data: rows.map((r) => r.breaches),
        color: "#847e6d", itemStyle: { opacity: 0.8 },
        barMaxWidth: 18,
      },
      // "_" prefix keeps the ghost out of legend/tooltip series lists; the
      // formatter above appends the projection rows itself.
      ...(hasProj
        ? [{
            name: "_projected breaches", type: "bar", stack: "breaches",
            yAxisIndex: 0,
            data: rows.map((r, i) => (i === projIdx ? ghost : null)),
            barMaxWidth: 18,
            itemStyle: {
              color: "transparent",
              borderColor: "#847e6d",
              borderWidth: 1.5,
              borderType: "dashed",
              opacity: 0.9,
            },
            z: 4,
            silent: true,
          }]
        : []),
      {
        name: ed.legendRecords, type: "line",
        yAxisIndex: 1,
        // A log axis cannot place zero; an (unlikely) zero-record year
        // gets an honest gap instead of a fake floor point.
        data: rows.map((r) => (r.records > 0 ? r.records : null)),
        color: C.accent, symbol: "circle", symbolSize: 4,
        lineStyle: { width: 2 }, z: 5,
      },
    ],
  });
  if (hasProj) slots.extra.append(el("p", "panel-note", edp.note));
}
