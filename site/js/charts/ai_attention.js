// The AI Alibi 3 — AI-security attention against the clock it is blamed
// for. Contract: site/data/ai_alibi.json (`attention`).
//
// Two axes, on purpose and disclosed in the caption: attention is a
// monthly 0-100 index (module 02 normalizes every lane to its own peak),
// the clock is an annual median in days. They share no unit and no
// sampling rate, so the chart never implies a correlation coefficient —
// it shows one line climbing while the other sits still, which is the
// entire argument.
//
// The clock renders as a STEP line. An annual median interpolated across
// months would draw twelve monthly values that were never measured, and a
// smooth slope through them reads as motion the data doesn't contain.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, baseLegend, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

const TERM_COLOR = [C.accent, "#ded7c2"];

export function render(slots, data) {
  const ed = editorial.sections.ai_attention;
  const att = data.attention || {};
  const terms = att.terms || [];
  const clockRows = att.clock || [];

  // A degraded market upstream costs this section, never the page: the
  // pipeline says so explicitly rather than shipping an empty chart that
  // reads as a rendering bug.
  if (!att.available) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", ed.unavailable));
    slots.panel.querySelector(".panel-note")?.remove();
    return;
  }
  if (!terms.length || !clockRows.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    slots.panel.querySelector(".panel-note")?.remove();
    return;
  }

  // Month axis = the union across terms, so a lane that starts late
  // (Agentic AI has no Wikipedia article until 2025) leaves a visible
  // gap instead of being silently shifted left.
  const months = [...new Set(terms.flatMap((t) => t.months.map((p) => p.month)))].sort();
  const clockByYear = new Map(clockRows.map((r) => [r.year, r.value]));

  const seriesFor = (term) => {
    const byMonth = new Map(term.months.map((p) => [p.month, p.index]));
    return months.map((mo) => (byMonth.has(mo) ? byMonth.get(mo) : null));
  };

  // The clock, held flat across each year's months — and null for months
  // whose year has no complete-year value (the partial current year).
  const clockSeries = months.map((mo) => {
    const year = Number(mo.slice(0, 4));
    return clockByYear.has(year) ? clockByYear.get(year) : null;
  });

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, right: 56, top: 40 },
    legend: { ...baseLegend, data: [...terms.map((t) => t.label), ed.clockLabel] },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        if (!params.length) return "";
        const month = params[0].axisValueLabel ?? params[0].name;
        const lines = params
          .filter((p) => p.value !== null && p.value !== undefined)
          .map((p) => {
            const isClock = p.seriesName === ed.clockLabel;
            const v = isClock ? `${Math.round(p.value)}d` : Number(p.value).toFixed(1);
            return `<span style="color:${p.color};">■</span> ${escapeHtml(p.seriesName)} <strong>${v}</strong>`;
          });
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(month))}</div>` +
          lines.join("<br>")
        );
      },
    },
    xAxis: catAxis(months, {
      boundaryGap: false,
      axisLabel: { ...{ color: C.muted, fontFamily: MONO, fontSize: 11 }, formatter: (v) => v.slice(0, 4), interval: 11 },
    }),
    yAxis: [
      valAxis({
        name: ed.axisAttention,
        min: 0,
        max: 100,
        nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
      }),
      valAxis({
        name: ed.axisClock,
        nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
        splitLine: { show: false },
        axisLabel: { color: C.faint, fontFamily: MONO, fontSize: 11, formatter: (v) => `${Math.round(v)}d` },
      }),
    ],
    series: [
      ...terms.map((term, i) => ({
        name: term.label,
        type: "line",
        data: seriesFor(term),
        color: TERM_COLOR[i % TERM_COLOR.length],
        symbol: "none",
        lineStyle: { width: 2 },
        connectNulls: false,
        z: 5,
      })),
      {
        name: ed.clockLabel,
        type: "line",
        yAxisIndex: 1,
        step: "middle",
        data: clockSeries,
        color: C.faint,
        symbol: "none",
        lineStyle: { width: 2, type: "dashed" },
        connectNulls: false,
      },
    ],
  });

  // ---- panel note -----------------------------------------------------------
  const noteEl = slots.panel.querySelector(".panel-note");
  const h = att.headline;
  if (noteEl) {
    if (h) {
      noteEl.textContent = tpl(ed.note, {
        label: h.label,
        index_first: h.index_first.toFixed(1),
        index_last: h.index_last.toFixed(1),
        month_first: h.month_first,
        month_last: h.month_last,
        clock_min: Math.round(h.clock_min),
        clock_max: Math.round(h.clock_max),
        year_first: h.clock_year_first,
        year_last: h.clock_year_last,
      });
    } else {
      noteEl.remove(); // never show a template with holes in it
    }
  }
}
