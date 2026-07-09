// Market 1 (hero) — the hype index. Contract: site/data/market_hype.json
// (shared by all three market sections; market.js fetches it once).
// A strip of per-term GDELT sparkline cards selects the term shown in the
// big three-source line chart (GDELT / Hacker News / arXiv, index 0–100).
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, escapeHtml } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

const SOURCES = [
  { key: "gdelt", name: "GDELT", color: C.accent },
  { key: "hn", name: "Hacker News", color: C.versions.v3 },
  { key: "arxiv", name: "arXiv", color: C.versions.v2 },
];

// Honest empty state for launch-time payloads (backfill still running).
function noDataCard() {
  return el("div", "nodata-card", "Not enough data yet.");
}

// Union of every month observed in any series of any term, sorted ascending.
// YYYY-MM strings sort correctly as plain strings.
function monthUnion(terms) {
  const set = new Set();
  for (const t of terms) {
    for (const s of SOURCES) {
      for (const row of t.series?.[s.key] || []) set.add(row.month);
    }
  }
  return [...set].sort();
}

export function render(slots, data) {
  const ed = editorial.sections.hype;
  const terms = data.terms || [];
  const months = monthUnion(terms);

  if (!terms.length || !months.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(noDataCard());
    return;
  }

  // Term series values aligned to the global month axis; missing months stay
  // null so backfill gaps render as visible breaks (connectNulls: false).
  const seriesFor = (term, key) => {
    const byMonth = new Map((term.series?.[key] || []).map((r) => [r.month, r]));
    return months.map((mo) => {
      const row = byMonth.get(mo);
      return row === undefined || row.index === null || row.index === undefined ? null : row.index;
    });
  };

  // ---- native select control (kept in sync with the sparkline strip) --------
  const label = el("label", "term-select-label", ed.selectLabel);
  const select = el("select", "term-select");
  for (const t of terms) {
    const opt = el("option", null, t.label);
    opt.value = t.id;
    select.append(opt);
  }
  label.append(select);
  slots.controls.append(el("span", "term-count", tpl(ed.termCountNote, { n: terms.length })), label);

  // ---- sparkline strip (GDELT index only, one card per term) ----------------
  const strip = el("div", "sparkline-strip");
  slots.stat.append(strip, el("p", "strip-note", ed.sparklineNote));

  const cards = terms.map((term) => {
    const card = el("button", "sparkline-card");
    card.type = "button";
    card.setAttribute("aria-pressed", "false");
    card.append(el("span", "sparkline-label", term.label));
    // span, not div: <button> only permits phrasing content (display:block in CSS)
    const mini = el("span", "sparkline-chart");
    card.append(mini);
    strip.append(card);
    card.addEventListener("click", () => setTerm(term.id));
    return { term, card, mini, chart: null };
  });

  // Init after the cards are in the DOM so ECharts can measure them.
  for (const c of cards) {
    // A term whose GDELT fetch hasn't landed yet gets an honest label
    // instead of an empty box that reads as a rendering bug.
    if (!(c.term.series?.gdelt || []).length) {
      c.mini.classList.add("sparkline-empty");
      c.mini.textContent = "no media data yet";
      continue;
    }
    c.chart = mkChart(c.mini);
    c.chart.setOption({
      animation: false,
      grid: { left: 0, right: 0, top: 3, bottom: 3 },
      xAxis: { type: "category", data: months, show: false, boundaryGap: false },
      yAxis: { type: "value", min: 0, max: 100, show: false },
      series: [{
        type: "line",
        data: seriesFor(c.term, "gdelt"),
        symbol: "none", connectNulls: false, silent: true,
        lineStyle: { width: 1.5, color: C.muted },
      }],
    });
  }

  // ---- big chart: 3 sources for the selected term ----------------------------
  const big = mkChart(slots.chart);
  // display name -> Map(month -> raw row) for the selected term (tooltip needs n)
  let rawLookup = {};

  const optionFor = (term) => {
    rawLookup = {};
    // Only sources that actually have data: an empty series would put a
    // clickable legend entry over a chart with no line — reads as broken.
    const present = SOURCES.filter((s) => (term.series?.[s.key] || []).length);
    const series = present.map((s) => {
      const rows = term.series?.[s.key] || [];
      rawLookup[s.name] = new Map(rows.map((r) => [r.month, r]));
      return {
        name: s.name, type: "line", color: s.color,
        data: seriesFor(term, s.key),
        // a 1-point series has no line segment: show the symbol or it is
        // literally invisible
        symbol: "circle", symbolSize: rows.length < 2 ? 5 : 3,
        showSymbol: rows.length < 2,
        connectNulls: false,
        lineStyle: { width: 2 },
      };
    });
    return {
      grid: { ...baseGrid, top: 44 },
      legend: { ...baseLegend, data: present.map((s) => s.name) },
      tooltip: {
        ...baseTooltip, trigger: "axis",
        formatter: (params) => {
          const head = params.length
            ? `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(params[0].axisValueLabel ?? params[0].name)}</div>`
            : "";
          const rows = params
            .filter((p) => p.value !== null && p.value !== undefined && !Number.isNaN(p.value))
            .map((p) => {
              const raw = rawLookup[p.seriesName]?.get(p.axisValue);
              const n = raw && raw.n !== null && raw.n !== undefined ? fmtInt(raw.n) : "–";
              return (
                `<div style="display:flex;gap:12px;justify-content:space-between;align-items:baseline;">` +
                `<span>${p.marker} ${escapeHtml(p.seriesName)}</span>` +
                `<span><strong style="font-family:inherit">${escapeHtml(Number(p.value).toFixed(0))}</strong>` +
                `<span style="color:${C.muted}"> · n=${escapeHtml(n)}</span></span></div>`
              );
            })
            .join("");
          return head + rows;
        },
      },
      xAxis: catAxis(months, { boundaryGap: false }),
      yAxis: valAxis({ min: 0, max: 100 }),
      series,
    };
  };

  function setTerm(id) {
    const term = terms.find((t) => t.id === id) || terms[0];
    select.value = term.id;
    for (const c of cards) {
      const active = c.term.id === term.id;
      c.card.classList.toggle("is-active", active);
      c.card.setAttribute("aria-pressed", String(active));
      if (c.chart) {
        c.chart.setOption({ series: [{ lineStyle: { width: 1.5, color: active ? C.accent : C.muted } }] });
      }
    }
    big.setOption(optionFor(term), { replaceMerge: ["series"] });
  }

  select.addEventListener("change", () => setTerm(select.value));
  setTerm(data.headline?.top_riser?.term_id ?? terms[0].id);
}
