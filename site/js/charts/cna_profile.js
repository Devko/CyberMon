// Concentration 4 — CNA profile: one CNA against its peers, in eight
// linked small multiples (a CVSS histogram against all CNAs, then seven
// strips with every listed CNA as a tick, the median CNA as a dashed line
// and the chosen CNA in the accent). Contract: site/data/cna_profiles.json
// (its own file; concentration.js fetches it for this section only).
//
// Linking: the picker (a search box filtering a native <select>) drives
// every panel; hovering a strip names the nearest CNA in all eight
// panels, and clicking it picks that CNA. The choice lives in the URL
// hash (#cna=<shortName>), read on load and on hashchange; other hashes
// (the page's own section anchors) are left alone.
//
// Plain SVG, no ECharts: each graphic stretches to its cell
// (preserveAspectRatio="none", strokes non-scaling) and its text lives in
// HTML, so nothing redraws on resize. Each graphic is role="img" with a
// text alternative giving the CNA's value, the median CNA and its rank.
import { editorial, tpl } from "../editorial.js";
import { el, clear } from "../dom.js";
import { fmtInt, fmtPct } from "../theme.js";

const SVG_NS = "http://www.w3.org/2000/svg";
const VB_W = 1000; // viewBox width; the SVG stretches to its cell
const STRIP_H = 44;
const HIST_H = 120;

// Panel order: the score histogram spans two columns on wide screens.
const STRIPS = ["cwe_pct", "scored_pct", "affected_pct", "rejected_pct",
                "rescores", "kev_pct", "exploit_pct"];

let uid = 0;

function svg(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  return node;
}

// Strip axis: shares that some CNAs take to 100% keep the full 0-100
// scale; shares that stay low (KEV, exploit code, rejections) and the
// rescore count end at a round ceiling just above the largest CNA, so the
// ticks do not pile up at the left edge. The end label says which.
const FULL_SCALE = new Set(["cwe_pct", "scored_pct", "affected_pct"]);
const CEILINGS = [1, 2, 3, 5, 10, 15, 20, 25, 30, 40, 50, 60, 75, 100, 150, 200,
                  250, 300, 400, 500, 750, 1000];

function axisMax(metric, max) {
  if (FULL_SCALE.has(metric)) return 100;
  const top = Number.isFinite(max) ? max : 0;
  const nice = CEILINGS.find((c) => c >= top) ?? Math.ceil(top);
  return metric === "rescores" ? nice : Math.min(100, nice);
}

function readHashCna() {
  const m = /(?:^#|&)cna=([^&]+)/.exec(location.hash);
  if (!m) return null;
  try {
    return decodeURIComponent(m[1]);
  } catch {
    return null;
  }
}

export function render(slots, data) {
  const ed = editorial.sections.cna_profile;
  const L = ed.labels;
  const rows = data.cnas || [];
  const summary = data.summary || {};
  const w = data.window || {};
  const log = data.rescore_log || {};
  const pooled = data.all || {};

  slots.chart.classList.remove("chart");
  slots.chart.classList.add("profile");
  // A plain container here (picker + figures), not one image: each figure
  // below carries its own name.
  slots.chart.removeAttribute("aria-label");
  slots.stat.append(el("div", "table-context", tpl(ed.windowTemplate, {
    from: w.from ?? "?", to: w.to ?? "?",
    min_published: fmtInt(data.min_published),
    n: fmtInt(rows.length), all: fmtInt(pooled.cna_count),
  })));
  if (!rows.length) {
    slots.chart.append(el("div", "nodata-card", ed.nodata || editorial.ui.nodata));
    return;
  }

  const byName = new Map(rows.map((r) => [r.cna, r]));
  const sorted = [...rows].sort((a, b) =>
    a.cna.localeCompare(b.cna, "en", { sensitivity: "base" }));
  const fmt = (metric, v) => {
    if (v === null || v === undefined) return editorial.ui.na;
    if (metric === "rescores") return fmtInt(v);
    if (metric === "score_median") return Number(v).toFixed(1);
    return fmtPct(v);
  };
  const logFrom = log.first_observed ?? editorial.ui.na;

  // ---- picker: search box filtering a native select ----------------------
  const id = `cna-profile-${++uid}`;
  const picker = el("div", "profile-picker");
  const searchLabel = el("label", "profile-label", L.searchLabel);
  const search = el("input", "profile-search");
  search.type = "search";
  search.id = `${id}-search`;
  search.autocomplete = "off";
  search.spellcheck = false;
  search.placeholder = L.searchPlaceholder;
  search.setAttribute("aria-controls", `${id}-select`);
  searchLabel.htmlFor = search.id;
  const selectLabel = el("label", "profile-label", L.selectLabel);
  const select = el("select", "profile-select");
  select.id = `${id}-select`;
  selectLabel.htmlFor = select.id;
  const matches = el("p", "profile-matches");
  matches.setAttribute("aria-live", "polite");
  const field = (label, control) => {
    const f = el("div", "profile-field");
    f.append(label, control);
    return f;
  };
  picker.append(field(searchLabel, search), field(selectLabel, select), matches);

  const head = el("p", "profile-head");
  head.setAttribute("aria-live", "polite");

  // ---- legend --------------------------------------------------------------
  const legend = el("div", "profile-legend");
  const legendItem = (cls, text) => {
    const item = el("span", "profile-legend-item");
    item.append(el("span", `profile-key ${cls}`), text);
    return item;
  };
  const legendCna = legendItem("key-cna", "");
  legend.append(legendCna, legendItem("key-median", L.legendMedian),
                legendItem("key-peer", L.legendPeers),
                legendItem("key-all", L.legendAll));

  // ---- panels ----------------------------------------------------------------
  const grid = el("div", "profile-grid");
  const panels = [];

  // Histogram panel: the CNA's share of its scored records per whole-point
  // band, bars; every CNA's records pooled, outline steps.
  {
    const cell = el("figure", "profile-cell profile-cell-wide");
    const title = el("figcaption", "profile-title", L.metrics.score_median);
    const fig = el("div", "profile-figure");
    fig.setAttribute("role", "img");
    const g = svg("svg", { viewBox: `0 0 ${VB_W} ${HIST_H}`, preserveAspectRatio: "none",
                           class: "profile-svg", "aria-hidden": "true", focusable: "false" });
    fig.append(g);
    const axis = el("div", "profile-axis profile-axis-hist");
    for (const t of ["0", "2", "4", "6", "8", "10"]) axis.append(el("span", null, t));
    const readout = el("p", "profile-readout");
    const hover = el("p", "profile-hover");
    hover.setAttribute("aria-hidden", "true");
    // The bands as a table: the exact shares the bars and steps draw.
    const table = el("details", "profile-table");
    table.append(el("summary", null, L.tableSummary));
    const tbody = el("tbody");
    const tableEl = el("table", "cna-table profile-band-table");
    const headRow = el("tr");
    const colCna = el("th", "num", "");
    headRow.append(el("th", null, L.colBand), colCna, el("th", "num", L.colAll));
    const thead = el("thead");
    thead.append(headRow);
    tableEl.append(thead, tbody);
    table.append(tableEl);
    cell.append(title, fig, axis, readout, hover, table);
    grid.append(cell);
    panels.push({ metric: "score_median", fig, g, readout, hover, hist: true, tbody, colCna });
  }
  for (const metric of STRIPS) {
    const cell = el("figure", "profile-cell");
    const title = el("figcaption", "profile-title",
                     tpl(L.metrics[metric], { log_from: logFrom }));
    const fig = el("div", "profile-figure profile-strip");
    fig.setAttribute("role", "img");
    const g = svg("svg", { viewBox: `0 0 ${VB_W} ${STRIP_H}`, preserveAspectRatio: "none",
                           class: "profile-svg", "aria-hidden": "true", focusable: "false" });
    fig.append(g);
    const max = axisMax(metric, summary[metric]?.max);
    const axis = el("div", "profile-axis");
    const tick = (v) => (metric === "rescores" ? fmtInt(v) : `${v}%`);
    axis.append(el("span", null, tick(0)), el("span", null, tick(max)));
    const hover = el("p", "profile-hover");
    hover.setAttribute("aria-hidden", "true");
    const readout = el("p", "profile-readout");
    cell.append(title, fig, axis, readout, hover);
    grid.append(cell);
    panels.push({ metric, fig, g, readout, hover, max });
  }

  slots.chart.append(picker, head, legend, grid);

  // ---- drawing ---------------------------------------------------------------
  const xOf = (p, v) => (Math.max(0, Math.min(p.max, v)) / p.max) * VB_W;
  let current = null;
  let hovered = null;

  function rankText(metric, row, long) {
    const rank = row.ranks?.[metric];
    const n = summary[metric]?.n ?? 0;
    if (rank === null || rank === undefined) return L.unranked;
    const v = row.values[metric];
    const others = rows.filter((r) => r !== row && r.values[metric] === v).length;
    if (long) {
      const key = others > 1 ? L.rankLongTied : others === 1 ? L.rankLongTiedOne : L.rankLong;
      return tpl(key, {
        rank: fmtInt(rank), n: fmtInt(n), others: fmtInt(others),
      });
    }
    return tpl(others ? L.rankTied : L.rank, { rank: fmtInt(rank), n: fmtInt(n) });
  }

  function drawStrip(p, row) {
    const g = clear(p.g);
    const mid = STRIP_H / 2;
    g.append(svg("line", { x1: 0, x2: VB_W, y1: mid, y2: mid, class: "strip-base",
                           "vector-effect": "non-scaling-stroke" }));
    for (const r of rows) {
      const v = r.values[p.metric];
      if (v === null || v === undefined || r === row) continue;
      const x = xOf(p, v);
      g.append(svg("line", { x1: x, x2: x, y1: mid - 9, y2: mid + 9, class: "strip-peer",
                             "vector-effect": "non-scaling-stroke" }));
    }
    const med = summary[p.metric]?.median;
    if (med !== null && med !== undefined) {
      const x = xOf(p, med);
      g.append(svg("line", { x1: x, x2: x, y1: 2, y2: STRIP_H - 2, class: "strip-median",
                             "vector-effect": "non-scaling-stroke" }));
    }
    if (hovered && hovered !== row) {
      const v = hovered.values[p.metric];
      if (v !== null && v !== undefined) {
        const x = xOf(p, v);
        g.append(svg("line", { x1: x, x2: x, y1: 4, y2: STRIP_H - 4, class: "strip-hover",
                               "vector-effect": "non-scaling-stroke" }));
      }
    }
    const v = row.values[p.metric];
    if (v !== null && v !== undefined) {
      const x = xOf(p, v);
      g.append(svg("line", { x1: x, x2: x, y1: 0, y2: STRIP_H, class: "strip-cna",
                             "vector-effect": "non-scaling-stroke" }));
    }
  }

  function drawHist(p, row) {
    const g = clear(p.g);
    const bins = pooled.score_bins || [];
    const tot = pooled.scored || 0;
    const allShare = bins.map((n) => (tot ? n / tot : 0));
    const own = row.counts?.scored ? row.score_bins.map((n) => n / row.counts.scored) : null;
    p.shares = { own, all: allShare };
    clear(p.tbody);
    p.colCna.textContent = row.cna;
    (data.score_bins || []).forEach((band, i) => {
      const tr = el("tr");
      tr.append(el("td", null, band),
                el("td", "num", own ? fmtPct(100 * own[i]) : editorial.ui.na),
                el("td", "num", fmtPct(100 * (allShare[i] ?? 0))));
      p.tbody.append(tr);
    });
    const top = Math.max(0.01, ...allShare, ...(own || [0]));
    const bw = VB_W / Math.max(1, bins.length);
    const y = (s) => HIST_H - (s / top) * (HIST_H - 6);
    g.append(svg("line", { x1: 0, x2: VB_W, y1: HIST_H - 0.5, y2: HIST_H - 0.5, class: "strip-base",
                           "vector-effect": "non-scaling-stroke" }));
    if (own) {
      own.forEach((s, i) => {
        if (!s) return;
        g.append(svg("rect", { x: i * bw + 6, width: bw - 12, y: y(s), height: HIST_H - y(s),
                               class: "hist-cna" }));
      });
    }
    // pooled outline as a step line over the bars
    let d = "";
    allShare.forEach((s, i) => {
      d += `${i ? "L" : "M"}${i * bw},${y(s)} L${(i + 1) * bw},${y(s)} `;
    });
    if (d) g.append(svg("path", { d, class: "hist-all", "vector-effect": "non-scaling-stroke" }));
  }

  function panelText(p, row) {
    const metric = p.metric;
    const v = row.values[metric];
    const med = summary[metric]?.median;
    if (p.hist && (v === null || v === undefined)) {
      const scored = row.counts?.scored ?? 0;
      const tplKey = scored ? L.scoreFew : L.scoreNone;
      const text = tpl(tplKey, { cna: row.cna, scored: fmtInt(scored),
                                 min_scored: fmtInt(data.min_scored) });
      p.readout.textContent = text;
      p.fig.setAttribute("aria-label", `${text} ${tpl(L.altAll, {
        median: fmt(metric, pooled.score_median) })}`);
      return;
    }
    p.readout.textContent = tpl(p.hist ? L.readoutScore : L.readout, {
      value: fmt(metric, v), median: fmt(metric, med), rank: rankText(metric, row, false),
    });
    p.fig.setAttribute("aria-label", tpl(p.hist ? L.altHist : L.alt, {
      cna: row.cna, value: fmt(metric, v), median: fmt(metric, med),
      rank: rankText(metric, row, true), all: fmt(metric, pooled.score_median),
      title: tpl(L.metrics[metric], { log_from: logFrom }),
    }));
  }

  function draw() {
    const row = current;
    head.textContent = tpl(L.head, {
      cna: row.cna, published: fmtInt(row.published), rejected: fmtInt(row.rejected),
      from: w.from ?? "?", to: w.to ?? "?",
    });
    legendCna.lastChild.textContent = row.cna;
    for (const p of panels) {
      if (p.hist) drawHist(p, row);
      else drawStrip(p, row);
      panelText(p, row);
    }
  }

  function setHover(row, panel) {
    hovered = row;
    for (const p of panels) {
      if (p.hist) continue;
      drawStrip(p, current);
      p.hover.textContent = row && p === panel
        ? tpl(L.hover, { cna: row.cna, value: fmt(p.metric, row.values[p.metric]) })
        : "";
    }
  }

  function nearest(p, clientX) {
    const box = p.fig.getBoundingClientRect();
    if (!box.width) return null;
    const v = ((clientX - box.left) / box.width) * p.max;
    let best = null;
    let gap = Infinity;
    for (const r of rows) {
      const rv = r.values[p.metric];
      if (rv === null || rv === undefined) continue;
      const dv = Math.abs(rv - v);
      // ties go to the larger CNA (rows arrive largest first)
      if (dv < gap) { best = r; gap = dv; }
    }
    return best;
  }

  const histPanel = panels.find((p) => p.hist);
  const bandAt = (clientX) => {
    const box = histPanel.fig.getBoundingClientRect();
    const n = (data.score_bins || []).length;
    if (!box.width || !n) return -1;
    return Math.max(0, Math.min(n - 1, Math.floor(((clientX - box.left) / box.width) * n)));
  };
  histPanel.fig.addEventListener("pointermove", (e) => {
    const i = bandAt(e.clientX);
    const sh = histPanel.shares;
    if (i < 0 || !sh) return;
    histPanel.hover.textContent = tpl(L.histHover, {
      band: data.score_bins[i], cna: current.cna,
      own: sh.own ? fmtPct(100 * sh.own[i]) : editorial.ui.na,
      all: fmtPct(100 * (sh.all[i] ?? 0)),
    });
  });
  histPanel.fig.addEventListener("pointerleave", () => { histPanel.hover.textContent = ""; });

  for (const p of panels) {
    if (p.hist) continue;
    p.fig.addEventListener("pointermove", (e) => setHover(nearest(p, e.clientX), p));
    p.fig.addEventListener("pointerleave", () => setHover(null, null));
    p.fig.addEventListener("click", (e) => {
      const r = nearest(p, e.clientX);
      if (r) choose(r.cna, true);
    });
  }

  // ---- selection, search and the URL hash ------------------------------------
  // With no match the select keeps the chosen CNA as its only option, so
  // it never shows an empty box.
  function fillOptions(list) {
    clear(select);
    const shown = list.length ? list : [current].filter(Boolean);
    for (const r of shown) {
      const opt = el("option", null, tpl(L.option, { cna: r.cna, n: fmtInt(r.published) }));
      opt.value = r.cna;
      select.append(opt);
    }
    if (current && shown.includes(current)) select.value = current.cna;
    matches.textContent = search.value.trim()
      ? tpl(list.length ? L.matches : L.noMatch, { n: fmtInt(list.length), total: fmtInt(rows.length) })
      : "";
  }

  function choose(name, updateHash) {
    const row = byName.get(name);
    if (!row) return;
    current = row;
    if (![...select.options].some((o) => o.value === name)) {
      search.value = "";
      fillOptions(sorted);
    }
    select.value = name;
    hovered = null;
    for (const p of panels) if (p.hover) p.hover.textContent = "";
    draw();
    if (updateHash) history.replaceState(null, "", `#cna=${encodeURIComponent(name)}`);
  }

  search.addEventListener("input", () => {
    const q = search.value.trim().toLowerCase();
    const list = q ? sorted.filter((r) => r.cna.toLowerCase().includes(q)) : sorted;
    fillOptions(list);
    if (list.length && !list.includes(current)) choose(list[0].cna, true);
  });
  select.addEventListener("change", () => choose(select.value, true));
  window.addEventListener("hashchange", () => {
    const name = readHashCna();
    if (name && byName.has(name) && name !== current?.cna) choose(name, false);
  });

  fillOptions(sorted);
  const fromHash = readHashCna();
  // Default: the largest CNA (rows arrive sorted by published, largest first).
  choose(fromHash && byName.has(fromHash) ? fromHash : rows[0].cna, false);
  if (fromHash && byName.has(fromHash)) {
    requestAnimationFrame(() => slots.chart.closest(".chart-section")?.scrollIntoView());
  }
}
