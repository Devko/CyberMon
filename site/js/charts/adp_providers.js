// Third chart — the sole-enricher board. Contract: site/data/adp_coverage.json
// Every ADP publisher by how many published records it appears on, as a
// bar-in-cell table (the naming_board / cna board pattern; no ECharts). The
// list is short and lopsided: CISA-ADP does the substantive enrichment (drawn
// in accent), the CVE Program root — when present — only reference tags.
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";
import { fmtInt, fmtPct } from "../theme.js";

const COLS = [
  { key: "provider", label: "colProvider", numeric: false },
  { key: "n", label: "colRecords", numeric: true },
  { key: "pct", label: "colShare", numeric: true },
];

export function render(slots, data) {
  const ed = editorial.sections.adp_providers;
  const providers = data.providers || [];
  const h = data.headline || {};
  slots.chart.classList.remove("chart", "chart-tall");

  if (!providers.length) {
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }

  slots.stat.append(el("div", "table-context", tpl(ed.statTemplate, {
    shown: providers.length,
    pct: fmtPct(h.pct_cisa ?? 0),
  })));

  const maxN = providers[0].n || 1; // board is sorted by n descending

  const wrap = el("div", "table-wrap");
  const table = el("table", "cna-table");
  const thead = el("thead");
  const headRow = el("tr");
  for (const col of COLS) {
    headRow.append(el("th", col.numeric ? "num" : "", ed[col.label]));
  }
  thead.append(headRow);

  const tbody = el("tbody");
  for (const p of providers) {
    const tr = el("tr");
    const isSole = p.provider === h.sole_enricher;

    const tdName = el("td", "cna-name");
    tdName.append(el("span", "cna-short", p.provider));
    tr.append(tdName);

    const tdN = el("td", "num");
    const cell = el("div", "cellbar");
    const fill = el("div", "cellbar-fill" + (isSole ? " accent" : ""));
    fill.style.width =
      `${Math.max(0, Math.min(100, (p.n / maxN) * 100)).toFixed(1)}%`;
    cell.append(fill, el("span", "cellbar-val", fmtInt(p.n)));
    tdN.append(cell);
    tr.append(tdN);

    tr.append(el("td", "num", fmtPct(p.pct)));
    tbody.append(tr);
  }
  table.append(thead, tbody);
  wrap.append(table);
  slots.chart.append(wrap);
}
