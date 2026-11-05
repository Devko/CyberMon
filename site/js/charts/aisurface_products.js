// AI Product CVEs 4 — the products behind the counts: the classifier's
// product families ranked by CVEs published in the window, with their
// all-years count, KEV and exploit-code counts and the CNA that assigned
// most of them. Contract: site/data/ai_products.json (products, cnas).
// HTML table, no ECharts (tags_board pattern).
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";
import { fmtInt, fmtPct } from "../theme.js";

export function render(slots, data) {
  const ed = editorial.sections.aisurface_products;
  const L = ed.labels;
  const rows = data.products || [];
  const w = data.window || {};
  const cats = editorial.sections.aisurface_years.labels.categories;

  slots.stat.append(el("div", "table-context", tpl(ed.windowTemplate, {
    from: w.from ?? "?", to: w.to ?? "?", shown: fmtInt(rows.length),
    total: fmtInt(data.product_count),
  })));
  slots.chart.classList.remove("chart");
  if (!rows.length) {
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }
  const max = Math.max(...rows.map((r) => r.n));
  const wrap = el("div", "table-wrap");
  const table = el("table", "cna-table");
  const thead = el("thead");
  const head = el("tr");
  head.append(
    el("th", "", L.colProduct), el("th", "", L.colCategory),
    el("th", "num", L.colN), el("th", "num", L.colAll),
    el("th", "num", L.colKev), el("th", "num", L.colPoc),
    el("th", "", L.colCna)
  );
  thead.append(head);
  const tbody = el("tbody");
  for (const r of rows) {
    const tr = el("tr");
    const name = el("td", "cna-name");
    name.append(el("span", "cna-short", r.label));
    const nTd = el("td", "num");
    const cell = el("div", "cellbar");
    const fill = el("div", "cellbar-fill");
    fill.style.width = `${((100 * r.n) / max).toFixed(1)}%`;
    cell.append(fill, el("span", "cellbar-val", fmtInt(r.n)));
    nTd.append(cell);
    tr.append(
      name,
      el("td", "", cats[r.category] ?? r.category),
      nTd,
      el("td", "num", fmtInt(r.all_years)),
      el("td", "num", fmtInt(r.kev)),
      el("td", "num", fmtInt(r.poc)),
      el("td", "", tpl(L.cnaCell, { cna: r.top_cna, pct: fmtPct(r.top_cna_pct) }))
    );
    tbody.append(tr);
  }
  table.append(thead, tbody);
  wrap.append(table);
  slots.chart.append(wrap);
}
