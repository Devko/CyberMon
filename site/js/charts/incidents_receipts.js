// Incidents 3 — the receipts board. Contract: site/data/sec_incidents.json
// (recent). A plain HTML table, newest first as the pipeline emits it: each
// latest Item 1.05 filing with its form, filer (ticker when EDGAR's display
// name carries one) and the lag for a matched amendment. The filing date IS
// the link to the filing index on sec.gov (built from CIK + accession
// number), so the link survives phone widths where the table scrolls.
import { editorial } from "../editorial.js";
import { el, link } from "../dom.js";
import { fmtInt } from "../theme.js";
import { showNoData } from "./incidents_clock.js";

const COLS = [
  { key: "date", labelKey: "colDate", mono: true },
  { key: "form", labelKey: "colForm", mono: true },
  { key: "company", labelKey: "colCompany" },
  { key: "lag_days", labelKey: "colLag", numeric: true },
];

export function render(slots, data) {
  const ed = editorial.sections.incidents_receipts;
  if (data.status !== "ok") {
    showNoData(slots, ed.nodata);
    return;
  }
  const rows = data.recent || [];
  slots.chart.classList.remove("chart");
  if (!rows.length) {
    slots.chart.append(el("div", "nodata-card", ed.noRows));
    return;
  }

  const wrap = el("div", "table-wrap");
  const table = el("table", "cna-table");
  const thead = el("thead");
  const headRow = el("tr");
  for (const col of COLS) headRow.append(el("th", col.numeric ? "num" : "", ed[col.labelKey]));
  thead.append(headRow);
  const tbody = el("tbody");
  for (const r of rows) {
    const tr = el("tr");
    for (const col of COLS) {
      const td = el("td", col.numeric ? "num mono" : col.mono ? "mono" : "");
      if (col.key === "date") {
        const a = link(r.url, r.date, "mono");
        a.setAttribute("aria-label", `${r.date} ${r.form} ${r.company} ${ed.linkLabel}`);
        td.append(a);
      } else if (col.key === "company") {
        td.textContent = r.ticker ? `${r.company} (${r.ticker})` : r.company;
      } else if (col.key === "lag_days") {
        td.textContent = r.lag_days == null ? "" : fmtInt(r.lag_days);
      } else {
        td.textContent = String(r[col.key] ?? "");
      }
      tr.append(td);
    }
    tbody.append(tr);
  }
  table.append(thead, tbody);
  wrap.append(table);
  slots.chart.append(wrap);
}
