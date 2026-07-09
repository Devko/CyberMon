// Chart 5 — CNA rubber-stamp board. Contract: site/data/cna_leaderboard.json
// A sortable HTML table with bar-in-cell visualization (no ECharts needed).
import { editorial, tpl } from "../editorial.js";
import { el, clear } from "../dom.js";
import { fmtInt } from "../theme.js";

const COLS = [
  { key: "cna", labelKey: "colCna", numeric: false },
  { key: "n", labelKey: "colN", numeric: true },
  { key: "avg_cvss", labelKey: "colAvg", numeric: true, bar: (v) => v * 10 },
  { key: "median_cvss", labelKey: "colMedian", numeric: true, bar: (v) => v * 10 },
  { key: "pct_geq_9", labelKey: "colGeq9", numeric: true, bar: (v) => v, accent: true },
  { key: "pct_geq_7", labelKey: "colGeq7", numeric: true, bar: (v) => v },
];

function fmtCell(col, v) {
  if (col.key === "n") return fmtInt(v);
  if (col.key.startsWith("pct_")) return `${v.toFixed(1)}%`;
  if (typeof v === "number") return v.toFixed(1);
  return String(v);
}

export function render(slots, data) {
  const ed = editorial.sections.cna;

  slots.stat.append(
    el("div", "table-context", tpl(ed.windowTemplate, {
      window_years: data.window_years,
      min_cves: data.min_cves,
    }))
  );

  const state = { key: "pct_geq_9", dir: -1 }; // contract default sort
  const rows = [...data.cnas];

  const wrap = el("div", "table-wrap");
  const table = el("table", "cna-table");
  const thead = el("thead");
  const headRow = el("tr");
  const tbody = el("tbody");

  const ths = COLS.map((col) => {
    const th = el("th", col.numeric ? "num" : "", ed[col.labelKey]);
    th.tabIndex = 0;
    th.setAttribute("role", "button");
    const activate = () => {
      if (state.key === col.key) state.dir = -state.dir;
      else { state.key = col.key; state.dir = col.numeric ? -1 : 1; }
      draw();
    };
    th.addEventListener("click", activate);
    th.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); activate(); } });
    headRow.append(th);
    return { th, col };
  });
  thead.append(headRow);
  table.append(thead, tbody);
  wrap.append(table);
  slots.chart.classList.remove("chart");
  slots.chart.append(wrap);

  function draw() {
    ths.forEach(({ th, col }) => {
      th.classList.toggle("is-sorted", col.key === state.key);
      th.setAttribute("aria-sort", col.key === state.key ? (state.dir === -1 ? "descending" : "ascending") : "none");
    });

    rows.sort((a, b) => {
      const av = a[state.key], bv = b[state.key];
      const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
      return cmp * state.dir;
    });

    clear(tbody);
    for (const r of rows) {
      const tr = el("tr");
      for (const col of COLS) {
        if (col.key === "cna") {
          const td = el("td", "cna-name");
          td.append(el("span", "cna-short", r.cna), el("span", "cna-org", r.org));
          tr.append(td);
        } else {
          const td = el("td", "num");
          if (col.bar) {
            const cell = el("div", "cellbar");
            const fill = el("div", "cellbar-fill" + (col.accent ? " accent" : ""));
            fill.style.width = `${Math.max(0, Math.min(100, col.bar(r[col.key]))).toFixed(1)}%`;
            cell.append(fill, el("span", "cellbar-val", fmtCell(col, r[col.key])));
            td.append(cell);
          } else {
            td.textContent = fmtCell(col, r[col.key]);
          }
          tr.append(td);
        }
      }
      tbody.append(tr);
    }
  }

  draw();
}
