// Concentration 3 — rejection-rate leaderboard. Contract:
// site/data/cna_concentration.json (shared by all three concentration
// sections; concentration.js fetches it once). Sortable HTML table with
// bar-in-cell visualization (cna.js pattern; no ECharts needed).
import { editorial, tpl } from "../editorial.js";
import { el, clear } from "../dom.js";
import { fmtInt, fmtPct } from "../theme.js";

const COLS = [
  { key: "cna", labelKey: "colCna", numeric: false },
  { key: "total", labelKey: "colTotal", numeric: true },
  { key: "rejected", labelKey: "colRejected", numeric: true },
  { key: "rejected_rate_pct", labelKey: "colRate", numeric: true, bar: (v) => v, accent: true },
];

function fmtCell(col, v) {
  if (col.key === "rejected_rate_pct") return fmtPct(v);
  if (typeof v === "number") return fmtInt(v);
  return String(v);
}

export function render(slots, data) {
  const ed = editorial.sections.rejection;
  const board = data.rejection_leaderboard || {};

  // window / minimum caption line, filled from the payload (cna.js pattern)
  slots.stat.append(
    el("div", "table-context", tpl(ed.windowTemplate, {
      window_years: board.window_years ?? "?",
      min_total: Number.isFinite(board.min_total) ? fmtInt(board.min_total) : "?",
    }))
  );

  const rows = [...(board.cnas || [])];
  slots.chart.classList.remove("chart");
  if (!rows.length) {
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  const state = { key: "rejected_rate_pct", dir: -1 }; // default: rate, descending

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
          td.append(el("span", "cna-short", r.cna));
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
