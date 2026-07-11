// Rescores 3 — who edits. Contract: site/data/rescore_log.json (cna_board
// section). Sortable HTML table (guards_recidivism.js pattern): CNAs by
// logged rescore events, split into raised and lowered. The context line
// above the board states how much record it stands on — the board is
// expected to launch sparse and fill at the speed the ecosystem edits.
import { editorial, tpl } from "../editorial.js";
import { el, clear } from "../dom.js";
import { fmtInt } from "../theme.js";

const COLS = [
  { key: "cna", labelKey: "colCna", numeric: false },
  { key: "rescores", labelKey: "colRescores", numeric: true, bar: true },
  { key: "up", labelKey: "colUp", numeric: true },
  { key: "down", labelKey: "colDown", numeric: true },
];

export function render(slots, data) {
  const ed = editorial.sections.editors;
  const board = data.cna_board;
  const catalog = data.catalog;

  const context = catalog.events_total > 0
    ? tpl(ed.boardNote, {
        events: fmtInt(catalog.events_total),
        first_date: catalog.first_observed,
      })
    : ed.boardNoteEmpty;
  slots.stat.append(
    el("div", "table-context", tpl(ed.windowTemplate, {
      context,
      min_events: board.min_events ?? "?",
    }))
  );

  const rows = [...(board.cnas || [])];
  slots.chart.classList.remove("chart");
  if (!rows.length) {
    slots.chart.append(el("div", "nodata-card", ed.emptyBoard));
    return;
  }
  const maxRescores = Math.max(...rows.map((r) => r.rescores));

  const state = { key: "rescores", dir: -1 }; // default: rescores, descending

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
        } else if (col.key === "rescores") {
          const td = el("td", "num");
          const cell = el("div", "cellbar");
          const fill = el("div", "cellbar-fill accent");
          fill.style.width = `${((100 * r.rescores) / maxRescores).toFixed(1)}%`;
          cell.append(fill, el("span", "cellbar-val", fmtInt(r.rescores)));
          td.append(cell);
          tr.append(td);
        } else {
          const td = el("td", "num");
          td.textContent = fmtInt(r[col.key]);
          tr.append(td);
        }
      }
      tbody.append(tr);
    }
  }

  draw();
}
