// EPSS Volatility 3 — biggest single-day movers. Contract:
// site/data/epss_volatility.json (movers section). Sortable HTML table
// (rescore_editors.js pattern): the largest single-night RAW probability
// moves on record — one per observed night — because when EPSS actually
// changes its mind (not just reshuffles ranks), this is how far. The
// context line above the board states how much record it stands on; the
// board is expected to launch sparse and fill at the speed the model
// actually moves.
import { editorial, tpl } from "../editorial.js";
import { el, clear } from "../dom.js";
import { fmtInt } from "../theme.js";

const COLS = [
  { key: "cve", labelKey: "colCve", numeric: false },
  { key: "observed_date", labelKey: "colDate", numeric: false },
  { key: "shift", labelKey: "colShift", numeric: false },
  { key: "delta", labelKey: "colDelta", numeric: true, bar: true },
];

const pct = (p) => `${(p * 100).toFixed(1)}%`;
const absDelta = (v) => Math.abs(v);

export function render(slots, data) {
  const ed = editorial.sections.epssvol_movers;
  const movers = data.movers;
  const catalog = data.catalog;

  const rows = [...(movers.entries || [])];

  slots.stat.append(
    el("div", "table-context", tpl(ed.windowTemplate, {
      shown: fmtInt(rows.length),
      min_delta: movers.min_delta.toFixed(2),
      context: catalog.first_observed
        ? tpl(ed.boardNote, {
            days: fmtInt(catalog.days_observed),
            first_date: catalog.first_observed,
          })
        : ed.boardNoteEmpty,
    }))
  );

  slots.chart.classList.remove("chart", "chart-tall");
  if (!rows.length) {
    slots.chart.append(el("div", "nodata-card", ed.emptyBoard));
    return;
  }
  const maxDelta = Math.max(...rows.map((r) => absDelta(r.delta)));

  const state = { key: "delta", dir: -1 }; // default: biggest move, descending

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
      // The board ranks by MAGNITUDE of move — the sign is shown in the
      // cell, not sorted on — so the delta column compares |delta|.
      const av = state.key === "delta" ? absDelta(a.delta) : a[state.key];
      const bv = state.key === "delta" ? absDelta(b.delta) : b[state.key];
      const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
      return cmp * state.dir || absDelta(b.delta) - absDelta(a.delta) || a.cve.localeCompare(b.cve);
    });

    clear(tbody);
    for (const r of rows) {
      const tr = el("tr");
      for (const col of COLS) {
        if (col.key === "cve") {
          const td = el("td", "cna-name");
          td.append(el("span", "cna-short", r.cve));
          tr.append(td);
        } else if (col.key === "observed_date") {
          const td = el("td", null);
          td.textContent = r.observed_date;
          tr.append(td);
        } else if (col.key === "shift") {
          const td = el("td", "num");
          td.textContent = `${pct(r.old)} → ${pct(r.new)}`;
          tr.append(td);
        } else {
          const up = r.delta >= 0;
          const td = el("td", "num");
          const cell = el("div", "cellbar");
          const fill = el("div", "cellbar-fill" + (up ? " accent" : ""));
          fill.style.width = `${((100 * absDelta(r.delta)) / maxDelta).toFixed(1)}%`;
          cell.append(fill, el("span", "cellbar-val",
            `${up ? "▲" : "▼"} ${absDelta(r.delta).toFixed(3)}`));
          td.append(cell);
          tr.append(td);
        }
      }
      tbody.append(tr);
    }
  }

  draw();
}
