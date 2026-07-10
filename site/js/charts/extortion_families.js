// Extortion 3 — family concentration board. Contract:
// site/data/extortion_ledger.json (shared fetch, see extortion.js).
// A sortable HTML table (cna.js idiom): top labeled families by all-time
// confirmed USD, with payment counts and first/last seen years. The
// export's "Unlabeled" bucket is never a row here — it is disclosed in the
// panel note (ranking a reporting gap would crown it the leading brand).
import { editorial, tpl } from "../editorial.js";
import { el, clear } from "../dom.js";
import { fmtInt, fmtPct } from "../theme.js";
import { fmtUSD, fmtUSDCompact } from "./extortion_fmt.js";

const COLS = [
  { key: "family", labelKey: "colFamily", numeric: false },
  { key: "usd", labelKey: "colUsd", numeric: true, bar: true },
  { key: "payments", labelKey: "colPayments", numeric: true },
  { key: "first_year", labelKey: "colFirst", numeric: true },
  { key: "last_year", labelKey: "colLast", numeric: true },
];

function fmtCell(col, v) {
  if (col.key === "usd") return fmtUSD(v);
  if (col.key === "payments") return fmtInt(v);
  return String(v);
}

export function render(slots, data) {
  const ed = editorial.sections.families;
  const rows = [...(data.families?.top || [])];
  if (!rows.length) {
    slots.panel.querySelector(".panel-note")?.remove();
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // ---- unattributed disclosure (panel-note template, kev_latency idiom) ----
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    const un = data.families.unattributed || { usd: 0, payments: 0 };
    const total = data.catalog?.total_usd || 0;
    noteEl.textContent = tpl(ed.note, {
      unattributed_usd: fmtUSDCompact(un.usd),
      unattributed_pct: total ? fmtPct((100 * un.usd) / total) : "?",
    });
  }

  // ---- table ------------------------------------------------------------------
  const state = { key: "usd", dir: -1 }; // contract default sort
  const maxUsd = Math.max(...rows.map((r) => r.usd), 1);

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
        if (!col.numeric) {
          const td = el("td", "cna-name");
          td.append(el("span", "cna-short", r.family));
          tr.append(td);
        } else {
          const td = el("td", "num");
          if (col.bar) {
            const cell = el("div", "cellbar");
            const fill = el("div", "cellbar-fill accent");
            fill.style.width = `${((100 * r.usd) / maxUsd).toFixed(1)}%`;
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

  // ---- pooled remainder (footer line under the board) --------------------------
  const other = data.families.other || { families: 0, usd: 0, payments: 0 };
  if (other.families > 0) {
    slots.extra.append(el("p", "table-context", tpl(ed.otherTemplate, {
      families: fmtInt(other.families),
      usd: fmtUSDCompact(other.usd),
      payments: fmtInt(other.payments),
    })));
  }
}
