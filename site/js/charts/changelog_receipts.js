// Changelog 3 — the receipts board. Contract: site/data/kev_changelog.json
// (shared; changelog.js fetches it once). Sortable HTML table
// (guards_recidivism.js pattern): the most-edited catalog entries, with
// the removals — a removed KEV entry is news — listed by name below.
import { editorial, tpl } from "../editorial.js";
import { el, clear } from "../dom.js";
import { fmtInt } from "../theme.js";

const COLS = [
  { key: "cve", labelKey: "colCve", numeric: false, mono: true },
  { key: "vendor", labelKey: "colVendor", numeric: false },
  { key: "product", labelKey: "colProduct", numeric: false },
  { key: "edits", labelKey: "colEdits", numeric: true, bar: true },
  { key: "last_change", labelKey: "colLast", numeric: false, mono: true },
];

export function render(slots, data) {
  const ed = editorial.sections.receipts;
  const board = data.board || {};

  const rows = [...(board.most_edited || [])];
  slots.chart.classList.remove("chart");
  if (!rows.length) {
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
  } else {
    const maxEdits = Math.max(...rows.map((r) => r.edits));
    const state = { key: "edits", dir: -1 }; // default: edits, descending

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
          if (col.key === "edits") {
            const td = el("td", "num");
            const cell = el("div", "cellbar");
            const fill = el("div", "cellbar-fill accent");
            fill.style.width = `${((100 * r.edits) / maxEdits).toFixed(1)}%`;
            cell.append(fill, el("span", "cellbar-val", fmtInt(r.edits)));
            td.append(cell);
            tr.append(td);
          } else {
            const td = el("td", col.mono ? "mono" : "");
            td.textContent = String(r[col.key] ?? "");
            tr.append(td);
          }
        }
        tbody.append(tr);
      }
    }

    draw();
  }

  // ---- the removals list (panel-extra slot) ---------------------------------
  const removals = board.removals || [];
  const extra = el("div", "removals");
  extra.append(el("p", "table-context", ed.removalsTitle));
  if (!removals.length) {
    extra.append(el("p", "muted", ed.noRemovals));
  } else {
    for (const r of removals) {
      const line = r.listed ? ed.removalRow : ed.removalRowUnlisted;
      extra.append(el("p", "mono", tpl(line, {
        cve: r.cve,
        vendor: r.vendor || "?",
        product: r.product || "?",
        listed: r.listed,
        removed: r.removed,
      })));
    }
  }
  slots.extra.append(extra);
}
