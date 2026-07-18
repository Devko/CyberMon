// Hero — most-renamed leaderboard. Contract: site/data/naming.json
// A sortable HTML table with bar-in-cell visualization (no ECharts needed),
// mirroring the CNA rubber-stamp board (charts/cna.js).
import { editorial, tpl } from "../editorial.js";
import { el, clear } from "../dom.js";
import { fmtInt } from "../theme.js";

// The board can run to ~100 groups; the page shows the most-renamed slice and
// says so. The full ranking lives in data/naming.json for anyone who wants it.
const TOP_N = 30;

const COLS = [
  { key: "name", labelKey: "colActor", numeric: false, sortable: true },
  { key: "alt_count", labelKey: "colCount", numeric: true, sortable: true,
    bar: true, accent: true },
  { key: "aliases", labelKey: "colAliases", numeric: false, sortable: false },
];

export function render(slots, data) {
  const ed = editorial.sections.naming_board;
  const h = data.headline;
  slots.chart.classList.remove("chart", "chart-tall");

  if (!h || !data.groups.length) {
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }

  const rows = data.groups.slice(0, TOP_N);
  const maxAlt = h.most_renamed_alt_count || 1;

  slots.stat.append(el("div", "table-context", tpl(ed.statTemplate, {
    version: data.version,
    shown: rows.length,
    with_aliases: fmtInt(h.groups_with_aliases),
    total: fmtInt(h.total_groups),
  })));

  const state = { key: "alt_count", dir: -1 }; // contract default sort
  const wrap = el("div", "table-wrap");
  const table = el("table", "cna-table");
  const thead = el("thead");
  const headRow = el("tr");
  const tbody = el("tbody");

  const ths = COLS.map((col) => {
    const th = el("th", col.numeric ? "num" : "", ed[col.labelKey]);
    if (col.sortable) {
      th.tabIndex = 0;
      th.setAttribute("role", "button");
      const activate = () => {
        if (state.key === col.key) state.dir = -state.dir;
        else { state.key = col.key; state.dir = col.numeric ? -1 : 1; }
        draw();
      };
      th.addEventListener("click", activate);
      th.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); activate(); }
      });
    }
    headRow.append(th);
    return { th, col };
  });
  thead.append(headRow);
  table.append(thead, tbody);
  wrap.append(table);
  slots.chart.append(wrap);

  function draw() {
    ths.forEach(({ th, col }) => {
      const active = col.sortable && col.key === state.key;
      th.classList.toggle("is-sorted", active);
      th.setAttribute("aria-sort", active
        ? (state.dir === -1 ? "descending" : "ascending") : "none");
    });

    rows.sort((a, b) => {
      const av = a[state.key], bv = b[state.key];
      const cmp = typeof av === "number"
        ? av - bv
        : String(av).localeCompare(String(bv));
      // Stable tiebreak by alternate count (desc) then name so equal-count
      // rows keep a deterministic order.
      return cmp * state.dir || (b.alt_count - a.alt_count)
        || a.name.localeCompare(b.name);
    });

    clear(tbody);
    for (const r of rows) {
      const tr = el("tr");

      const tdName = el("td", "cna-name");
      tdName.append(el("span", "cna-short", r.name));
      tr.append(tdName);

      const tdCount = el("td", "num");
      const cell = el("div", "cellbar");
      const fill = el("div", "cellbar-fill accent");
      fill.style.width =
        `${Math.max(0, Math.min(100, (r.alt_count / maxAlt) * 100)).toFixed(1)}%`;
      cell.append(fill, el("span", "cellbar-val", fmtInt(r.alt_count)));
      tdCount.append(cell);
      tr.append(tdCount);

      // The names themselves — the whole point of the board.
      tr.append(el("td", "alias-list", r.aliases.join(" · ")));

      tbody.append(tr);
    }
  }

  draw();
}
