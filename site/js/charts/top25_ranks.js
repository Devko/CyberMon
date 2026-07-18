// Hero — the official CWE Top 25 with each class's OFFICIAL rank beside its
// MEASURED first-listed-CWE prevalence rank: the divergence. Contract:
// site/data/cwe_top25.json. A sortable HTML table with a bar-in-cell for
// prevalence share (no ECharts needed), mirroring the naming board.
import { editorial, tpl } from "../editorial.js";
import { el, clear } from "../dom.js";
import { fmtInt, fmtPct } from "../theme.js";

// defaultDir: which way a column sorts when first clicked. Ranks and the
// weakness name read best ascending; prevalence and KEV volume, descending.
const COLS = [
  { key: "name", labelKey: "colWeakness", numeric: false, sortable: true, defaultDir: 1 },
  { key: "official_rank", labelKey: "colOfficial", numeric: true, sortable: true, defaultDir: 1 },
  { key: "measured_rank", labelKey: "colMeasured", numeric: true, sortable: true, defaultDir: 1 },
  { key: "measured_share", labelKey: "colPrevalence", numeric: true, sortable: true,
    bar: true, accent: true, defaultDir: -1 },
  { key: "kev_n", labelKey: "colKev", numeric: true, sortable: true, defaultDir: -1 },
];

// null measured_rank (class never observed in the window) sorts to the bottom.
const rankVal = (v) => (v == null ? Number.POSITIVE_INFINITY : v);

export function render(slots, data) {
  const ed = editorial.sections.top25_ranks;
  const h = data.headline;
  slots.chart.classList.remove("chart", "chart-tall");

  if (!h || !data.ranks?.length) {
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }

  const rows = data.ranks.slice();
  const maxShare = Math.max(...rows.map((r) => r.measured_share), 0.1);

  slots.stat.append(el("div", "table-context", tpl(ed.statTemplate, {
    year: h.official_year,
    start: h.window_start,
    end: h.window_end,
    in_top25: h.in_measured_top25,
    total: rows.length,
  })));

  const state = { key: "official_rank", dir: 1 }; // contract default: list order
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
        else { state.key = col.key; state.dir = col.defaultDir; }
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
        ? (state.dir === 1 ? "ascending" : "descending") : "none");
    });

    rows.sort((a, b) => {
      let av = a[state.key], bv = b[state.key];
      let cmp;
      if (state.key === "measured_rank") {
        cmp = rankVal(av) - rankVal(bv);
      } else if (typeof av === "number") {
        cmp = av - bv;
      } else {
        cmp = String(av).localeCompare(String(bv));
      }
      // Stable tiebreak by official rank so equal cells keep list order.
      return cmp * state.dir || (a.official_rank - b.official_rank);
    });

    clear(tbody);
    for (const r of rows) {
      const tr = el("tr");

      const tdName = el("td", "cna-name");
      tdName.append(el("span", "cna-short", r.name));
      tdName.append(el("span", "alias-list", r.cwe));
      tr.append(tdName);

      tr.append(el("td", "num", `#${fmtInt(r.official_rank)}`));

      const tdMeasured = el("td", "num");
      if (r.measured_rank == null) {
        const off = el("span", "muted", ed.unranked);
        off.title = ed.unrankedTitle;
        tdMeasured.append(off);
      } else {
        tdMeasured.append(`#${fmtInt(r.measured_rank)}`);
      }
      tr.append(tdMeasured);

      const tdShare = el("td", "num");
      const cell = el("div", "cellbar");
      const fill = el("div", "cellbar-fill accent");
      fill.style.width =
        `${Math.max(0, Math.min(100, (r.measured_share / maxShare) * 100)).toFixed(1)}%`;
      cell.append(fill, el("span", "cellbar-val", fmtPct(r.measured_share)));
      tdShare.append(cell);
      tr.append(tdShare);

      const tdKev = el("td", "num" + (r.kev_n === 0 ? " muted" : ""));
      tdKev.textContent = fmtInt(r.kev_n);
      tr.append(tdKev);

      tbody.append(tr);
    }
  }

  draw();
}
