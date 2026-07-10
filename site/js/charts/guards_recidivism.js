// Guards 2 — recidivism board. Contract: site/data/kev_guards.json
// (shared by all three guards sections; guards.js fetches it once).
// Sortable HTML table (concentration_rejection.js pattern): vendors by
// total KEV entries, security-majority rows flagged, with first/last
// listing dates and the median gap between consecutive listings.
import { editorial, tpl } from "../editorial.js";
import { el, clear } from "../dom.js";
import { fmtInt } from "../theme.js";

const COLS = [
  { key: "vendor", labelKey: "colVendor", numeric: false },
  { key: "entries", labelKey: "colEntries", numeric: true, bar: true },
  { key: "security_entries", labelKey: "colSecurity", numeric: true },
  { key: "first_added", labelKey: "colFirst", numeric: false, mono: true },
  { key: "last_added", labelKey: "colLast", numeric: false, mono: true },
  { key: "median_gap_days", labelKey: "colGap", numeric: true },
];

// A row is visually flagged as a security vendor when at least half its
// entries classify as security products (the payload carries the pct).
const FLAG_THRESHOLD = 50;

function fmtGap(v) {
  return v === null || v === undefined ? "—" : `${fmtInt(Math.round(v))}d`;
}

export function render(slots, data) {
  const ed = editorial.sections.recidivism;

  slots.stat.append(
    el("div", "table-context", tpl(ed.windowTemplate, {
      min_vendor_entries: data.min_vendor_entries ?? "?",
    }))
  );

  const rows = [...(data.vendors || [])];
  slots.chart.classList.remove("chart");
  if (!rows.length) {
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }
  const maxEntries = Math.max(...rows.map((r) => r.entries));

  const state = { key: "entries", dir: -1 }; // default: entries, descending

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
      // null gaps (single dated entry) always sort to the bottom
      if (av === null || av === undefined) return 1;
      if (bv === null || bv === undefined) return -1;
      const cmp = typeof av === "number" ? av - bv : String(av).localeCompare(String(bv));
      return cmp * state.dir;
    });

    clear(tbody);
    for (const r of rows) {
      const tr = el("tr");
      const flagged = r.pct_security >= FLAG_THRESHOLD;
      for (const col of COLS) {
        if (col.key === "vendor") {
          const td = el("td", "cna-name");
          td.append(el("span", "cna-short" + (flagged ? " accent" : ""), r.vendor));
          if (flagged) td.append(el("span", "cna-org", ed.securityFlagLabel));
          tr.append(td);
        } else if (col.key === "entries") {
          const td = el("td", "num");
          const cell = el("div", "cellbar");
          const fill = el("div", "cellbar-fill" + (flagged ? " accent" : ""));
          fill.style.width = `${((100 * r.entries) / maxEntries).toFixed(1)}%`;
          cell.append(fill, el("span", "cellbar-val", fmtInt(r.entries)));
          td.append(cell);
          tr.append(td);
        } else {
          const td = el("td", col.numeric ? "num" : "mono");
          td.textContent = col.key === "median_gap_days"
            ? fmtGap(r.median_gap_days)
            : String(r[col.key]);
          tr.append(td);
        }
      }
      tbody.append(tr);
    }
  }

  draw();
}
