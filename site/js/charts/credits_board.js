// 03 — the finder board. Contract: site/data/ai_credits.json (board).
// A sortable HTML table (no ECharts), mirroring charts/naming_board.js: the
// counted-CVE bar in cell, each finder's own severity strip, how many records
// name the AI system itself, and what the kind's counting rule leaves out.
import { editorial, tpl } from "../editorial.js";
import { el, clear } from "../dom.js";
import { sortHeader } from "../ui.js";
import { fmtInt, fmtPct } from "../theme.js";
import { sevStrip } from "./credits_sev.js";

const seriousPct = (r) =>
  r.counted ? (100 * (r.severity.critical + r.severity.high)) / r.counted : null;

const COLS = [
  { key: "label", labelKey: "colFinder", numeric: false, sortable: true },
  { key: "counted", labelKey: "colCounted", numeric: true, sortable: true },
  { key: "severity", labelKey: "colSeverity", numeric: false, sortable: false },
  { key: "serious", labelKey: "colSerious", numeric: true, sortable: true },
  { key: "system", labelKey: "colSystem", numeric: true, sortable: true },
  { key: "uncounted", labelKey: "colNotCounted", numeric: true, sortable: true },
  { key: "kev", labelKey: "colKev", numeric: true, sortable: true },
  { key: "first_month", labelKey: "colSince", numeric: false, sortable: true },
  { key: "cnas", labelKey: "colCnas", numeric: false, sortable: false },
];

// The uncounted number, with its make-up on hover: a lab named without its
// model, and/or anyone credited only for the fix (tier "fix").
function uncountedCell(r, ed) {
  const td = el("td", "num", fmtInt(r.uncounted));
  if (r.uncounted) {
    const named = r.uncounted - r.fix;
    const parts = [];
    if (named > 0) parts.push(tpl(ed.uncountedNamed, { n: fmtInt(named) }));
    if (r.fix) parts.push(tpl(ed.uncountedFix, { n: fmtInt(r.fix) }));
    td.title = parts.join(" · ");
  }
  return td;
}

export function render(slots, data) {
  const ed = editorial.sections.credits_board;
  const sevLabels = editorial.sections.credits_funnel.severityLabels;
  slots.chart.classList.remove("chart", "chart-tall");

  if (!data.board.length) {
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }

  // "not counted" = matched but outside the kind's rule: a lab named without
  // its model, or anyone credited only for the fix (tier "fix").
  const rows = data.board.map((r) => ({
    ...r, serious: seriousPct(r), uncounted: r.cves - r.counted,
  }));
  const maxCounted = Math.max(1, ...rows.map((r) => r.counted));

  const state = { key: "counted", dir: -1 }; // contract default sort
  const wrap = el("div", "table-wrap");
  const table = el("table", "cna-table credits-table");
  const thead = el("thead");
  const headRow = el("tr");
  const tbody = el("tbody");

  const ths = COLS.map((col) => {
    const th = el("th", col.numeric ? "num" : "", ed[col.labelKey]);
    if (col.sortable) {
      sortHeader(th, () => {
        if (state.key === col.key) state.dir = -state.dir;
        else { state.key = col.key; state.dir = col.numeric ? -1 : 1; }
        draw();
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
      const cmp = typeof av === "number" || typeof bv === "number"
        ? (av ?? -1) - (bv ?? -1)
        : String(av).localeCompare(String(bv));
      // Stable tiebreak: counted (desc), then label.
      return cmp * state.dir || (b.counted - a.counted)
        || a.label.localeCompare(b.label);
    });

    clear(tbody);
    for (const r of rows) {
      const tr = el("tr");

      const tdName = el("td", "cna-name");
      tdName.append(
        el("span", "cna-short", r.label), " ",
        el("span", "kind-tag" + (r.kind === "llm" ? " is-llm" : ""), ed.kindShort[r.kind])
      );
      tr.append(tdName);

      const tdCount = el("td", "num");
      const cell = el("div", "cellbar");
      cell.style.setProperty("--cellbar-val-w", "5ch"); // "1,234"
      const fill = el("div", "cellbar-fill");
      fill.style.width = `${((r.counted / maxCounted) * 100).toFixed(1)}%`;
      cell.append(fill, el("span", "cellbar-val", fmtInt(r.counted)));
      tdCount.append(cell);
      tr.append(tdCount);

      const tdSev = el("td");
      if (r.counted) tdSev.append(sevStrip(r.severity, sevLabels));
      else tdSev.append(el("span", "muted", "—"));
      tr.append(tdSev);

      tr.append(
        el("td", "num", fmtPct(r.serious)),
        el("td", "num", fmtInt(r.system)),
        uncountedCell(r, ed),
        el("td", "num" + (r.kev ? " accent" : ""), fmtInt(r.kev)),
        el("td", "mono", r.first_month),
        r.top_cnas.length
          ? el("td", "cna-list",
            r.top_cnas.map((c) => `${c.cna} ${fmtInt(c.n)}`).join(" · "))
          : el("td", "cna-list muted", "—")
      );
      tbody.append(tr);
    }
  }

  draw();
}
