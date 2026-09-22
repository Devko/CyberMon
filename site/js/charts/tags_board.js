// Record Tags 2 — who sets the tags: a board per tag (toggle), each CNA's
// tagged records with its share of the tag (bar in cell) and the share of
// its own records it tagged. Contract: site/data/cve_tags.json (shared;
// tags.js fetches it once). HTML table, no ECharts (concentration_rejection
// pattern).
import { editorial, tpl } from "../editorial.js";
import { el, clear } from "../dom.js";
import { mkToggle } from "../ui.js";
import { fmtInt, fmtPct } from "../theme.js";

const TAGS = ["unsupported-when-assigned", "disputed"];

export function render(slots, data) {
  const ed = editorial.sections.tags_board;
  const labels = editorial.sections.tags_trend.tagLabels;
  const boards = data.boards || {};
  const w = data.window || {};

  const context = el("div", "table-context");
  slots.stat.append(context);
  slots.chart.classList.remove("chart");
  const body = el("div");
  slots.chart.append(body);

  const draw = (tag) => {
    const board = boards[tag] || {};
    context.textContent = tpl(ed.windowTemplate, {
      from: w.from ?? "?", to: w.to ?? "?",
      min_n: fmtInt(board.min_n), cnas: fmtInt(board.cna_count),
    });
    clear(body);
    const rows = board.cnas || [];
    if (!rows.length) {
      body.append(el("div", "nodata-card", ed.nodata));
      return;
    }
    const wrap = el("div", "table-wrap");
    const table = el("table", "cna-table");
    const thead = el("thead");
    const head = el("tr");
    head.append(el("th", "", ed.colCna), el("th", "num", ed.colN),
                el("th", "num", ed.colShare), el("th", "num", ed.colRate));
    thead.append(head);
    const tbody = el("tbody");
    for (const r of rows) {
      const tr = el("tr");
      const name = el("td", "cna-name");
      name.append(el("span", "cna-short", r.cna));
      const shareTd = el("td", "num");
      const cell = el("div", "cellbar");
      const fill = el("div", "cellbar-fill" + (tag === TAGS[0] ? " accent" : ""));
      fill.style.width = `${Math.max(0, Math.min(100, r.share_pct)).toFixed(1)}%`;
      cell.append(fill, el("span", "cellbar-val", fmtPct(r.share_pct)));
      shareTd.append(cell);
      tr.append(name, el("td", "num", fmtInt(r.n)), shareTd,
                el("td", "num", fmtPct(r.rate_pct)));
      tbody.append(tr);
    }
    table.append(thead, tbody);
    wrap.append(table);
    body.append(wrap);
  };

  slots.controls.append(mkToggle(TAGS.map((t) => labels[t]), (i) => draw(TAGS[i])));
  draw(TAGS[0]);
}
