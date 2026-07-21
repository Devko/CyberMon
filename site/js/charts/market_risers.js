// Market 2 — YoY risers & fallers. Contract: site/data/market_hype.json
// (shared by all three market sections; market.js fetches it once).
// Sortable HTML table (same pattern as cna.js): one row per (term, source)
// pair with a non-null yoy entry, plus top riser / faller stat cards.
import { editorial, tpl } from "../editorial.js";
import { el, clear } from "../dom.js";
import { fmtInt } from "../theme.js";

const SOURCE_LABELS = {
  gdelt: "GDELT",
  hn: "Hacker News",
  arxiv: "arXiv",
  wiki: "Wikipedia",
  edgar: "SEC EDGAR",
};

// Visual cap for the diverging in-cell bars: one 900% outlier must not
// flatten every other bar. Values beyond the cap clip and say so via title.
const BAR_CAP_PCT = 300;

const fmtSigned = (v) => `${v > 0 ? "+" : ""}${Number(v).toFixed(1)}%`;

// Honest empty state for launch-time payloads (backfill still running).
function noDataCard() {
  return el("div", "nodata-card", "Not enough data yet.");
}

function statCard(entry, labelText) {
  const card = el("div", "stat-card");
  if (!entry || entry.pct_change === null || entry.pct_change === undefined) {
    card.classList.add("is-empty");
    card.append(
      el("div", "stat-lead muted", "Not enough data yet."),
      el("div", "stat-note", labelText)
    );
    return card;
  }
  const ed = editorial.sections.risers;
  card.append(
    el("div", "stat-big" + (entry.pct_change > 0 ? " accent" : ""), fmtSigned(entry.pct_change)),
    el("div", "stat-lead", tpl(ed.statTemplate, {
      label: entry.label,
      source: SOURCE_LABELS[entry.source] ?? entry.source,
    })),
    el("div", "stat-note", labelText)
  );
  return card;
}

const COLS = [
  { key: "label", labelKey: "colTerm", numeric: false },
  { key: "source", labelKey: "colSource", numeric: false },
  { key: "pct_change", labelKey: "colChange", numeric: true, bar: true },
  { key: "n_latest_12m", labelKey: "colVolume", numeric: true },
];

export function render(slots, data) {
  const ed = editorial.sections.risers;

  // ---- headline stat cards ---------------------------------------------------
  const stats = el("div", "stat-grid");
  stats.append(
    statCard(data.headline?.top_riser, ed.statRiserLabel),
    statCard(data.headline?.top_faller, ed.statFallerLabel)
  );
  slots.stat.append(stats);

  // ---- flatten (term, source) pairs with a computed YoY ----------------------
  const rows = [];
  for (const t of data.terms || []) {
    for (const key of Object.keys(SOURCE_LABELS)) {
      const y = t.yoy?.[key];
      if (!y || y.pct_change === null || y.pct_change === undefined) continue;
      rows.push({
        label: t.label,
        source: SOURCE_LABELS[key],
        pct_change: Number(y.pct_change),
        n_latest_12m: y.n_latest_12m ?? 0,
      });
    }
  }

  slots.extra.append(el("p", "panel-note", ed.eligibilityNote));

  slots.chart.classList.remove("chart");
  if (!rows.length) {
    slots.chart.append(noDataCard());
    return;
  }

  const maxAbs = Math.max(...rows.map((r) => Math.abs(r.pct_change)));
  const scaleMax = Math.min(maxAbs, BAR_CAP_PCT) || 1;

  // ---- sortable table (cna.js pattern) ---------------------------------------
  const state = { key: "pct_change", dir: -1 }; // default: biggest riser first

  const wrap = el("div", "table-wrap");
  const table = el("table", "cna-table market-table");
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
        if (col.key === "label") {
          tr.append(el("td", "term-name", r.label));
        } else if (col.key === "source") {
          tr.append(el("td", "term-source", r.source));
        } else if (col.bar) {
          const td = el("td", "num");
          const cell = el("div", "cellbar cellbar-diverging");
          const clipped = Math.min(Math.abs(r.pct_change), BAR_CAP_PCT);
          const fill = el("div", r.pct_change >= 0 ? "pos" : "neg");
          fill.style.width = `${((clipped / scaleMax) * 50).toFixed(1)}%`;
          if (Math.abs(r.pct_change) > BAR_CAP_PCT) {
            cell.title = `bar clipped at ±${BAR_CAP_PCT}%`;
          }
          cell.append(fill, el("span", "cellbar-val", fmtSigned(r.pct_change)));
          td.append(cell);
          tr.append(td);
        } else {
          tr.append(el("td", "num", fmtInt(r[col.key])));
        }
      }
      tbody.append(tr);
    }
  }

  draw();
}
