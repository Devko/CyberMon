// Machine-Readable Advisories 2 — documents per provider per year of first
// release. Contract: site/data/csaf_adoption.json (sources[].by_year,
// years). A plain HTML grid: one row per counted provider, one column per
// year for the last eight years plus an "earlier" column and the total;
// cell shade is log-scaled to the largest cell (counts run from 1 to tens
// of thousands). The current year is partial and marked with an asterisk.
import { C, fmtInt } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";
import { fillRef, isMeasured, noEdition, shortName } from "./csaf_sources.js";

// Years shown individually, ending with the current year. A carousel slide
// (carousel.js) prints the table at enlarged type, so it keeps four.
const SPAN = 8;
const SPAN_SLIDE = 4;

function shade(n, max) {
  if (!n) return "";
  const t = max > 1 ? Math.log(n) / Math.log(max) : 1;
  return `rgba(255, 74, 63, ${(0.1 + 0.55 * t).toFixed(3)})`;
}

export function render(slots, data, refs) {
  const ed = editorial.sections.csaf_years;
  const rows = (data.sources || []).filter(isMeasured);
  const current = data.current_year;
  if (!rows.length || !(data.years || []).length) {
    noEdition(slots, ed.nodata, refs);
    return;
  }
  const span = slots.panel.closest(".slide") ? SPAN_SLIDE : SPAN;
  const first = current - span + 1;
  const years = Array.from({ length: span }, (_, i) => first + i);

  const count = (byYear, y) => byYear.find((e) => e.year === y)?.n ?? 0;
  const before = (byYear) => byYear.filter((e) => e.year < first).reduce((a, e) => a + e.n, 0);
  const totalRow = { name: ed.rowTotal, by_year: data.years, documents: data.totals.documents };
  const curYear = data.years.find((e) => e.year === current);

  // Caption: who dominates the current year.
  const topCurrent = rows
    .map((r) => ({ r, n: count(r.by_year, current) }))
    .sort((a, b) => b.n - a.n)[0];
  const curN = curYear?.n ?? 0;
  fillRef(refs?.caption, {
    from: first,
    to: current,
    top_name: shortName(topCurrent?.r.name ?? ""),
    top_current: curN ? `${((100 * (topCurrent?.n ?? 0)) / curN).toFixed(1)}%` : editorial.ui.na,
    current: fmtInt(curN),
    current_year: current,
  });
  fillRef(refs?.methodText, { undated: fmtInt(data.totals.undated) });
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) noteEl.textContent = tpl(ed.note, { current_year: current });

  const max = Math.max(1, ...rows.flatMap((r) => [
    before(r.by_year), ...years.map((y) => count(r.by_year, y))]));

  slots.chart.classList.remove("chart", "chart-tall");
  const wrap = el("div", "table-wrap");
  const table = el("table", "cna-table csaf-grid");
  const head = el("tr");
  head.append(el("th", null, ed.colSource));
  head.append(el("th", "num", tpl(ed.colBefore, { year: first })));
  for (const y of years) head.append(el("th", "num", y === current ? `${y}*` : String(y)));
  head.append(el("th", "num", ed.colTotal));
  const thead = el("thead");
  thead.append(head);

  const cell = (n, shaded) => {
    const td = el("td", "num", n ? fmtInt(n) : "");
    if (shaded && n) td.style.background = shade(n, max);
    return td;
  };
  const tbody = el("tbody");
  for (const r of rows) {
    const tr = el("tr");
    const th = el("th", "csaf-name", shortName(r.name));
    th.scope = "row";
    tr.append(th, cell(before(r.by_year), true));
    for (const y of years) tr.append(cell(count(r.by_year, y), true));
    tr.append(cell(r.documents, false));
    tbody.append(tr);
  }
  const tfoot = el("tfoot");
  const sum = el("tr", "csaf-sum");
  const sumTh = el("th", "csaf-name", totalRow.name);
  sumTh.scope = "row";
  sum.append(sumTh, cell(before(totalRow.by_year), false));
  for (const y of years) sum.append(cell(count(totalRow.by_year, y), false));
  sum.append(cell(totalRow.documents, false));
  const prov = el("tr", "csaf-sum");
  const provTh = el("th", "csaf-name", ed.rowProviders);
  provTh.scope = "row";
  const providersBefore = rows.filter((r) => before(r.by_year) > 0).length;
  prov.append(provTh, cell(providersBefore, false));
  for (const y of years) prov.append(cell(data.years.find((e) => e.year === y)?.providers ?? 0, false));
  prov.append(cell(rows.length, false));
  tfoot.append(sum, prov);
  table.append(thead, tbody, tfoot);
  wrap.append(table);
  slots.chart.append(wrap);
  slots.chart.style.color = C.ink;
}
