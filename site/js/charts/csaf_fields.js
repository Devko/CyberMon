// Machine-Readable Advisories 3 — field completeness in the sampled
// documents. Contract: site/data/csaf_adoption.json (sources[].fields,
// sources[].sample_n, totals.by_group). Plain HTML: one row per sampled
// provider, one column per field, each cell a percentage with a bar drawn
// behind it on a fixed 0–100% scale; the bottom rows pool every sampled
// document by type (VEX / security advisory / other).
import { fmtInt, fmtPct } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";
import { fillRef, isMeasured, noEdition, shortName } from "./csaf_sources.js";

const FIELDS = ["cvss", "cwe", "product_tree", "remediation"];
const POOLED = ["advisory", "vex", "other"];

function pctCell(v) {
  const td = el("td", "num csaf-pct");
  if (!Number.isFinite(v)) {
    td.textContent = "—";
    return td;
  }
  td.textContent = fmtPct(v);
  const w = Math.max(0, Math.min(100, v)).toFixed(1);
  td.style.background =
    `linear-gradient(to right, rgba(222, 215, 194, 0.16) ${w}%, transparent ${w}%)`;
  return td;
}

export function render(slots, data, refs) {
  const ed = editorial.sections.csaf_fields;
  const legend = editorial.sections.csaf_sources.legend;
  const rows = (data.sources || []).filter((r) => isMeasured(r) && r.fields);
  const t = data.totals || {};
  if (!rows.length) {
    noEdition(slots, ed.nodata, refs);
    return;
  }
  fillRef(refs?.caption, { k: fmtInt(data.sampling?.k), sample_n: fmtInt(t.sample_n) });
  fillRef(refs?.methodText, { refresh: fmtInt(data.sampling?.refresh_cap) });

  slots.chart.classList.remove("chart", "chart-tall");
  const wrap = el("div", "table-wrap");
  const table = el("table", "cna-table csaf-fields");
  const head = el("tr");
  head.append(el("th", null, ed.colSource), el("th", "num", ed.colSample));
  for (const f of FIELDS) head.append(el("th", "num", ed.cols[f]));
  const thead = el("thead");
  thead.append(head);

  const tbody = el("tbody");
  for (const r of rows) {
    const tr = el("tr");
    const th = el("th", "csaf-name", shortName(r.name));
    th.scope = "row";
    tr.append(th, el("td", "num muted", tpl(ed.sampleOf, {
      n: fmtInt(r.sample_n), total: fmtInt(r.documents) })));
    for (const f of FIELDS) tr.append(pctCell(r.fields[f]));
    tbody.append(tr);
  }
  const tfoot = el("tfoot");
  for (const g of POOLED) {
    const pooled = t.by_group?.[g];
    if (!pooled) continue;
    const tr = el("tr", "csaf-sum");
    const th = el("th", "csaf-name", tpl(ed.pooledLabel, { label: legend[g] }));
    th.scope = "row";
    tr.append(th, el("td", "num muted", fmtInt(pooled.n)));
    for (const f of FIELDS) tr.append(pctCell(pooled[f]));
    tfoot.append(tr);
  }
  table.append(thead, tbody, tfoot);
  wrap.append(table);
  slots.chart.append(wrap);
}
