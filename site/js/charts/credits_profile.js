// 02 — labs vs vendors vs everyone, side by side. Contract:
// site/data/ai_credits.json (profile + the funnels' high-or-critical share).
// Plain HTML: one row per metric, a bar each for labs and vendors on a scale
// shared within the row, and the baseline drawn INTO both bars as a tick —
// the reader compares each bar to its tick, never labs to vendors by eye
// across different axes. The baseline's own value sits in the last column.
import { C, fmtInt, fmtPct } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

const KINDS = ["llm", "vendor"];
const fmtNum = (v) => (Number.isFinite(v) ? v.toFixed(1) : "—");

// key: profile field (or a function of the payload); max: fixed scale, or
// null to scale the row to its own largest value (tiny shares stay legible).
const ROWS = [
  { id: "median_cvss", get: (p) => p.median_cvss, fmt: fmtNum, max: 10 },
  { id: "serious", get: (p, f) => f.high_or_critical_pct, fmt: fmtPct, max: 100 },
  { id: "memory_pct", get: (p) => p.memory_pct, fmt: fmtPct, max: null },
  { id: "top_cwe", text: true },
  { id: "median_epss_pctile", get: (p) => p.median_epss_pctile, fmt: fmtNum, max: 100 },
  { id: "poc_pct", get: (p) => p.poc_pct, fmt: fmtPct, max: null },
  { id: "kev_pct", get: (p) => p.kev_pct, fmt: fmtPct, max: null },
  { id: "cna_scored_pct", get: (p) => p.cna_scored_pct, fmt: fmtPct, max: 100 },
];

const pos = (v, max) => `${Math.max(0, Math.min(100, max ? (v / max) * 100 : 0)).toFixed(1)}%`;

function barCell(value, baseline, max, fmt, color) {
  const td = el("td", "profile-cell");
  if (!Number.isFinite(value)) {
    td.append(el("span", "muted", "—"));
    return td;
  }
  const track = el("div", "profile-track");
  const fill = el("div", "profile-fill");
  fill.style.width = pos(value, max);
  fill.style.background = color;
  track.append(fill);
  if (Number.isFinite(baseline)) {
    const tick = el("div", "profile-tick");
    tick.style.left = pos(baseline, max);
    track.append(tick);
  }
  td.append(track, el("span", "profile-val", fmt(value)));
  return td;
}

export function render(slots, data) {
  const ed = editorial.sections.credits_profile;
  slots.chart.classList.remove("chart", "chart-tall");
  const profile = data.profile;
  if (!profile) {
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }
  const funnels = { llm: data.kinds.llm.funnel, vendor: data.kinds.vendor.funnel, baseline: data.baseline };
  const colors = { llm: C.sev.high, vendor: C.versions.v4 };
  const cweName = (id) => (ed.cweNames[id] ? `${ed.cweNames[id]} (${id})` : id);

  const wrap = el("div", "table-wrap");
  const table = el("table", "cna-table profile-table");
  const head = el("tr");
  head.append(el("th", null, ""));
  for (const name of [...KINDS, "baseline"]) {
    const th = el("th", null, ed.columns[name]);
    th.append(el("span", "profile-n", tpl(ed.nTemplate, { n: fmtInt(profile[name].n) })));
    head.append(th);
  }
  const thead = el("thead");
  thead.append(head);
  const tbody = el("tbody");

  for (const row of ROWS) {
    const tr = el("tr");
    const th = el("th", "profile-metric", ed.rows[row.id]);
    th.scope = "row";
    tr.append(th);
    if (row.text) {
      for (const name of [...KINDS, "baseline"]) {
        const top = profile[name].top_cwe;
        const td = el("td", "profile-cell profile-text");
        if (top) td.append(cweName(top.cwe), el("span", "muted", ` ${fmtPct(top.pct)}`));
        else td.append(el("span", "muted", "—"));
        tr.append(td);
      }
    } else {
      const values = Object.fromEntries([...KINDS, "baseline"].map(
        (name) => [name, row.get(profile[name], funnels[name])]));
      const finite = Object.values(values).filter(Number.isFinite);
      // A self-scaled row gets 15% headroom so the largest bar never looks
      // like it hit a ceiling; an all-zero row still needs a non-zero scale.
      const max = row.max ?? (Math.max(0, ...finite) * 1.15 || 1);
      for (const kind of KINDS) {
        tr.append(barCell(values[kind], values.baseline, max, row.fmt, colors[kind]));
      }
      const base = el("td", "profile-cell profile-base");
      base.append(el("span", "profile-val", Number.isFinite(values.baseline)
        ? row.fmt(values.baseline) : "—"));
      tr.append(base);
    }
    tbody.append(tr);
  }
  table.append(thead, tbody);
  wrap.append(table);
  slots.chart.append(wrap);

  const legend = el("p", "panel-note");
  legend.append(ed.tickNote);
  slots.extra.append(legend);
}
