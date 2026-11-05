// Detection Rules 2 — the share of today's ATT&CK enterprise techniques that
// had entered ATT&CK and carried at least one Sigma rule, at each quarter
// end. Contract: site/data/sigma_coverage.json (quarters[].pct, coverage,
// attack). The line starts at the first quarter with an ATT&CK release in
// MITRE's index; the current, partial quarter is a hollow point. The y-axis
// runs from 0 to 100% so the size of the change is read honestly.
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid,
  fmtInt, fmtPct, escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";
import { fillRef, noEdition, quarterName, yearLabel } from "./sigma_shared.js";

export function render(slots, data, refs) {
  const ed = editorial.sections.sigma_coverage;
  const L = ed.labels;
  const cov = data.coverage || {};
  const attack = data.attack || {};
  const rows = (data.quarters || []).filter((q) => q.pct !== null && q.pct !== undefined);
  if (!rows.length || !cov.techniques) {
    noEdition(slots, ed.nodata, refs);
    return;
  }

  const today = data.as_of || (data.generated_at || "").slice(0, 10);
  const cat = data.catalog || {};
  fillRef(refs?.caption, { version: attack.version, date: today }, tpl);
  fillRef(refs?.methodText, {
    first_version: attack.first_version,
    first_released: attack.first_released,
    untagged: fmtInt((cat.rules ?? 0) - (cat.technique_tagged ?? 0)),
    rules: fmtInt(cat.rules),
  }, tpl);

  // ---- headline stat ---------------------------------------------------------------
  const peak = cov.peak || {};
  const stat = el("div", "hero-stat");
  const row = el("div", "hero-stat-row");
  row.append(
    el("span", "hero-num accent", fmtPct(cov.pct)),
    el("span", "hero-when", tpl(ed.statWhen, {
      covered: fmtInt(cov.covered),
      techniques: fmtInt(cov.techniques),
      version: attack.version,
      peak_pct: fmtPct(peak.pct),
      peak_quarter: quarterName(peak.quarter),
    }))
  );
  stat.append(el("div", "hero-stat-label", ed.statLabel), frag(row));
  slots.stat.append(stat);

  const labels = rows.map((q) => (q.partial ? `${q.quarter}*` : q.quarter));
  // Phones: one year label in two, or ~10 labels collide.
  const narrow = slots.chart.clientWidth < 600;
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 48, top: 40, bottom: 34 },
    legend: { ...baseLegend, data: [L.legendShare] },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const i = params.length ? params[0].dataIndex : -1;
        const q = rows[i];
        if (!q) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(quarterName(q.quarter))}` +
          `${q.partial ? ` · ${escapeHtml(tpl(L.tipPartial, { date: today }))}` : ""}</div>` +
          `<strong>${fmtPct(q.pct)}</strong> ` +
          `<span style="color:${C.muted};">${escapeHtml(tpl(L.tipCovered, {
            covered: fmtInt(q.covered), techniques: fmtInt(q.techniques),
          }))}</span>`
        );
      },
    },
    xAxis: catAxis(labels, {
      boundaryGap: false,
      axisLabel: {
        color: C.muted, fontFamily: MONO, fontSize: 11, interval: 0,
        formatter: (v) => yearLabel(v, narrow),
      },
    }),
    yAxis: valAxis({
      min: 0, max: 100,
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: "{value}%" },
    }),
    series: [{
      name: L.legendShare,
      type: "line",
      symbol: "circle",
      symbolSize: 5,
      lineStyle: { color: C.accent, width: 2 },
      itemStyle: { color: C.accent },
      data: rows.map((q) => (q.partial
        ? { value: q.pct, symbolSize: 9, itemStyle: { color: C.panel, borderColor: C.accent, borderWidth: 2 } }
        : q.pct)),
    }],
  });
}
