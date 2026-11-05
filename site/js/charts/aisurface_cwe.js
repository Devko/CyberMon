// AI Product CVEs 2 — the most common first-listed CWEs of AI-product CVEs
// in the window, against a year-matched baseline of every other CVE.
// Contract: site/data/ai_products.json (cwe). Shares, not counts (the
// populations differ by two orders of magnitude); the baseline is a tick on
// each row (credits_weakness pattern), so the eye reads "above or below
// everyone else".
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid,
  fmtInt, fmtPct, escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.aisurface_cwe;
  const L = ed.labels;
  const c = data.cwe || {};
  const top = c.top || [];

  const stat = el("div", "hero-stat");
  stat.append(el("div", "hero-stat-label", ed.statLabel));
  const row = el("div", "hero-stat-row");
  if (c.n) {
    row.append(
      el("span", "hero-num accent", fmtInt(c.ai_specific?.n)),
      el("span", "hero-when", tpl(ed.statOf, {
        n: fmtInt(c.n), ids: (c.ai_specific?.ids || []).join(", "),
      }))
    );
  } else {
    row.append(el("span", "hero-when muted", ed.nodata));
  }
  stat.append(row);
  slots.stat.append(stat);

  if (!top.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }

  // ECharts draws a category y-axis bottom-up; reverse so the commonest CWE
  // sits on top.
  const rows = [...top].reverse();
  const label = (t) => (t.name && t.name !== t.cwe ? `${t.cwe} ${t.name}` : t.cwe);

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 8, right: 28, top: 40, bottom: 34, containLabel: true },
    legend: { ...baseLegend, itemHeight: 8 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params) => {
        const t = rows[params[0].dataIndex];
        const line = (name, value) =>
          `<div style="display:flex;gap:14px;justify-content:space-between;">` +
          `<span>${escapeHtml(name)}</span><strong>${value}</strong></div>`;
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(label(t))}</div>` +
          line(L.ai, `${fmtPct(t.pct)} <span style="color:${C.muted};">${fmtInt(t.n)}</span>`) +
          line(L.baseline, fmtPct(t.baseline_pct))
        );
      },
    },
    xAxis: valAxis({
      name: L.xAxis,
      nameLocation: "middle",
      nameGap: 24,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: "{value}%" },
    }),
    yAxis: catAxis(rows.map(label), {
      axisLabel: {
        color: C.ink, fontFamily: MONO, fontSize: 11,
        // long CWE names would squeeze the plot on phones
        width: slots.chart.clientWidth < 600 ? 150 : 260, overflow: "truncate",
      },
    }),
    series: [
      {
        name: L.ai, type: "bar", barWidth: 10,
        itemStyle: { color: C.sev.high },
        data: rows.map((t) => t.pct),
      },
      {
        name: L.baseline, type: "scatter", symbol: "rect", symbolSize: [2, 18],
        itemStyle: { color: C.ink }, z: 5,
        data: rows.map((t) => t.baseline_pct),
      },
    ],
  });

  slots.extra.append(el("p", "panel-note", tpl(ed.noCweNote, {
    no_cwe: fmtPct(c.no_cwe_pct), baseline_no_cwe: fmtPct(c.baseline_no_cwe_pct),
    top_share: fmtPct(c.top_share_pct),
  })));
}
