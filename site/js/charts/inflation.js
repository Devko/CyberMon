// Chart 1 (hero) — severity inflation. Contract: site/data/severity_inflation.json
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, tooltipRows, fmtPct, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.inflation;

  // ---- headline stat --------------------------------------------------------
  const h = data.headline;
  const stat = el("div", "hero-stat");
  stat.append(
    el("div", "hero-stat-label", ed.statLabel),
    frag(
      (() => {
        const row = el("div", "hero-stat-row");
        row.append(
          el("span", "hero-num accent", fmtPct(h.pct_high_critical_latest)),
          el("span", "hero-when", tpl(ed.statLatest, { latest_year: h.latest_year })),
          el("span", "hero-vs", "vs"),
          el("span", "hero-num", fmtPct(h.pct_high_critical_baseline)),
          // baseline_year comes from the payload — per the contract, the
          // baseline is the earliest year that survived the sample-size
          // filters, not necessarily latest_year - 10.
          el("span", "hero-when", tpl(ed.statAgo, { ago_year: h.baseline_year }))
        );
        return row;
      })()
    )
  );
  slots.stat.append(stat);

  // ---- chart ----------------------------------------------------------------
  const years = data.blended.map((d) => d.year);
  const cats = years.map(String);
  const byYear = (rows) => {
    const m = new Map(rows.map((r) => [r.year, r]));
    return (pick) => years.map((y) => (m.has(y) ? pick(m.get(y)) : null));
  };

  const series = [];
  const legendData = [];

  for (const v of ["v2", "v3", "v4"]) {
    const rows = data.series[v] || [];
    if (!rows.length) continue;
    const get = byYear(rows);
    const color = C.versions[v];
    const name = `CVSS ${v} median`;
    legendData.push(name);
    series.push(
      { // invisible IQR base (p25)
        name: `_${v}_p25`, type: "line", stack: `iqr_${v}`, data: get((r) => r.p25),
        lineStyle: { opacity: 0 }, symbol: "none", silent: true, emphasis: { disabled: true },
      },
      { // IQR band = (p75 - p25) stacked on the base
        name: `_${v}_iqr`, type: "line", stack: `iqr_${v}`, data: get((r) => +(r.p75 - r.p25).toFixed(2)),
        lineStyle: { opacity: 0 }, areaStyle: { color, opacity: 0.13 },
        symbol: "none", silent: true, emphasis: { disabled: true },
      },
      {
        name, type: "line", data: get((r) => r.median), color,
        symbol: "none", lineStyle: { width: 2 }, z: 5,
      }
    );
  }

  const blendedName = "Blended median";
  legendData.push(blendedName);
  series.push({
    name: blendedName, type: "line",
    data: data.blended.map((d) => d.median),
    color: C.accent, symbol: "none",
    lineStyle: { width: 2, type: [6, 4] }, z: 6,
    markLine: {
      silent: true, symbol: "none",
      lineStyle: { color: C.faint, type: [3, 4], width: 1 },
      label: {
        color: C.muted, fontFamily: MONO, fontSize: 10,
        formatter: (p) => p.name, position: "insideEndTop", distance: 6,
      },
      data: (data.annotations || []).map((a) => ({ name: a.label, xAxis: String(a.year) })),
    },
  });

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, top: 44 },
    legend: { ...baseLegend, data: legendData },
    tooltip: {
      ...baseTooltip, trigger: "axis",
      formatter: (params) => tooltipRows(params, (v) => Number(v).toFixed(1)),
    },
    xAxis: catAxis(cats, { boundaryGap: false }),
    yAxis: valAxis({
      min: 0, max: 10, interval: 2,
      name: "CVSS base score",
      nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
    }),
    series,
  });
}
