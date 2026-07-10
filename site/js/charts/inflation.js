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
  // Axis years = union of every per-version series and the blended line:
  // v3 clears the >=100 filter years before blended clears its 20%-coverage
  // rule, and building the axis from blended alone would silently drop
  // those points (and any annotation older than the blended span).
  const years = [...new Set([
    ...Object.values(data.series || {}).flat().map((d) => d.year),
    ...data.blended.map((d) => d.year),
  ])].sort((a, b) => a - b);
  // The generation year plots but is partial — mark it (the headline stat
  // above already excludes it by contract).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = years.map((y) => (y === genYear ? `${y}*` : String(y)));
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
  // Year-aligned, NOT positional: the axis is the union of all series'
  // years, so blended (which starts later than v3) must map by year or
  // it renders shifted to the left edge.
  const blendedByYear = byYear(data.blended);
  series.push({
    name: blendedName, type: "line",
    data: blendedByYear((r) => r.median),
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
