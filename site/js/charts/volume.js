// Chart 6 — volume curve. Contract: site/data/volume_curve.json
import { C, mkChart, catAxis, baseTooltip, baseLegend, baseGrid, tooltipRows, tooltipFootnote, fmtInt, fmtPct } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";
import { mkToggle } from "../ui.js";

export function render(slots, data) {
  const ed = editorial.sections.volume;
  const edp = editorial.projection;
  // Label the still-filling generation year so its dip reads as "partial".
  const genYear = Number(data.generated_at.slice(0, 4));
  const years = data.years.map((d) =>
    d.year === genYear ? `${d.year}*` : String(d.year));

  // Optional full-year pace projection (see the data contract); it needs a
  // complete year to anchor the dashed run-out, hence projIdx > 0.
  const proj = data.projection;
  const projIdx = proj ? data.years.findIndex((d) => d.year === proj.year) : -1;
  const hasProj = projIdx > 0;

  // Dashed segment from the last complete year's actual point to the
  // projected value, hollow marker at the projection. The "_" prefix keeps
  // it out of tooltipRows; the formatter appends the projection rows itself.
  // NOTE: the hollow fill lives on the data item, not the series — a line
  // series' itemStyle.color would repaint the dash panel-colored too.
  const projSeries = (name, key, color) => ({
    name: `_${name} projected`,
    type: "line",
    data: data.years.map((d, i) => {
      if (i === projIdx - 1) return { value: d[key], symbol: "none" };
      if (i === projIdx)
        return {
          value: proj[key],
          itemStyle: { color: C.panel, borderColor: color, borderWidth: 1.5 },
        };
      return null;
    }),
    color,
    symbol: "circle",
    symbolSize: 7,
    lineStyle: { width: 1.5, type: [3, 3], opacity: 0.85 },
    z: 4,
    silent: true,
  });

  const fmtTooltip = (params) => {
    let html = tooltipRows(params, fmtInt);
    if (hasProj && params.some((p) => p.dataIndex === projIdx)) {
      html += tooltipFootnote([
        tpl(edp.tooltipProjected, { name: "Published", n: fmtInt(proj.published) }),
        tpl(edp.tooltipProjected, { name: "Rejected", n: fmtInt(proj.rejected) }),
        tpl(edp.tooltipElapsed, { pct: fmtPct(proj.elapsed * 100) }),
      ]);
    }
    return html;
  };

  const chart = mkChart(slots.chart);

  const setScale = (log) => {
    chart.setOption(
      {
        grid: { ...baseGrid, left: 54, top: 44 },
        legend: { ...baseLegend, data: ["Published", "Rejected"] },
        tooltip: { ...baseTooltip, trigger: "axis", formatter: fmtTooltip },
        xAxis: catAxis(years, { boundaryGap: false }),
        yAxis: {
          type: log ? "log" : "value",
          logBase: 10,
          min: log ? 1 : 0,
          axisLine: { show: false },
          axisLabel: {
            color: C.muted, fontFamily: baseLegend.textStyle.fontFamily, fontSize: 11,
            formatter: (v) => (v >= 1000 ? `${v / 1000}k` : String(v)),
          },
          splitLine: { lineStyle: { color: C.rule, type: [2, 4] } },
        },
        series: [
          {
            name: "Published", type: "line",
            data: data.years.map((d) => d.published),
            color: C.ink, symbol: "none", lineStyle: { width: 2 },
            areaStyle: { color: C.ink, opacity: 0.05 },
          },
          {
            name: "Rejected", type: "line",
            data: data.years.map((d) => d.rejected),
            color: C.accent, symbol: "none", lineStyle: { width: 1.5, type: [5, 3] },
          },
          ...(hasProj
            ? [projSeries("Published", "published", C.ink),
               projSeries("Rejected", "rejected", C.accent)]
            : []),
        ],
      },
      { replaceMerge: ["yAxis", "series"] }
    );
  };

  slots.controls.append(mkToggle([ed.toggleLinear, ed.toggleLog], (idx) => setScale(idx === 1)));
  setScale(false);
  if (hasProj) slots.extra.append(el("p", "panel-note", edp.note));
}
