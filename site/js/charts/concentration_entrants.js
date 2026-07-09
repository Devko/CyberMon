// Concentration 2 — first-year CNAs (bars) vs. the active roster (line),
// both counts on ONE integer axis (volume.js twin-series idiom).
// Contract: site/data/cna_concentration.json (shared by all three
// concentration sections; concentration.js fetches it once).
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, tooltipRows, tooltipFootnote, fmtInt, fmtPct } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const edp = editorial.projection;
  const years = data.years || [];
  if (!years.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = years.map((d) => (d.year === genYear ? `${d.year}*` : String(d.year)));

  // Optional full-year pace projection of the newcomer flow: a hollow
  // ghost extension stacked on the current-year bar, from the actual top
  // up to the projected height. The roster line never projects (headcount).
  const proj = data.projection;
  const projIdx = proj ? years.findIndex((d) => d.year === proj.year) : -1;
  const ghost = projIdx >= 0 ? proj.newcomers - years[projIdx].newcomer_count : 0;
  const hasProj = projIdx >= 0 && ghost > 0;

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 44 },
    legend: { ...baseLegend, data: ["First-year CNAs", "Active CNAs"] },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        let html = tooltipRows(params, fmtInt);
        if (hasProj && params.some((p) => p.dataIndex === projIdx)) {
          html += tooltipFootnote([
            tpl(edp.tooltipProjected, { name: "First-year CNAs", n: fmtInt(proj.newcomers) }),
            tpl(edp.tooltipElapsed, { pct: fmtPct(proj.elapsed * 100) }),
          ]);
        }
        return html;
      },
    },
    xAxis: catAxis(cats),
    yAxis: valAxis({
      min: 0,
      minInterval: 1, // counts — never fractional gridlines
      axisLabel: { color: C.muted, fontFamily: baseLegend.textStyle.fontFamily, fontSize: 11 },
    }),
    series: [
      {
        name: "First-year CNAs", type: "bar", stack: "newcomers",
        data: years.map((d) => d.newcomer_count),
        color: C.accent, itemStyle: { opacity: 0.75 },
        barMaxWidth: 18,
      },
      // "_" prefix keeps the ghost out of tooltipRows; the formatter above
      // appends the projection rows itself.
      ...(hasProj
        ? [{
            name: "_projected newcomers", type: "bar", stack: "newcomers",
            data: years.map((d, i) => (i === projIdx ? ghost : null)),
            barMaxWidth: 18,
            itemStyle: {
              color: "transparent",
              borderColor: C.accent,
              borderWidth: 1.5,
              borderType: "dashed",
              opacity: 0.9,
            },
            z: 4,
            silent: true,
          }]
        : []),
      {
        name: "Active CNAs", type: "line",
        data: years.map((d) => d.cna_count),
        color: C.ink, symbol: "none", lineStyle: { width: 2 }, z: 5,
      },
    ],
  });
  if (hasProj) slots.extra.append(el("p", "panel-note", edp.note));
}
