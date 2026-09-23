// Chart 6 — volume curve. Contract: site/data/volume_curve.json
import { C, mkChart, catAxis, baseTooltip, baseLegend, baseGrid, tooltipRows, tooltipFootnote, fmtInt, fmtPct } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";
import { mkToggle } from "../ui.js";

export function render(slots, data) {
  const ed = editorial.sections.volume;
  const edp = editorial.projection;
  const edl = editorial.linuxToggle;
  // Label the still-filling generation year so its dip reads as "partial".
  const genYear = Number(data.generated_at.slice(0, 4));
  const years = data.years.map((d) =>
    d.year === genYear ? `${d.year}*` : String(d.year));

  // The Linux-kernel toggle swaps in the additive without_linux variant: its
  // own years AND its own pace projection (never the all-CNA one), so the
  // dashed run-out always paces the series it extends.
  const variants = [data];
  if (data.without_linux?.years?.length === data.years.length) {
    variants.push(data.without_linux);
  }
  const state = { log: false, variant: 0 };

  const chart = mkChart(slots.chart);
  const projNote = el("p", "panel-note", edp.note);
  const linuxNote = el("p", "panel-note", `${edl.note} ${ed.linuxNote}`);

  const draw = () => {
    const v = variants[state.variant];
    const rows = v.years;
    // Optional full-year pace projection (see the data contract); it needs a
    // complete year to anchor the dashed run-out, hence projIdx > 0.
    const proj = v.projection;
    const projIdx = proj ? rows.findIndex((d) => d.year === proj.year) : -1;
    const hasProj = projIdx > 0;

    // Dashed segment from the last complete year's actual point to the
    // projected value, hollow marker at the projection. The "_" prefix keeps
    // it out of tooltipRows; the formatter appends the projection rows itself.
    // NOTE: the hollow fill lives on the data item, not the series — a line
    // series' itemStyle.color would repaint the dash panel-colored too.
    const projSeries = (name, key, color) => ({
      name: `_${name} projected`,
      type: "line",
      data: rows.map((d, i) => {
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

    chart.setOption(
      {
        grid: { ...baseGrid, left: 54, top: 44 },
        legend: { ...baseLegend, data: ["Published", "Rejected"] },
        tooltip: { ...baseTooltip, trigger: "axis", formatter: fmtTooltip },
        xAxis: catAxis(years, { boundaryGap: false }),
        yAxis: {
          type: state.log ? "log" : "value",
          logBase: 10,
          min: state.log ? 1 : 0,
          axisLine: { show: false },
          axisLabel: {
            color: C.muted, fontFamily: baseLegend.textStyle.fontFamily, fontSize: 11,
            formatter: (val) => (val >= 1000 ? `${val / 1000}k` : String(val)),
          },
          splitLine: { lineStyle: { color: C.rule, type: [2, 4] } },
        },
        series: [
          {
            name: "Published", type: "line",
            data: rows.map((d) => d.published),
            color: C.ink, symbol: "none", lineStyle: { width: 2 },
            areaStyle: { color: C.ink, opacity: 0.05 },
          },
          {
            name: "Rejected", type: "line",
            data: rows.map((d) => d.rejected),
            color: C.accent, symbol: "none", lineStyle: { width: 1.5 },
          },
          ...(hasProj
            ? [projSeries("Published", "published", C.ink),
               projSeries("Rejected", "rejected", C.accent)]
            : []),
        ],
      },
      { replaceMerge: ["yAxis", "series"] }
    );
    projNote.hidden = !hasProj;
    linuxNote.hidden = state.variant === 0;
  };

  slots.controls.append(mkToggle([ed.toggleLinear, ed.toggleLog], (idx) => {
    state.log = idx === 1;
    draw();
  }));
  if (variants.length > 1) {
    slots.controls.append(mkToggle(edl.labels, (idx) => {
      state.variant = idx;
      draw();
    }));
    slots.extra.append(linuxNote);
  }
  slots.extra.append(projNote);
  draw();
}
