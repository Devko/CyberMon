// 04 — the floor caveat: share of published CVEs carrying any credit, by
// publication year. Contract: site/data/ai_credits.json (coverage). The
// y-axis is pinned 0-100 on purpose — the point is how far below "everyone
// gets thanked" the record sits, and an auto-fitted axis would hide that.
import { editorial, tpl } from "../editorial.js";
import {
  C, MONO, mkChart, catAxis, valAxis, baseGrid, baseTooltip, fmtInt, fmtPct,
  escapeHtml,
} from "../theme.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.credits_coverage;
  const rows = data.coverage || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 52, top: 40 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const r = rows[params[0].dataIndex];
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(r.year)}</div>` +
          `<strong>${fmtPct(r.pct)}</strong><br>` +
          `<span style="color:${C.muted};">` +
          escapeHtml(tpl(ed.tooltipTemplate, {
            with_credits: fmtInt(r.with_credits),
            published: fmtInt(r.published),
          })) + `</span>`
        );
      },
    },
    xAxis: catAxis(rows.map((r) => String(r.year))),
    yAxis: valAxis({
      min: 0,
      max: 100,
      name: ed.yAxis,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11, align: "left" },
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: "{value}%" },
    }),
    series: [
      {
        name: ed.yAxis,
        type: "bar",
        barWidth: "62%",
        itemStyle: { color: C.versions.v4 },
        data: rows.map((r) => r.pct),
        // The half-way line the caption argues against.
        markLine: {
          silent: true,
          symbol: "none",
          lineStyle: { color: C.faint, type: [4, 4] },
          label: { color: C.faint, fontFamily: MONO, fontSize: 10, formatter: "50%" },
          data: [{ yAxis: 50 }],
        },
      },
    ],
  });
}
