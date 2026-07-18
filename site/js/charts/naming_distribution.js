// Second chart — how many alternate names groups carry. Contract:
// site/data/naming.json. A plain histogram: x = alternate-name count,
// y = number of tracked groups. The zero bucket (groups the taxonomy never
// renamed) is muted so the eye reads the renamed tail.
import { editorial } from "../editorial.js";
import {
  C, MONO, mkChart, catAxis, valAxis, baseGrid, baseTooltip, fmtInt,
  escapeHtml,
} from "../theme.js";

export function render(slots, data) {
  const ed = editorial.sections.naming_dist;
  const dist = data.distribution || [];
  if (!dist.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(document.createTextNode(ed.nodata));
    return;
  }

  const cats = dist.map((d) => String(d.alt_count));
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, bottom: 46, left: 48 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const p = params[0];
        const k = p.axisValue;
        const plural = k === "1" ? "" : "s";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(k)} alternate name${plural}</div>` +
          `<strong>${fmtInt(p.value)}</strong> tracked group` +
          `${p.value === 1 ? "" : "s"}`
        );
      },
    },
    xAxis: catAxis(cats, {
      name: ed.xAxis,
      nameLocation: "middle",
      nameGap: 28,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
    }),
    yAxis: valAxis({
      name: ed.yAxis,
      minInterval: 1,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
    }),
    series: [
      {
        name: "Tracked groups",
        type: "bar",
        barWidth: "62%",
        data: dist.map((d) => ({
          value: d.n,
          // The "no alternate name" bucket fades; the renamed buckets read solid.
          itemStyle: { color: d.alt_count === 0 ? C.faint : C.versions.v4 },
        })),
      },
    ],
  });
}
