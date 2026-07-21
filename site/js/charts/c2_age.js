// C2 3 — infrastructure age of tonight's listed C2s. Contract:
// site/data/botnet_weather.json (c2_age section). Bars over fixed age
// buckets (days since Feodo Tracker first saw each server), with the median
// as the headline stat. Meaningful from day one — it reads only tonight's
// snapshot; an empty blocklist renders an honest empty card.
import {
  C, MONO, mkChart, catAxis, valAxis, baseGrid, baseTooltip, fmtInt,
  escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.c2_age;
  const age = data.c2_age || {};
  const buckets = age.buckets || [];

  if (!age.n) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }

  // Headline stat: the median age (and the oldest survivor) — from the data.
  const stat = el("div", "hero-stat");
  const row = el("div", "hero-stat-row");
  row.append(
    el("span", "hero-num accent", tpl(ed.statValue, {
      median: fmtInt(age.median_age_days),
    })),
    el("span", "hero-when", tpl(ed.statWhen, {
      oldest: fmtInt(age.oldest_age_days),
    }))
  );
  stat.append(el("div", "hero-stat-label", ed.statLabel), frag(row));
  slots.stat.append(stat);

  const maxN = Math.max(...buckets.map((b) => b.n));

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 48, top: 24, bottom: 44 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params) => {
        const p = params[0];
        if (!p) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(p.axisValue)}</div>` +
          `<strong>${fmtInt(p.value)}</strong> C2 servers`
        );
      },
    },
    xAxis: catAxis(buckets.map((b) => b.label), {
      axisLabel: { ...catAxis([]).axisLabel, interval: 0, rotate: 20 },
    }),
    yAxis: valAxis({
      name: ed.yAxis,
      minInterval: 1,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
    }),
    series: [
      {
        name: "C2 servers",
        type: "bar",
        barMaxWidth: 48,
        data: buckets.map((b) => ({
          value: b.n,
          // The fullest bucket reads in accent; the rest stay neutral.
          itemStyle: { color: b.n === maxN && b.n > 0 ? C.accent : C.versions.v3 },
        })),
        label: {
          show: true,
          position: "top",
          color: C.muted,
          fontFamily: MONO,
          fontSize: 11,
          formatter: (p) => (p.value ? fmtInt(p.value) : ""),
        },
      },
    ],
  });
}
