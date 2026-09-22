// Incidents 2 — the amendment lag. Contract: site/data/sec_incidents.json
// (amendment_lag). Bars over fixed day buckets: for each Item 1.05 original
// that has been amended, the days to its FIRST amendment (matched by filer
// CIK to the nearest prior original — see sec_incidents_metrics.py). The
// median sits above the chart; unmatched amendments are named, not hidden.
import {
  C, MONO, mkChart, catAxis, valAxis, baseGrid, baseTooltip, fmtInt,
  escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";
import { showNoData } from "./incidents_clock.js";

export function render(slots, data) {
  const ed = editorial.sections.incidents_amend;
  if (data.status !== "ok") {
    showNoData(slots, ed.nodata);
    return;
  }
  const lag = data.amendment_lag;

  if (lag.unmatched_amendments > 0) {
    slots.extra.append(el("p", "table-context", tpl(ed.unmatched, {
      unmatched: fmtInt(lag.unmatched_amendments),
    })));
  }
  if (!lag.amended) {
    slots.panel.querySelector(".panel-note")?.remove();
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", ed.noAmend));
    return;
  }

  // Headline stat: the median lag and the amended share — from the data.
  const stat = el("div", "hero-stat");
  const row = el("div", "hero-stat-row");
  row.append(
    el("span", "hero-num accent", tpl(ed.statValue, {
      // Half-day medians (an even count) keep their .5 — no silent rounding.
      median: Number.isInteger(lag.median_days) ? fmtInt(lag.median_days) : lag.median_days.toFixed(1),
    })),
    el("span", "hero-when", tpl(ed.statWhen, {
      amended: fmtInt(lag.amended),
      originals: fmtInt(lag.originals),
      max: fmtInt(lag.max_days),
    }))
  );
  stat.append(el("div", "hero-stat-label", ed.statLabel), frag(row));
  slots.stat.append(stat);

  const buckets = lag.buckets;
  const maxN = Math.max(...buckets.map((b) => b.n));
  const narrow = slots.chart.clientWidth < 560;
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 48, top: 36, bottom: narrow ? 84 : 56 },
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
          `<strong>${fmtInt(p.value)}</strong> ${escapeHtml(ed.yAxis.toLowerCase())}`
        );
      },
    },
    xAxis: catAxis(buckets.map((b) => b.label), {
      name: ed.xAxis,
      nameLocation: "middle",
      nameGap: narrow ? 68 : 40,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
      axisLabel: { ...catAxis([]).axisLabel, interval: 0, hideOverlap: false, rotate: narrow ? 40 : 20 },
    }),
    yAxis: valAxis({
      name: ed.yAxis,
      minInterval: 1,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
    }),
    series: [
      {
        name: ed.yAxis,
        type: "bar",
        barMaxWidth: 48,
        data: buckets.map((b) => ({
          value: b.n,
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
