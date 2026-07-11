// Rescores 2 — magnitude of rescore deltas. Contract:
// site/data/rescore_log.json (magnitude section). Histogram over fixed
// signed delta buckets, rescore events only (same CVSS version by
// construction — version shifts never land here). Below the min-n gate the
// data file ships buckets: null, and this renderer shows the honest
// placeholder, built from the file's own n / min_n — never hardcoded.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, escapeHtml } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.magnitude;
  const mag = data.magnitude;

  if (!mag.buckets) {
    // The gate is closed: report exactly how much record exists.
    slots.chart.classList.remove("chart", "chart-tall");
    const text = mag.n > 0
      ? tpl(ed.placeholder, {
          n: fmtInt(mag.n),
          first_date: data.catalog.first_observed ?? "",
          min_n: fmtInt(mag.min_n),
        })
      : tpl(ed.placeholderEmpty, { min_n: fmtInt(mag.min_n) });
    slots.chart.append(el("div", "nodata-card", text));
    return;
  }

  if (mag.median_delta !== null) {
    slots.controls.append(
      el("div", "panel-subtitle", tpl(ed.medianLabel, {
        median: (mag.median_delta > 0 ? "+" : "") + mag.median_delta.toFixed(1),
      }))
    );
  }

  const buckets = mag.buckets;
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 28, bottom: 34 },
    tooltip: {
      ...baseTooltip,
      formatter: (p) =>
        `${escapeHtml(String(p.name))}<br><strong>` +
        `${escapeHtml(tpl(ed.tooltipCount, { n: fmtInt(p.value) }))}</strong>`,
    },
    xAxis: catAxis(buckets.map((b) => b.bucket), {
      name: ed.xAxisLabel,
      nameLocation: "middle",
      nameGap: 26,
      nameTextStyle: { color: C.faint, fontSize: 10 },
    }),
    yAxis: valAxis({
      name: ed.yAxisLabel,
      nameTextStyle: { color: C.faint, fontSize: 10 },
    }),
    series: [{
      type: "bar",
      barMaxWidth: 48,
      data: buckets.map((b) => ({
        value: b.n,
        // downward deltas in the "lowered" ink, upward in accent — the
        // same reading as the hero's diverging bars
        itemStyle: { color: b.bucket.startsWith("+") || b.bucket.startsWith(">")
          ? C.accent : C.versions.v3 },
      })),
    }],
  });
}
