// EPSS 2 — day-before score distribution, split by model era. Contract:
// site/data/epss_report.json. Grouped bars: x = the log-ish probability
// buckets score_vs_reality uses, one series per EPSS model version that
// actually graded entries. The split is the point — v1..v5 are different
// models, and pooling them would be the CVSS-v2-vs-v3 landmine again.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, escapeHtml } from "../theme.js";
import { el } from "../dom.js";

// Newsprint ramp, oldest era darkest — the accent stays reserved for the
// hero's sub-1% band, which is a verdict; an era is not.
const ERA_COLORS = {
  v1: "#4b473d",
  v2: "#77715f",
  v3: "#a89f8a",
  v4: "#c9c1ab",
  v5: "#ded7c2",
};

export function render(slots, data) {
  const dist = data.distribution || {};
  const buckets = dist.buckets || [];
  const byModel = dist.by_model || [];
  if (!buckets.length || !byModel.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // Era date ranges ride into legend tooltips via the payload's own table.
  const eras = new Map((data.model_eras || []).map((e) => [e.label, e]));
  const seriesName = (m) => {
    const era = eras.get(m.model);
    return era ? `EPSS ${m.model} (${era.from.slice(0, 4)}–${era.to ? era.to.slice(0, 4) : "now"})`
               : `EPSS ${m.model}`;
  };

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 40 },
    legend: { ...baseLegend, data: byModel.map(seriesName) },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const bucket = params[0]?.axisValueLabel ?? params[0]?.name ?? "";
        const rows = params
          .map((p) => {
            const m = byModel[p.seriesIndex];
            if (!m) return "";
            const n = m.counts[bucket] ?? 0;
            return `${p.marker} ${escapeHtml(p.seriesName)} ` +
              `<strong>${fmtInt(n)}</strong> of ${fmtInt(m.n)} graded`;
          })
          .join("<br>");
        return `<div style="color:${C.muted};margin-bottom:4px;">day-before score ${escapeHtml(String(bucket))}</div>` + rows;
      },
    },
    xAxis: catAxis(buckets.map(String)),
    yAxis: valAxis({ name: "graded entries", nameTextStyle: { color: C.faint, fontSize: 10 } }),
    series: byModel.map((m) => ({
      name: seriesName(m),
      type: "bar",
      barGap: "10%",
      data: buckets.map((b) => m.counts[b] ?? 0),
      itemStyle: { color: ERA_COLORS[m.model] ?? C.muted, opacity: 0.9 },
    })),
  });
}
