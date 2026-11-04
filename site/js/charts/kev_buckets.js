// KEV 2 — latency distribution buckets. Contract: site/data/kev_latency.json
// (shared by all three KEV sections; kev.js fetches it once).
// Horizontal bars in the contract's fixed bucket order, colored with the
// C.latency ramp (accent reserved for "before publish").
import { C, mkChart, catAxis, baseTooltip, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

// Fixed contract order (top to bottom); keys double as C.latency ramp keys
// and as keys of editorial.sections.buckets.labels.buckets.
const ORDER = ["before_publish", "0-7d", "8-30d", "31-90d", "91-365d", "1-3y", "3y+"];

export function render(slots, data) {
  const ed = editorial.sections.buckets;
  const L = ed.labels;
  const byKey = new Map((data.latency_buckets || []).map((b) => [b.bucket, b]));
  const rows = ORDER.map((key) => {
    const b = byKey.get(key);
    return { key, label: L.buckets[key], n: b?.n ?? 0, pct: Number.isFinite(b?.pct) ? b.pct : 0 };
  });

  if (!rows.some((r) => r.n > 0)) {
    // Empty cohort: an honest muted state, never a chart of zeros.
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", ed.nodata || editorial.ui.nodata));
    return;
  }

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { left: 8, right: 70, top: 10, bottom: 10, containLabel: true },
    tooltip: {
      ...baseTooltip,
      formatter: (p) => {
        const r = rows[p.dataIndex];
        if (!r) return "";
        return `${escapeHtml(r.label)}<br><strong>${fmtPct(r.pct)}</strong> · ` +
          escapeHtml(tpl(L.tipCount, { n: fmtInt(r.n) }));
      },
    },
    xAxis: { type: "value", show: false },
    yAxis: catAxis(rows.map((r) => r.label), {
      axisLine: { show: false },
      inverse: true, // contract order reads top-down: before publish first
    }),
    series: [{
      type: "bar",
      barWidth: 18,
      data: rows.map((r) => ({
        value: r.pct,
        itemStyle: { color: C.latency[r.key] ?? C.faint },
      })),
      label: {
        show: true, position: "right",
        color: C.muted, fontFamily: MONO, fontSize: 11,
        formatter: (p) => fmtPct(p.value),
      },
    }],
  });
}
