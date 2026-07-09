// KEV 2 — latency distribution buckets. Contract: site/data/kev_latency.json
// (shared by all three KEV sections; kev.js fetches it once).
// Horizontal bars in the contract's fixed bucket order, colored with the
// C.latency ramp (accent reserved for "before publish").
import { C, mkChart, catAxis, baseTooltip, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { el } from "../dom.js";

// Fixed contract order (top to bottom); keys double as C.latency ramp keys.
const ORDER = [
  { key: "before_publish", label: "before publish" },
  { key: "0-7d", label: "0–7d" },
  { key: "8-30d", label: "8–30d" },
  { key: "31-90d", label: "31–90d" },
  { key: "91-365d", label: "91–365d" },
  { key: "1-3y", label: "1–3y" },
  { key: "3y+", label: "3y+" },
];

export function render(slots, data) {
  const byKey = new Map((data.latency_buckets || []).map((b) => [b.bucket, b]));
  const rows = ORDER.map((o) => {
    const b = byKey.get(o.key);
    return { ...o, n: b?.n ?? 0, pct: Number.isFinite(b?.pct) ? b.pct : 0 };
  });

  if (!rows.some((r) => r.n > 0)) {
    // Empty cohort: an honest muted state, never a chart of zeros.
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
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
        return `${escapeHtml(r.label)}<br><strong>${fmtPct(r.pct)}</strong> · ${fmtInt(r.n)} entries`;
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
