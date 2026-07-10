// Hygiene 3 — the spread: every measured economy bucketed by current
// validation rate. Contract: site/data/dnssec_adoption.json. One economy,
// one vote — deliberately the opposite weighting of the hero's
// user-weighted world line. Accent reserved for the no-validation bucket.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

// Rate buckets, worst first (the contract fixes the order). Color fades
// from the accent (nobody validates) toward newsprint ink (nearly all do).
const BUCKET_COLORS = {
  "<10%": C.accent,
  "10-25%": "#c08a45",
  "25-50%": "#a89f8a",
  "50-75%": "#cfc7b0",
  "75%+": "#ded7c2",
};

function statCard(bigText, leadText, noteText) {
  const card = el("div", "stat-card");
  card.append(
    el("div", "stat-big accent", bigText),
    el("div", "stat-lead", leadText),
    el("div", "stat-note", noteText)
  );
  return card;
}

export function render(slots, data) {
  const ed = editorial.sections.spread;
  const spread = data.spread || {};
  const buckets = spread.buckets || [];
  if (!buckets.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // ---- headline stat: how many clear the halfway mark ------------------------
  const byBucket = new Map(buckets.map((b) => [b.bucket, b.n]));
  const overHalf = (byBucket.get("50-75%") ?? 0) + (byBucket.get("75%+") ?? 0);
  const stats = el("div", "stat-grid");
  stats.append(statCard(
    tpl(ed.statBig, { n: fmtInt(overHalf), total: fmtInt(spread.n_economies) }),
    ed.statLead,
    tpl(ed.statNote, { min_seen: fmtInt(spread.min_seen) })
  ));
  slots.stat.append(stats);

  // ---- chart ----------------------------------------------------------------
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 24 },
    tooltip: {
      ...baseTooltip,
      formatter: (p) => {
        const b = buckets[p.dataIndex];
        if (!b) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(tpl(ed.tooltipBucket, { bucket: b.bucket }))}</div>` +
          `<strong>${fmtInt(b.n)}</strong> ${escapeHtml(ed.tooltipUnit)}`
        );
      },
    },
    xAxis: catAxis(buckets.map((b) => b.bucket)),
    yAxis: valAxis({
      name: ed.yAxisLabel,
      nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
    }),
    series: [{
      type: "bar",
      barWidth: "55%",
      data: buckets.map((b) => ({
        value: b.n,
        itemStyle: { color: BUCKET_COLORS[b.bucket] ?? C.faint, opacity: 0.9 },
      })),
      label: {
        show: true, position: "top",
        color: C.muted, fontFamily: MONO, fontSize: 11,
        formatter: (p) => fmtInt(p.value),
      },
    }],
  });
}
