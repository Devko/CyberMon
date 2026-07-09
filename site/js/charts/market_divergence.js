// Market 3 — research vs. media divergence. Contract: site/data/market_hype.json
// (shared by all three market sections; market.js fetches it once).
// Scatter: x = GDELT (media) 3-month avg index, y = arXiv (research) 3-month
// avg index, both fixed 0–100, diagonal y = x reference line. Terms whose
// divergence is null (backfill pending) are simply absent.
import { C, mkChart, valAxis, baseTooltip, baseGrid, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

// Honest empty state for launch-time payloads (backfill still running).
function noDataCard() {
  return el("div", "nodata-card", "Not enough data yet.");
}

const fmtSignedPts = (v) => `${Number(v) > 0 ? "+" : ""}${Number(v).toFixed(0)}`;

export function render(slots, data) {
  const ed = editorial.sections.divergence;

  const dirText = {
    research_leads: ed.directionResearchLeads,
    media_leads: ed.directionMediaLeads,
    aligned: ed.directionAligned,
  };
  const dirColor = {
    research_leads: C.versions.v3,
    media_leads: C.accent,
    aligned: C.faint,
  };
  const legendText = {
    research_leads: ed.legendResearchLeads,
    media_leads: ed.legendMediaLeads,
    aligned: ed.legendAligned,
  };

  // ---- headline stat card ------------------------------------------------------
  const td = data.headline?.top_divergence;
  const stats = el("div", "stat-grid");
  const card = el("div", "stat-card");
  if (!td || td.research_vs_media_index === null || td.research_vs_media_index === undefined) {
    card.classList.add("is-empty");
    card.append(
      el("div", "stat-lead muted", "Not enough data yet."),
      el("div", "stat-note", ed.statLabel)
    );
  } else {
    const pts = Math.abs(Number(td.research_vs_media_index));
    card.append(
      el("div", "stat-big accent", pts.toFixed(0)),
      el("div", "stat-lead", tpl(ed.statTemplate, {
        label: td.label,
        direction: dirText[td.direction] ?? td.direction,
        points: pts.toFixed(0),
      })),
      el("div", "stat-note", ed.statLabel)
    );
  }
  stats.append(card);
  slots.stat.append(stats);

  // ---- scatter ------------------------------------------------------------------
  const scored = (data.terms || []).filter((t) => t.divergence);
  if (!scored.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(noDataCard());
    return;
  }

  // Custom HTML legend chips (direction -> color), above the plot.
  const legend = el("div", "quadrant-legend");
  for (const key of ["research_leads", "media_leads", "aligned"]) {
    const chip = el("span", "quadrant-chip");
    const dot = el("span", "quadrant-dot");
    dot.style.background = dirColor[key];
    chip.append(dot, el("span", null, legendText[key]));
    legend.append(chip);
  }
  slots.controls.append(legend);

  const points = scored.map((t) => ({
    name: t.label,
    value: [t.divergence.gdelt_index_avg3m, t.divergence.arxiv_index_avg3m],
    direction: t.divergence.direction,
    score: t.divergence.research_vs_media_index,
    itemStyle: { color: dirColor[t.divergence.direction] ?? C.faint },
  }));

  const nameStyle = { color: C.faint, fontFamily: MONO, fontSize: 10 };
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 56, right: 30, top: 20, bottom: 48 },
    tooltip: {
      ...baseTooltip,
      formatter: (p) =>
        `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(p.name)}</div>` +
        `<div style="display:flex;gap:12px;justify-content:space-between;align-items:baseline;">` +
        `<span>${escapeHtml(dirText[p.data.direction] ?? String(p.data.direction))}</span>` +
        `<strong style="font-family:inherit">${escapeHtml(fmtSignedPts(p.data.score))}</strong></div>`,
    },
    xAxis: valAxis({
      min: 0, max: 100,
      name: ed.xAxisLabel, nameLocation: "middle", nameGap: 30, nameTextStyle: nameStyle,
    }),
    yAxis: valAxis({
      min: 0, max: 100,
      name: ed.yAxisLabel, nameLocation: "middle", nameGap: 40, nameRotate: 90, nameTextStyle: nameStyle,
    }),
    series: [{
      type: "scatter",
      data: points,
      symbolSize: 10,
      label: {
        show: true, position: "right",
        color: C.muted, fontFamily: MONO, fontSize: 10,
        formatter: (p) => p.name, // canvas text, not HTML — no escaping needed
      },
      labelLayout: { hideOverlap: true },
      emphasis: { itemStyle: { borderColor: C.ink, borderWidth: 1 } },
      markLine: {
        silent: true, symbol: "none",
        lineStyle: { color: C.faint, type: [4, 4], width: 1 },
        label: { show: false },
        data: [[{ coord: [0, 0] }, { coord: [100, 100] }]], // y = x reference
      },
    }],
  });
}
