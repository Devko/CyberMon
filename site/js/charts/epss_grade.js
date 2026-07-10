// EPSS 1 (hero) — the grade: per KEV year, the share of graded additions
// whose day-before EPSS score fell under 1%, in 1–10%, or at/above 10%.
// Contract: site/data/epss_report.json (shared by all three sections;
// epss.js fetches it once). Stacked 100% bars; accent ink on the sub-1%
// band on purpose — a confirmed-exploited CVE the model scored under 1%
// the day before is the strongest form of miss the data can show.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

const BAND_COLORS = { below: C.accent, mid: "#c08a45", above: "#77715f" };

export function render(slots, data) {
  const ed = editorial.sections.grade;

  // ---- headline stat --------------------------------------------------------
  const h = data.headline;
  const stat = el("div", "hero-stat");
  stat.append(el("div", "hero-stat-label", ed.statLabel));
  const row = el("div", "hero-stat-row");
  if (h && Number.isFinite(h.pct_below_1pct_latest) && Number.isFinite(h.pct_below_1pct)) {
    row.append(
      el("span", "hero-num accent", fmtPct(h.pct_below_1pct_latest)),
      el("span", "hero-when", tpl(ed.statLatest, { latest_year: h.latest_year })),
      el("span", "hero-vs", "vs"),
      el("span", "hero-num", fmtPct(h.pct_below_1pct)),
      el("span", "hero-when", ed.statAgo)
    );
  } else {
    // Nothing graded yet (fresh backfill): an honest muted state, no invention.
    row.append(el("span", "hero-when muted", "Not enough data yet."));
  }
  stat.append(row);
  slots.stat.append(stat);

  // ---- coverage callout (panel-note template, kev_latency.js pattern) --------
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    const cat = data.catalog || {};
    const ungradeable = cat.ungradeable || {};
    const nUngradeable = Object.values(ungradeable).reduce((s, n) => s + (n || 0), 0);
    const parts = [];
    if (nUngradeable > 0) {
      parts.push(tpl(ed.note, {
        ungradeable: fmtInt(nUngradeable),
        total: fmtInt(cat.total ?? 0),
        before_pub: fmtInt(ungradeable.listed_before_publication ?? 0),
      }));
    }
    if ((cat.pending_backfill ?? 0) > 0) {
      parts.push(tpl(ed.pendingNote, { pending: fmtInt(cat.pending_backfill) }));
    }
    if (parts.length) noteEl.textContent = parts.join(" ");
    else noteEl.remove(); // never show a template with holes in it
  }

  // ---- chart ----------------------------------------------------------------
  const rows = data.grade_by_year || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = rows.map((r) => (r.year === genYear ? `${r.year}*` : String(r.year)));

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 40 },
    legend: { ...baseLegend, data: [ed.legendBelow, ed.legendMid, ed.legendAbove] },
    tooltip: {
      ...baseTooltip,
      formatter: (p) => {
        const r = rows[p.dataIndex];
        if (!r) return "";
        const lines = [
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(p.name))}</div>`,
          `<span style="color:${BAND_COLORS.below}">under 1%</span> ` +
            `<strong>${fmtPct(r.pct_below_1pct)}</strong> (${fmtInt(r.n_below_1pct)})<br>`,
          `1–10% ${fmtPct(r.pct_1_to_10pct)} (${fmtInt(r.n_1_to_10pct)})<br>`,
          `10%+ ${fmtPct(r.pct_above_10pct)} (${fmtInt(r.n_above_10pct)})<br>`,
          `${fmtInt(r.graded)} graded entries`,
        ];
        if (r.ungradeable > 0) lines.push(` · ${fmtInt(r.ungradeable)} ungradeable`);
        if (r.pending > 0) lines.push(` · ${fmtInt(r.pending)} pending backfill`);
        return lines.join("");
      },
    },
    xAxis: catAxis(cats),
    yAxis: valAxis({
      min: 0, max: 100,
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series: [
      {
        name: ed.legendBelow, type: "bar", stack: "grade", barWidth: "58%",
        data: rows.map((r) => r.pct_below_1pct),
        itemStyle: { color: BAND_COLORS.below, opacity: 0.9 },
        label: {
          show: true, position: "inside",
          color: C.bg, fontFamily: MONO, fontSize: 11,
          formatter: (p) => (p.value >= 12 ? fmtPct(p.value) : ""),
        },
      },
      {
        name: ed.legendMid, type: "bar", stack: "grade",
        data: rows.map((r) => r.pct_1_to_10pct),
        itemStyle: { color: BAND_COLORS.mid, opacity: 0.85 },
      },
      {
        name: ed.legendAbove, type: "bar", stack: "grade",
        data: rows.map((r) => r.pct_above_10pct),
        itemStyle: { color: BAND_COLORS.above, opacity: 0.85 },
      },
    ],
  });
}
