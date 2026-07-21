// Time to PoC 2 — PoC before the government confirms. Contract:
// site/data/time_to_poc.json (shared; exploits.js fetches it once).
// Bars: per KEV dateAdded year, the share of matched entries (those with
// a dated public PoC) whose first PoC predates the listing. The 2021-22
// seeding years plot honestly — a back-catalog import of old CVEs is
// trivially preempted by equally old exploit code — while the panel note
// carries the trend-cohort figure the seeding era is kept out of.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.poc_preempt;
  const kp = data.kev_preempt || {};

  // ---- trend-cohort note (panel-note template) ------------------------------
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    const t = kp.trend || {};
    if (t.with_poc_date > 0) {
      noteEl.textContent = tpl(ed.note, {
        trend_pct: fmtPct(t.pct_preempted),
        trend_n: fmtInt(t.with_poc_date),
        cutoff_year: String(kp.cutoff || "").slice(0, 4),
      });
    } else {
      noteEl.remove(); // never show a template with holes in it
    }
  }

  const rows = kp.years || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  const genYear = Number(data.generated_at.slice(0, 4));
  const cutoffYear = Number(String(kp.cutoff || "").slice(0, 4));
  const cats = rows.map((r) => (r.year === genYear ? `${r.year}*` : String(r.year)));

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 24 },
    tooltip: {
      ...baseTooltip,
      formatter: (p) => {
        const r = rows[p.dataIndex];
        if (!r) return "";
        const era = Number.isFinite(cutoffYear) && r.year < cutoffYear
          ? `<br><span style="color:${C.muted};">seeding-era listings — kept out of the headline figure</span>`
          : "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(p.name))}</div>` +
          `<strong>${fmtPct(r.pct_preempted)}</strong> had public exploit code first<br>` +
          `${fmtInt(r.preempted)} of ${fmtInt(r.with_poc_date)} matched · ` +
          `${fmtInt(r.total_added)} listings added${era}`
        );
      },
    },
    xAxis: catAxis(cats),
    yAxis: valAxis({
      min: 0, max: 100,
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series: [{
      type: "bar",
      barWidth: "55%",
      data: rows.map((r) => ({
        value: r.pct_preempted,
        // Seeding-era bars are muted: real data, different regime.
        itemStyle: Number.isFinite(cutoffYear) && r.year < cutoffYear
          ? { color: C.muted, opacity: 0.45 }
          : { color: C.accent, opacity: 0.85 },
      })),
      label: {
        show: true, position: "top",
        color: C.muted, fontFamily: MONO, fontSize: 11,
        formatter: (p) => fmtPct(p.value),
      },
    }],
  });
}
