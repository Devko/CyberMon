// Changelog 2 — the ransomware flag arrives late. Contract:
// site/data/kev_changelog.json (shared; changelog.js fetches it once).
// Bars: Unknown->Known flips observed per month; line: the cumulative
// count. The stat renders honestly when thin: below min_n the pipeline
// ships a null median and the note says so instead of inventing one.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.flagflip;
  const flips = data.flips || {};
  const lag = flips.lag || {};

  const rows = flips.by_month || [];

  // ---- stat (hygiene_spread statBig pattern) -------------------------------
  // The step month (the first capture carrying the flag column flips every
  // already-flagged entry at once) is schema initialization, not a
  // reassessment, so the headline count leaves it out. Editions from
  // 2026-09-20 ship step_month_flips/total_after_step; older ones that
  // carry step_month get the same split derived from by_month, since the
  // step month is by construction the first month of the series.
  const stepMonth = flips.step_month || null;
  const stepFlips = flips.step_month_flips
    ?? (stepMonth && rows.length && rows[0].month === stepMonth ? rows[0].flips : 0);
  const headlineN = flips.total_after_step ?? Math.max(0, (flips.total ?? 0) - stepFlips);
  const stat = el("div", "hero-stat");
  const row = el("div", "hero-stat-row");
  row.append(
    el("span", "hero-num accent", tpl(ed.statBig, { n: fmtInt(headlineN) })),
    el("span", "hero-when", ed.statLead)
  );
  stat.append(row);
  // Post-step median (editions from 2026-09-08) beside the pooled one; the
  // pooled-only note covers older editions and thin post-step cohorts; a
  // record with no capture step names none.
  const post = flips.lag_post_step || {};
  const hasPooled = lag.median_days !== null && lag.median_days !== undefined;
  const hasPost = stepMonth && post.median_days !== null && post.median_days !== undefined;
  const vars = { median: fmtInt(Math.round(lag.median_days)),
                 post_median: fmtInt(Math.round(post.median_days)),
                 step_month: stepMonth, step_flips: fmtInt(stepFlips) };
  stat.append(el("div", "hero-stat-label",
    !hasPooled
      ? ed.statNoteThin
      : !stepMonth
        ? tpl(ed.statNoteNoStep, vars)
        : hasPost
          ? tpl(ed.statNote, vars)
          : tpl(ed.statNotePooled, vars)));
  slots.stat.append(stat);

  // ---- chart ----------------------------------------------------------------
  if (!rows.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  const genMonth = data.generated_at.slice(0, 7);
  const cats = rows.map((r) => (r.month === genMonth ? `${r.month}*` : r.month));

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, right: 50, top: 40, bottom: 48 },
    legend: { ...baseLegend, data: [ed.legendMonthly, ed.legendCumulative] },
    tooltip: {
      ...baseTooltip,
      formatter: (p) => {
        const r = rows[p.dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(p.name))}</div>` +
          `${escapeHtml(ed.legendMonthly)} <strong>${fmtInt(r.flips)}</strong><br>` +
          `${escapeHtml(ed.legendCumulative)} <strong>${fmtInt(r.cumulative)}</strong>`
        );
      },
    },
    xAxis: catAxis(cats, {
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 10, rotate: 45 },
    }),
    yAxis: [
      valAxis(),
      valAxis({ splitLine: { show: false } }),
    ],
    series: [
      {
        name: ed.legendMonthly,
        type: "bar",
        yAxisIndex: 0,
        data: rows.map((r) => r.flips),
        itemStyle: { color: "#77715f", opacity: 0.85 },
      },
      {
        name: ed.legendCumulative,
        type: "line",
        yAxisIndex: 1,
        data: rows.map((r) => r.cumulative),
        symbol: "none",
        lineStyle: { color: C.accent, width: 2 },
        itemStyle: { color: C.accent },
      },
    ],
  });
}
