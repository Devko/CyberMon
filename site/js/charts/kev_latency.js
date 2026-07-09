// KEV 1 (hero) — listing latency, median + IQR band per year.
// Contract: site/data/kev_latency.json (shared by all three KEV sections;
// kev.js fetches it once). Same band idiom as inflation.js: an invisible
// p25 base line plus a stacked (p75 − p25) area, with the median on top.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

// Days, not percent: "39d". Negative medians keep their sign — a listing
// that predates its own CVE record is a real (and alarming) event.
const fmtDays = (v) => `${fmtInt(Math.round(v))}d`;

export function render(slots, data) {
  const ed = editorial.sections.latency;

  // ---- headline stat --------------------------------------------------------
  const h = data.headline || {};
  const stat = el("div", "hero-stat");
  stat.append(el("div", "hero-stat-label", ed.statLabel));
  const row = el("div", "hero-stat-row");
  if (Number.isFinite(h.median_days_latest) && Number.isFinite(h.median_days_baseline)) {
    row.append(
      el("span", "hero-num accent", fmtDays(h.median_days_latest)),
      el("span", "hero-when", tpl(ed.statLatest, { latest_year: h.latest_year })),
      el("span", "hero-vs", "vs"),
      el("span", "hero-num", fmtDays(h.median_days_baseline)),
      // baseline_year comes from the payload — the earliest trend-cohort
      // year that cleared the sample-size filter, not a fixed offset.
      el("span", "hero-when", tpl(ed.statAgo, { ago_year: h.baseline_year }))
    );
  } else {
    // Young cohort: no invented comparison, just an honest muted state.
    row.append(el("span", "hero-when muted", "Not enough data yet."));
  }
  stat.append(row);
  slots.stat.append(stat);

  // ---- launch-batch callout (panel-note template, decay.js pattern) ----------
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    const bf = data.launch_backfill || {};
    if (bf.n > 0 && Number.isFinite(bf.median_days)) {
      noteEl.textContent = tpl(ed.backfillNote, {
        n: fmtInt(bf.n),
        date_added_before: bf.date_added_before,
        median_days: fmtInt(Math.round(bf.median_days)),
      });
    } else {
      // Empty launch cohort (or no computable median): nothing to call out —
      // never show a template with holes in it.
      noteEl.remove();
    }
  }

  // ---- chart ----------------------------------------------------------------
  const rows = data.latency_by_year || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = rows.map((r) => (r.year === genYear ? `${r.year}*` : String(r.year)));

  const medianName = "Median latency";
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 24 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const p = params.find((x) => x.seriesName === medianName) ?? params[0];
        const r = p && rows[p.dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(p.axisValueLabel ?? p.name))}</div>` +
          `median <strong>${fmtDays(r.median_days)}</strong> · IQR ${fmtDays(r.p25_days)}–${fmtDays(r.p75_days)}<br>` +
          `${fmtInt(r.n)} matched entries · ${fmtPct(r.pct_negative)} before publish · ` +
          `${fmtPct(r.pct_over_365d)} over a year`
        );
      },
    },
    xAxis: catAxis(cats, { boundaryGap: false }),
    yAxis: valAxis({
      name: "days",
      nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
    }),
    series: [
      { // invisible IQR base (p25)
        name: "_p25", type: "line", stack: "iqr",
        data: rows.map((r) => r.p25_days),
        lineStyle: { opacity: 0 }, symbol: "none", silent: true, emphasis: { disabled: true },
      },
      { // IQR band = (p75 − p25) stacked on the base
        name: "_iqr", type: "line", stack: "iqr",
        data: rows.map((r) => +(r.p75_days - r.p25_days).toFixed(1)),
        lineStyle: { opacity: 0 }, areaStyle: { color: C.accent, opacity: 0.13 },
        symbol: "none", silent: true, emphasis: { disabled: true },
      },
      {
        name: medianName, type: "line",
        data: rows.map((r) => r.median_days),
        color: C.accent,
        // visible symbols: the trend cohort can be only a few years long,
        // and a two-point line with no markers reads as an accident
        symbol: "circle", symbolSize: 5,
        lineStyle: { width: 2 }, z: 5,
      },
    ],
  });
}
