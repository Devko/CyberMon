// Breach 1 (hero) — disclosure lag, median + IQR band per catalog year.
// Contract: site/data/breach_ledger.json (shared by all three breach
// sections; breaches.js fetches it once). Same band idiom as
// kev_latency.js: an invisible p25 base line plus a stacked (p75 − p25)
// area, with the median on top.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

// Days, not percent: "144d". Negative medians keep their sign — a breach
// catalogued before its own stated breach date is a date-quality signal.
const fmtDays = (v) => `${fmtInt(Math.round(v))}d`;

export function render(slots, data) {
  const ed = editorial.sections.disclosure;

  // ---- headline stat --------------------------------------------------------
  const h = data.headline || {};
  const stat = el("div", "hero-stat");
  stat.append(el("div", "hero-stat-label", ed.statLabel));
  const row = el("div", "hero-stat-row");
  if (h.trend_n > 0 && Number.isFinite(h.median_days) &&
      Number.isFinite(h.median_days_latest) && h.latest_year > 0) {
    // Trend start comes from the payload's import cutoff, never hardcoded.
    const trendStart = Number((data.import_era?.added_before || "").slice(0, 4)) || "";
    row.append(
      el("span", "hero-num accent", fmtDays(h.median_days)),
      el("span", "hero-when", tpl(ed.statWhole, { trend_start: trendStart })),
      el("span", "hero-vs", "vs"),
      el("span", "hero-num", fmtDays(h.median_days_latest)),
      el("span", "hero-when", tpl(ed.statLatest, { latest_year: h.latest_year }))
    );
  } else {
    // Young cohort: no invented comparison, just an honest muted state.
    row.append(el("span", "hero-when muted", "Not enough data yet."));
  }
  stat.append(row);
  slots.stat.append(stat);

  // ---- import-era callout (panel-note template, kev_latency.js pattern) -----
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    const era = data.import_era || {};
    if (era.n > 0 && Number.isFinite(era.median_days)) {
      noteEl.textContent = tpl(ed.importNote, {
        n: fmtInt(era.n),
        added_before: era.added_before,
        median_days: fmtInt(Math.round(era.median_days)),
      });
    } else {
      // Empty import cohort (or no computable median): nothing to call
      // out — never show a template with holes in it.
      noteEl.remove();
    }
  }

  // ---- chart ----------------------------------------------------------------
  const rows = data.lag_by_year || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = rows.map((r) => (r.year === genYear ? `${r.year}*` : String(r.year)));

  const medianName = "Median lag";
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
        const negative = r.pct_negative > 0
          ? ` · ${fmtPct(r.pct_negative)} before stated breach date`
          : "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(p.axisValueLabel ?? p.name))}</div>` +
          `median <strong>${fmtDays(r.median_days)}</strong> · IQR ${fmtDays(r.p25_days)}–${fmtDays(r.p75_days)}<br>` +
          `${fmtInt(r.n)} breaches · ${fmtPct(r.pct_over_365d)} over a year${negative}`
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
        // visible symbols: a decade of yearly medians is a short line, and
        // a sparse line with no markers reads as an accident
        symbol: "circle", symbolSize: 5,
        lineStyle: { width: 2 }, z: 5,
      },
    ],
  });
}
