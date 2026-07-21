// Time to PoC 1 (hero) — publication -> first public exploit, median + IQR
// band per CVE publication year. Contract: site/data/time_to_poc.json
// (shared by all three sections; exploits.js fetches it once). Same band
// idiom as kev_latency.js: invisible p25 base + stacked (p75 − p25) area,
// median line on top. Negative medians keep their sign — exploit code that
// predates the CVE record is the finding, not an error.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

const fmtDays = (v) => `${fmtInt(Math.round(v))}d`;

export function render(slots, data) {
  const ed = editorial.sections.poc_gap;
  const hero = data.hero || {};

  // ---- headline stat --------------------------------------------------------
  const h = hero.headline || {};
  const stat = el("div", "hero-stat");
  stat.append(el("div", "hero-stat-label", ed.statLabel));
  const row = el("div", "hero-stat-row");
  if (Number.isFinite(h.median_days_latest) && Number.isFinite(h.median_days_baseline)) {
    row.append(
      el("span", "hero-num accent", fmtDays(h.median_days_latest)),
      el("span", "hero-when", tpl(ed.statLatest, { latest_year: h.latest_year })),
      el("span", "hero-vs", "vs"),
      el("span", "hero-num", fmtDays(h.median_days_baseline)),
      // baseline_year ships in the payload — the ten-year lookback when the
      // data has one, else the earliest year that cleared the min-n filter.
      el("span", "hero-when", tpl(ed.statAgo, { ago_year: h.baseline_year }))
    );
  } else {
    row.append(el("span", "hero-when muted", "Not enough data yet."));
  }
  stat.append(row);
  slots.stat.append(stat);

  // ---- match-audit note (panel-note template, kev_latency pattern) ----------
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    const m = hero.matched || {};
    if (m.dated_cves > 0) {
      noteEl.textContent = tpl(ed.note, {
        dated: fmtInt(m.dated_cves),
        matched: fmtInt(m.matched_cves),
        unmatched: fmtInt(m.unmatched_cves),
      });
    } else {
      noteEl.remove(); // never show a template with holes in it
    }
  }

  // ---- chart ----------------------------------------------------------------
  const rows = hero.years || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = rows.map((r) => (r.year === genYear ? `${r.year}*` : String(r.year)));

  const medianName = "Median gap";
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 56, top: 24 },
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
          `${fmtInt(r.n)} matched CVEs · ${fmtPct(r.pct_negative)} PoC before publish · ` +
          `${fmtPct(r.pct_within_week)} within a week`
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
        symbol: "circle", symbolSize: 5,
        lineStyle: { width: 2 }, z: 5,
        // Zero line matters here: below it, the exploit beat the paperwork.
        markLine: {
          silent: true, symbol: "none",
          lineStyle: { color: C.faint, type: "dashed", width: 1 },
          label: { show: false },
          data: [{ yAxis: 0 }],
        },
      },
    ],
  });
}
