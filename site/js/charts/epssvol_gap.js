// EPSS Volatility 1 (hero) — the headline gap. Contract:
// site/data/epss_volatility.json (gap section; epssvol.js fetches the file
// once for all three sections). Two lines over the observed nights: the
// share of compared CVEs whose EPSS PERCENTILE moved (high, the number
// teams triage on — accent, because that churn is the story) against the
// share whose raw PROBABILITY moved (low, the model actually holding). The
// space between them is the point. Below the min-days gate the file ships
// prob_moved_pct: null and this renderer shows the honest placeholder,
// built from the file's own trend_days / min_days — never hardcoded.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, fmtPct, escapeHtml } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.epssvol_gap;
  const gap = data.gap;
  const first = data.catalog.first_observed;

  // The static note carries a {first_date} placeholder — fill it from the
  // log's actual start; before any diff-night exists, the launch variant
  // renders instead. Thin is a fact, not a bug.
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    noteEl.textContent = first
      ? tpl(ed.note, { first_date: first })
      : ed.noteEmpty;
  }

  if (gap.prob_moved_pct === null) {
    // The gate is closed: report exactly how much record exists.
    slots.chart.classList.remove("chart", "chart-tall");
    const text = gap.trend_days > 0
      ? tpl(ed.placeholder, {
          days: fmtInt(gap.trend_days),
          first_date: first ?? "",
          min_days: fmtInt(gap.min_days),
        })
      : tpl(ed.placeholderEmpty, { min_days: fmtInt(gap.min_days) });
    slots.chart.append(el("div", "nodata-card", text));
    return;
  }

  // ---- headline stat: the two shares, straight from the data --------------
  const stat = el("div", "hero-stat");
  const row = el("div", "hero-stat-row");
  row.append(
    el("span", "hero-num accent", fmtPct(gap.pct_moved_pct)),
    el("span", "hero-when", tpl(ed.statVersus, {
      prob: fmtPct(gap.prob_moved_pct),
      days: fmtInt(gap.trend_days),
    }))
  );
  stat.append(el("div", "hero-stat-label", ed.statLabel), frag(row));
  slots.stat.append(stat);

  const days = gap.days;
  const SERIES = [
    { name: ed.legendPct, color: C.accent, value: (d) => d.pct_moved },
    { name: ed.legendProb, color: C.versions.v3, value: (d) => d.prob_moved },
  ];

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 40, bottom: days.length > 16 ? 52 : 34 },
    legend: { ...baseLegend, data: SERIES.map((s) => s.name) },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const d = params.length && days[params[0].dataIndex];
        if (!d) return "";
        const head =
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(d.date)}</div>`;
        const body = SERIES.map(({ name, color, value }) =>
          `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
          `<span><span style="display:inline-block;width:8px;height:8px;background:${color};margin-right:6px;"></span>` +
          `${escapeHtml(name)}</span>` +
          `<strong style="font-family:inherit">${escapeHtml(fmtPct(value(d)))}</strong></div>`
        ).join("");
        return head + body;
      },
    },
    xAxis: catAxis(days.map((d) => d.date), {
      axisLabel: { ...catAxis([]).axisLabel, rotate: days.length > 16 ? 45 : 0 },
    }),
    yAxis: valAxis({
      max: 100,
      name: ed.yAxisLabel,
      nameTextStyle: { color: C.faint, fontSize: 10 },
      axisLabel: { ...valAxis().axisLabel, formatter: (v) => `${v}%` },
    }),
    series: SERIES.map(({ name, color, value }) => ({
      name,
      type: "line",
      color,
      symbol: "circle",
      symbolSize: days.length > 40 ? 0 : 5,
      lineStyle: { width: 2 },
      areaStyle: name === ed.legendPct ? { opacity: 0.1 } : undefined,
      emphasis: { focus: "series" },
      data: days.map(value),
    })),
  });
}
