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
import { calendar, gapData, gapTooltip, loneSymbol } from "../gaps.js";

export function render(slots, data) {
  const ed = editorial.sections.epssvol_gap;
  const gap = data.gap;
  const first = data.catalog.first_observed;

  // The static note carries a {first_date} placeholder — fill it from the
  // log's actual start; before any diff-night exists, the launch variant
  // renders instead. Thin is a fact, not a bug.
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    let note = first ? tpl(ed.note, { first_date: first }) : ed.noteEmpty;
    // Quarantined nights (reset / pooled / lurch) are named in the catalog;
    // say how many and why, so the trend's denominator is never a mystery.
    const q = data.catalog.quarantined ?? [];
    if (q.length) {
      const counts = {};
      for (const entry of q) counts[entry.reason] = (counts[entry.reason] ?? 0) + 1;
      const label = ed.labels.quarantineReasons;
      note += tpl(ed.noteQuarantined, {
        n: fmtInt(q.length),
        days: fmtInt(data.catalog.days_observed),
        reasons: Object.entries(counts)
          .map(([r, n]) => `${fmtInt(n)} ${label[r] ?? r}`)
          .join(", "),
      });
    }
    noteEl.textContent = note;
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

  // Excluded and missed nights are empty slots: the lines break there
  // (gaps.js). The tooltip says which of the two a slot is.
  const cal = calendar(gap.days);
  const days = cal.rows;
  const n = cal.slots.length;
  const excluded = new Map((data.catalog.quarantined ?? []).map((q) => [q.date, q.reason]));
  const SERIES = [
    { name: ed.legendPct, color: C.accent, value: (d) => d.pct_moved },
    { name: ed.legendProb, color: C.versions.v3, value: (d) => d.prob_moved },
  ];

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 40, bottom: n > 16 ? 52 : 34 },
    legend: { ...baseLegend, data: SERIES.map((s) => s.name) },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const i = params.length ? params[0].dataIndex : -1;
        const d = days[i];
        if (!d) {
          const date = cal.slots[i];
          if (!date) return "";
          const reason = excluded.get(date);
          return gapTooltip(date, reason
            ? tpl(ed.labels.tipExcluded, { reason: ed.labels.quarantineReasons[reason] ?? reason })
            : ed.labels.tipMissed);
        }
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
    xAxis: catAxis(cal.slots, {
      axisLabel: { ...catAxis([]).axisLabel, rotate: n > 16 ? 45 : 0 },
    }),
    yAxis: valAxis({
      max: 100,
      name: ed.yAxisLabel,
      // anchored over the plot: centred on the axis it clipped at the left edge
      nameTextStyle: { color: C.faint, fontSize: 10, align: "left" },
      axisLabel: { ...valAxis().axisLabel, formatter: (v) => `${v}%` },
    }),
    series: SERIES.map(({ name, color, value }) => ({
      name,
      type: "line",
      color,
      symbol: "circle",
      // Dense record: no dots, except a night with a gap on both sides,
      // which has no line segment and would otherwise not show at all.
      symbolSize: n > 40 ? loneSymbol(cal, 5) : 5,
      showAllSymbol: true,
      lineStyle: { width: 2 },
      areaStyle: name === ed.legendPct ? { opacity: 0.1 } : undefined,
      emphasis: { focus: "series" },
      data: gapData(cal, value),
    })),
  });
}
