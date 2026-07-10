// Calendar 1 (hero) — reservation aging. Contract: site/data/cve_calendar.json
// (id_age section). Stacked 100% bands: share of each year's published
// records whose CVE ID was minted the same year / one year / 2+ years
// earlier. Accent ink on the 2+ band — the stale-paperwork tail is the
// chart's point.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, fmtPct, escapeHtml } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.reservation;
  const rows = data.id_age.years || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // ---- headline stat (inflation.js pattern; payload-authoritative years) ----
  const h = data.id_age.headline;
  if (h) {
    const stat = el("div", "hero-stat");
    stat.append(
      el("div", "hero-stat-label", ed.statLabel),
      frag(
        (() => {
          const row = el("div", "hero-stat-row");
          row.append(
            el("span", "hero-num accent", fmtPct(h.pct_prior_year_latest)),
            el("span", "hero-when", tpl(ed.statLatest, { latest_year: h.latest_year })),
            el("span", "hero-vs", "vs"),
            el("span", "hero-num", fmtPct(h.pct_prior_year_baseline)),
            el("span", "hero-when", tpl(ed.statAgo, { ago_year: h.baseline_year }))
          );
          return row;
        })()
      )
    );
    slots.stat.append(stat);
  }

  // ---- chart ----------------------------------------------------------------
  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = rows.map((r) => (r.year === genYear ? `${r.year}*` : String(r.year)));

  // Stacking order bottom -> top: same-year carries the mass; the aged IDs
  // sit on top where the eye reads the trend.
  const BANDS = [
    { pctKey: "pct_same_year", nKey: "same_year", name: ed.legendSameYear, color: C.sev.low },
    { pctKey: "pct_one_year", nKey: "one_year", name: ed.legendOneYear, color: C.sev.high },
    { pctKey: "pct_two_plus", nKey: "two_plus", name: ed.legendTwoPlus, color: C.accent },
  ];

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 44 },
    legend: { ...baseLegend, data: BANDS.map((b) => b.name).reverse(), icon: "rect", itemHeight: 8 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const r = params.length && rows[params[0].dataIndex];
        if (!r) return "";
        const head =
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(String(params[0].axisValueLabel ?? params[0].name))}` +
          ` · ${fmtInt(r.n)} records</div>`;
        const body = [...BANDS].reverse().map(({ pctKey, nKey, name, color }) =>
          `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
          `<span><span style="display:inline-block;width:8px;height:8px;background:${color};margin-right:6px;"></span>` +
          `${escapeHtml(name)}</span>` +
          `<strong style="font-family:inherit">${fmtPct(r[pctKey])} · ${fmtInt(r[nKey])}</strong></div>`
        ).join("");
        return head + body;
      },
    },
    xAxis: catAxis(cats, { boundaryGap: false }),
    yAxis: valAxis({
      min: 0, max: 100,
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series: BANDS.map(({ pctKey, name, color }) => ({
      name,
      type: "line",
      stack: "age",
      areaStyle: { color, opacity: pctKey === "pct_two_plus" ? 0.9 : 0.75 },
      lineStyle: { width: 0 },
      color,
      symbol: "none",
      emphasis: { focus: "series" },
      data: rows.map((r) => r[pctKey]),
    })),
  });
}
