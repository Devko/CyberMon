// Concentration 1 (hero) — top-5/top-10 volume share on a 0–100% axis, with
// the active-CNA roster on a right-hand value axis (a visible, legended
// series — not a hidden helper). Contract: site/data/cna_concentration.json
// (shared by all three concentration sections; concentration.js fetches it
// once). HHI is in the payload but deliberately appears only in the
// methodology footnote — the chart reports shares.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

const TOP5_NAME = "Top-5 share";
const TOP10_NAME = "Top-10 share";
const COUNT_NAME = "Active CNAs";

export function render(slots, data) {
  const ed = editorial.sections.concentration;

  // ---- headline stat --------------------------------------------------------
  const h = data.headline || {};
  const stat = el("div", "hero-stat");
  stat.append(el("div", "hero-stat-label", ed.statLabel));
  const row = el("div", "hero-stat-row");
  if (Number.isFinite(h.top5_share_latest) && Number.isFinite(h.top5_share_baseline)) {
    row.append(
      el("span", "hero-num accent", fmtPct(h.top5_share_latest)),
      el("span", "hero-when", tpl(ed.statLatest, { latest_year: h.latest_year })),
      el("span", "hero-vs", "vs"),
      el("span", "hero-num", fmtPct(h.top5_share_baseline)),
      el("span", "hero-when", tpl(ed.statAgo, { ago_year: h.baseline_year }))
    );
  } else {
    row.append(el("span", "hero-when muted", "Not enough data yet."));
  }
  stat.append(row);
  slots.stat.append(stat);

  // ---- chart ----------------------------------------------------------------
  const years = data.years || [];
  if (!years.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = years.map((d) => (d.year === genYear ? `${d.year}*` : String(d.year)));

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, right: 54, top: 44 },
    legend: { ...baseLegend, data: [TOP5_NAME, TOP10_NAME, COUNT_NAME] },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const head = params.length
          ? `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(params[0].axisValueLabel ?? params[0].name))}</div>`
          : "";
        return head + params
          .filter((p) => p.value !== null && p.value !== undefined && !Number.isNaN(p.value))
          .map((p) =>
            `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
            `<span>${p.marker} ${p.seriesName}</span>` +
            `<strong style="font-family:inherit">${p.seriesName === COUNT_NAME ? fmtInt(p.value) : fmtPct(p.value)}</strong></div>`
          )
          .join("");
      },
    },
    xAxis: catAxis(cats, { boundaryGap: false }),
    yAxis: [
      valAxis({
        min: 0, max: 100,
        axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: "{value}%" },
        name: "share",
        nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
      }),
      valAxis({
        min: 0,
        splitLine: { show: false }, // one set of gridlines is enough
        axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11 },
        name: "CNAs",
        nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
      }),
    ],
    series: [
      {
        name: TOP5_NAME, type: "line", yAxisIndex: 0,
        data: years.map((d) => d.top5_share),
        color: C.accent, symbol: "none",
        lineStyle: { width: 2 }, z: 5,
      },
      {
        name: TOP10_NAME, type: "line", yAxisIndex: 0,
        data: years.map((d) => d.top10_share),
        color: C.ink, symbol: "none",
        lineStyle: { width: 1.5, type: [6, 4] }, z: 4,
      },
      {
        name: COUNT_NAME, type: "line", yAxisIndex: 1,
        data: years.map((d) => d.cna_count),
        color: C.muted, symbol: "none",
        lineStyle: { width: 1, type: [2, 3] }, z: 3,
      },
    ],
  });
}
