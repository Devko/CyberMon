// ATT&CK 1 (hero) — the growing map: active techniques and sub-techniques
// per enterprise release. Contract: site/data/attack_churn.json (shared by
// all three ATT&CK sections; attack.js fetches it once). The x-axis is
// real time (release dates), NOT a category axis: ATT&CK ships roughly
// twice a year at uneven gaps, and equal spacing would flatten the
// calendar. Step lines, because a count holds until the next release.
import { C, mkChart, timeAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.map;
  const rows = data.versions || [];

  // ---- headline stat: active technique+sub-technique total, first vs latest
  const h = data.headline;
  const stat = el("div", "hero-stat");
  stat.append(el("div", "hero-stat-label", ed.statLabel));
  const row = el("div", "hero-stat-row");
  if (h) {
    row.append(
      el("span", "hero-num accent", fmtInt(h.techniques_latest + h.subtechniques_latest)),
      el("span", "hero-when", tpl(ed.statLatest, {
        version: h.latest_version, year: h.released_latest.slice(0, 4),
      })),
      el("span", "hero-vs", "vs"),
      el("span", "hero-num", fmtInt(h.techniques_first + h.subtechniques_first)),
      el("span", "hero-when", tpl(ed.statAgo, {
        version: h.first_version, year: h.released_first.slice(0, 4),
      }))
    );
  } else {
    // Empty history: no invented comparison, just an honest muted state.
    row.append(el("span", "hero-when muted", "Not enough data yet."));
  }
  stat.append(row);
  slots.stat.append(stat);

  // ---- chart ----------------------------------------------------------------
  if (!rows.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 36 },
    legend: { ...baseLegend, data: [ed.legendTechniques, ed.legendSubtechniques] },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const r = params[0] && rows[params[0].dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(`v${r.version} · ${r.released}`)}</div>` +
          `${escapeHtml(ed.legendTechniques)} <strong>${fmtInt(r.techniques)}</strong><br>` +
          `${escapeHtml(ed.legendSubtechniques)} <strong>${fmtInt(r.subtechniques)}</strong>`
        );
      },
    },
    xAxis: timeAxis(),
    yAxis: valAxis({
      name: "active entries",
      nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
    }),
    series: [
      {
        name: ed.legendTechniques, type: "line", step: "end",
        data: rows.map((r) => [r.released, r.techniques]),
        color: C.versions.v3,
        symbol: "circle", symbolSize: 4,
        lineStyle: { width: 2 }, z: 4,
      },
      {
        name: ed.legendSubtechniques, type: "line", step: "end",
        data: rows.map((r) => [r.released, r.subtechniques]),
        color: C.accent,
        symbol: "circle", symbolSize: 4,
        lineStyle: { width: 2 }, z: 5,
      },
    ],
  });
}
