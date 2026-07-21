// C2 1 (hero) — active botnet C2s over time, by malware family. Contract:
// site/data/botnet_weather.json (c2_weather section; c2.js fetches the file
// once for all three sections). Stacked bars of the online count per family,
// drawn from the committed daily record, with a dashed context line for
// everything still listed. Launch-thin by design — the record begins at
// first deploy and the note says so; single digits (and zero) are normal
// readings here, not broken charts.
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid,
  fmtInt, escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";

// Family palette: a small newsprint ramp, accent first — the stack is the
// star of this page. Cycles if the record ever holds more families.
const FAMILY_COLORS = [
  C.accent, C.versions.v3, C.sev.high, C.versions.v2, C.sev.medium,
  C.versions.v4, C.sev.low,
];

export function render(slots, data) {
  const ed = editorial.sections.c2_weather;
  const weather = data.c2_weather || {};
  const series = weather.series || [];
  const families = weather.families || [];
  const first = weather.first_observed;

  // Thin-launch honesty: the note is data-driven from the record's start.
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    noteEl.textContent = series.length > 1
      ? tpl(ed.note, { first_date: first })
      : ed.noteEmpty;
  }

  // ---- headline stat: tonight's online count, listed context ---------------
  if (weather.current_online != null) {
    const stat = el("div", "hero-stat");
    const row = el("div", "hero-stat-row");
    row.append(
      el("span", "hero-num accent", fmtInt(weather.current_online)),
      el("span", "hero-when", tpl(ed.statWhen, {
        listed: fmtInt(weather.current_listed),
        first_date: first,
      }))
    );
    stat.append(el("div", "hero-stat-label", ed.statLabel), frag(row));
    slots.stat.append(stat);
  }

  const dates = series.map((pt) => pt.date);
  const famSeries = families.map((fam, i) => ({
    name: fam,
    type: "bar",
    stack: "online",
    barMaxWidth: 26,
    color: FAMILY_COLORS[i % FAMILY_COLORS.length],
    emphasis: { focus: "series" },
    data: series.map((pt) => pt.online[fam] ?? 0),
  }));

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 48, top: 44, bottom: 40 },
    legend: {
      ...baseLegend,
      data: [...families, ed.legendListed],
      icon: "rect",
      itemHeight: 8,
    },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const pt = params.length && series[params[0].dataIndex];
        if (!pt) return "";
        const head =
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(pt.date)}</div>`;
        const rows = families
          .filter((fam) => (pt.listed[fam] ?? 0) > 0)
          .map((fam, i) =>
            `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
            `<span><span style="display:inline-block;width:8px;height:8px;` +
            `background:${FAMILY_COLORS[families.indexOf(fam) % FAMILY_COLORS.length]};margin-right:6px;"></span>` +
            `${escapeHtml(fam)}</span>` +
            `<strong style="font-family:inherit">${fmtInt(pt.online[fam] ?? 0)}` +
            `<span style="color:${C.muted}"> / ${fmtInt(pt.listed[fam])}</span></strong></div>`
          ).join("");
        const totals =
          `<div style="color:${C.muted};margin-top:4px;">` +
          `${fmtInt(pt.online_total)} online / ${fmtInt(pt.listed_total)} listed</div>`;
        return head + (rows || "") + totals;
      },
    },
    xAxis: catAxis(dates, {
      axisLabel: { ...catAxis([]).axisLabel, rotate: dates.length > 10 ? 45 : 0 },
    }),
    yAxis: valAxis({
      name: ed.yAxis,
      minInterval: 1,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
    }),
    series: [
      ...famSeries,
      {
        name: ed.legendListed,
        type: "line",
        symbol: "circle",
        symbolSize: dates.length > 40 ? 3 : 5,
        lineStyle: { color: C.muted, width: 1.5, type: "dashed" },
        itemStyle: { color: C.muted },
        data: series.map((pt) => pt.listed_total),
      },
    ],
  });
}
