// Roster 1 (hero) — roster size over time. Contract: site/data/cna_roster.json
// (roster_size section; roster.js fetches the file once for all three
// sections). A single line of the federation's headcount, drawn from the
// committed snapshot history. It starts as one point — the record begins at
// first deploy — and the note says so; thin is a fact, not a bug (the Silent
// Rescores pattern).
import {
  C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";
import { calendar, gapData, gapTooltip } from "../gaps.js";

export function render(slots, data) {
  const ed = editorial.sections.roster_size;
  const size = data.roster_size || {};
  const series = size.series || [];
  const first = size.first_observed;

  // The static note carries a {first_date} placeholder — fill it from the
  // record's actual start; before two snapshots exist, the launch-night
  // variant renders instead.
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    noteEl.textContent = series.length > 1
      ? tpl(ed.note, { first_date: first })
      : ed.noteEmpty;
  }

  // ---- headline stat: today's headcount, and net change when the record
  // is deep enough to state one (both straight from the data) ---------------
  if (size.current != null) {
    const stat = el("div", "hero-stat");
    const row = el("div", "hero-stat-row");
    const when = size.net_change != null
      ? tpl(ed.statNet, {
          first_date: first,
          net: (size.net_change >= 0 ? "+" : "") + fmtInt(size.net_change),
        })
      : tpl(ed.statSince, { first_date: first });
    row.append(
      el("span", "hero-num accent", fmtInt(size.current)),
      el("span", "hero-when", when)
    );
    stat.append(el("div", "hero-stat-label", ed.statLabel), frag(row));
    slots.stat.append(stat);
  }

  if (!series.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", ed.emptyChart));
    return;
  }

  // A night without a snapshot is an empty slot: the line breaks there.
  const cal = calendar(series);
  const n = cal.slots.length;
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 52, top: 24, bottom: 40 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const p = params[0];
        if (!p) return "";
        if (!cal.rows[p.dataIndex]) return gapTooltip(p.axisValue);
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(p.axisValue)}</div>` +
          tpl(escapeHtml(ed.labels.tipOrgs), { n: `<strong>${fmtInt(p.value)}</strong>` })
        );
      },
    },
    xAxis: catAxis(cal.slots, {
      axisLabel: { ...catAxis([]).axisLabel, rotate: n > 10 ? 45 : 0 },
    }),
    yAxis: valAxis({ name: ed.yAxis, minInterval: 1,
      nameTextStyle: { color: C.muted, fontSize: 11 } }),
    series: [
      {
        name: ed.labels.size,
        type: "line",
        smooth: false,
        symbol: "circle",
        symbolSize: n > 40 ? 3 : 6,
        showSymbol: true,
        lineStyle: { color: C.accent, width: 2 },
        itemStyle: { color: C.accent },
        areaStyle: { color: C.accentSoft },
        data: gapData(cal, (pt) => pt.size),
      },
    ],
  });
}
