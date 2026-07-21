// C2 2 — tonight's blocklist composition. Contract:
// site/data/botnet_weather.json (c2_today section). One horizontal bar per
// malware family, split into the online remainder (accent) and listings gone
// dark (neutral); below the chart, the same snapshot cut by hosting country
// and network as text tallies. AGGREGATES ONLY — no address, port or
// hostname ever reaches this page; the module is the weather, not the
// blocklist. Fully real from day one; an empty blocklist renders an honest
// empty card (the tracker's documented post-takedown state).
import {
  C, MONO, mkChart, catAxis, valAxis, baseGrid, baseLegend, baseTooltip,
  fmtInt, escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

// A "label 3 · label 2" text tally line for a [{label, n}] breakdown.
function tallyLine(labelText, entries) {
  const wrap = el("div", "table-context");
  wrap.append(el("strong", null, `${labelText}: `));
  wrap.append(entries.map((e) => `${e.label} ${fmtInt(e.n)}`).join(" · "));
  return wrap;
}

export function render(slots, data) {
  const ed = editorial.sections.c2_today;
  const today = data.c2_today || {};
  const families = today.families || [];

  if (!families.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }

  // Context stat: listed / online / family count — all from the data file.
  slots.stat.append(el("div", "table-context", tpl(ed.statTemplate, {
    listed: fmtInt(today.listed_total),
    online: fmtInt(today.online_total),
    families: fmtInt(families.length),
  })));

  // ECharts plots the first category at the bottom; reverse the
  // listed-descending list to put the biggest family on top.
  const rows = families.slice().reverse();

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 110, right: 32, top: 34, bottom: 36 },
    legend: {
      ...baseLegend,
      data: [ed.legendOnline, ed.legendDark],
      icon: "rect",
      itemHeight: 8,
    },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params) => {
        const r = params.length && rows[params[0].dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">` +
          `${escapeHtml(r.label)}</div>` +
          `<strong>${fmtInt(r.listed)}</strong> listed · ` +
          `<strong>${fmtInt(r.online)}</strong> online`
        );
      },
    },
    xAxis: valAxis({
      name: ed.xAxis,
      nameLocation: "middle",
      nameGap: 24,
      minInterval: 1,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
    }),
    yAxis: catAxis(rows.map((r) => r.label), {
      axisLabel: { ...catAxis([]).axisLabel, fontSize: 11 },
    }),
    series: [
      {
        name: ed.legendOnline,
        type: "bar",
        stack: "c2",
        barWidth: "62%",
        color: C.accent,
        data: rows.map((r) => r.online),
      },
      {
        name: ed.legendDark,
        type: "bar",
        stack: "c2",
        barWidth: "62%",
        color: C.versions.v2,
        data: rows.map((r) => r.listed - r.online),
        label: {
          show: true,
          position: "right",
          color: C.muted,
          fontFamily: MONO,
          fontSize: 11,
          formatter: (p) => fmtInt(rows[p.dataIndex].listed),
        },
      },
    ],
  });

  // The same snapshot cut two more ways — text tallies, never a server table.
  slots.extra.append(
    tallyLine(ed.countriesLabel, today.countries || []),
    tallyLine(ed.asnsLabel, today.asns || [])
  );
}
