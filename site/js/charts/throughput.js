// Chart 5 — NVD throughput. Contract: site/data/nvd_throughput.json
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, baseLegend, tooltipRows, fmtInt, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.throughput;
  const hist = data.history;

  // The static note carries a {first_date} placeholder — the record's
  // actual start date, once the rows are here (thin-launch honesty: an
  // empty record starts "today").
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    noteEl.textContent = tpl(ed.note, {
      first_date: hist[0]?.date ?? "today",
    });
  }

  // ---- stat card: the queue clock -------------------------------------------
  // Data-driven switch (contract: min_known_duration): once enough queue
  // exits carry a known entry date, the median publishes; until then the
  // card shows the count still accumulating — a number, not a promise.
  const q = data.queue;
  const card = el("div", "stat-card");
  if (q.median_days !== null && q.n_known_duration >= data.min_known_duration) {
    card.append(
      el("div", "stat-big accent", tpl(ed.statMedianBig, { days: fmtInt(q.median_days) })),
      el("div", "stat-lead", ed.statMedianLabel),
      el("div", "stat-note", tpl(ed.statMedianNote, { n: fmtInt(q.n_known_duration) }))
    );
  } else {
    card.append(
      el("div", "stat-big", fmtInt(q.n_known_duration)),
      el("div", "stat-lead", ed.statCountLabel),
      el("div", "stat-note", tpl(ed.statCountNote, { min_known: fmtInt(data.min_known_duration) }))
    );
  }
  slots.stat.append(card);

  // ---- daily flow (CyberMon's own nightly transition record) ----------------
  slots.panel.insertBefore(el("div", "panel-subtitle", ed.lineTitle), slots.chart);
  const line = mkChart(slots.chart);
  line.setOption({
    grid: { ...baseGrid, left: 52, right: 36, top: 40, bottom: 24 },
    legend: { ...baseLegend, top: 0 },
    tooltip: {
      ...baseTooltip, trigger: "axis",
      formatter: (params) => {
        let html = tooltipRows(params, fmtInt);
        const i = params[0]?.dataIndex;
        if (i != null && hist[i]?.resweep) {
          html += `<div style="margin-top:4px;color:${C.muted};">${ed.resweepFlag}</div>`;
        }
        return html;
      },
    },
    xAxis: catAxis(hist.map((d) => d.date), {
      boundaryGap: false,
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 10, formatter: (v) => v.slice(2) },
    }),
    yAxis: valAxis({
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: (v) => fmtInt(v) },
    }),
    // Visible symbols on purpose: a young record (one diff = no line
    // segment yet) still renders points instead of nothing. Resweep days
    // get a hollow marker so a catch-up lump never reads as a trend.
    series: [
      {
        name: ed.seriesAnalyzed, type: "line",
        data: hist.map((d) => d.analyzed_from_awaiting),
        color: C.accent, symbol: "circle", symbolSize: 5,
        lineStyle: { width: 2 },
        areaStyle: { color: C.accent, opacity: 0.07 },
      },
      {
        name: ed.seriesDeferred, type: "line",
        data: hist.map((d) => d.deferred_from_awaiting),
        color: C.faint, symbol: "circle", symbolSize: 4,
        lineStyle: { width: 1, type: [4, 4] },
      },
      {
        name: ed.seriesReceived, type: "line",
        data: hist.map((d) => d.received_new),
        color: C.muted, symbol: "circle", symbolSize: 4,
        lineStyle: { width: 1 },
      },
      {
        // helper series (underscore name: legends skip it): rings on
        // resweep days across all three flows' x positions.
        name: "_resweep", type: "scatter",
        data: hist.map((d, i) => (d.resweep ? [i, d.analyzed_from_awaiting] : null)).filter(Boolean),
        color: C.ink, symbol: "circle", symbolSize: 9,
        itemStyle: { color: "transparent", borderColor: C.muted, borderWidth: 1 },
        tooltip: { show: false },
        z: 1,
      },
    ],
  });
}
