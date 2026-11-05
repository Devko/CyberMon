// Chart 6 — NVD queue waits as a survival curve. Contract:
// site/data/nvd_throughput.json, block `queue_survival` (built by
// pipeline/nvd_throughput.py from the nightly exit log). Editions built
// before the block existed lack it; the section then shows its empty state.
// The headline is filled in cve.js (fillQueueSurvival), like CVSS 4.0's.
import { C, mkChart, valAxis, baseTooltip, baseGrid, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.queue_survival;
  const s = data.queue_survival;

  // ---- stat card ------------------------------------------------------------
  // Three states: no exit log yet; a log too young to publish (the count
  // still accumulating, the throughput median's min_known idea); a
  // published curve with its median (or "over" the horizon when the curve
  // has not reached 50% yet).
  const card = el("div", "stat-card");
  const exits = s ? s.exits.analyzed + s.exits.deferred + s.exits.other : 0;
  if (!s || !s.log_start) {
    card.append(
      el("div", "stat-big", fmtInt(0)),
      el("div", "stat-lead", ed.statCountLabel),
      el("div", "stat-note", ed.statNoLogNote)
    );
  } else if (!s.ready) {
    card.append(
      el("div", "stat-big", fmtInt(exits)),
      el("div", "stat-lead", ed.statCountLabel),
      el("div", "stat-note", tpl(ed.statCountNote, {
        log_start: s.log_start, waiting: fmtInt(s.censored.waiting),
      }))
    );
  } else {
    const big = s.median_days !== null
      ? tpl(ed.statMedianBig, { days: fmtInt(s.median_days) })
      : tpl(ed.statAboveBig, { days: fmtInt(s.horizon_days) });
    card.append(
      el("div", "stat-big accent", big),
      el("div", "stat-lead", ed.statMedianLabel),
      el("div", "stat-note", tpl(ed.statMedianNote, {
        exits: fmtInt(exits), deferred: fmtInt(s.exits.deferred),
        waiting: fmtInt(s.censored.waiting), log_start: s.log_start,
      }))
    );
  }
  slots.stat.append(card);

  // ---- the curve --------------------------------------------------------------
  const curve = s?.ready ? (s.curve || []) : [];
  if (!curve.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", ed.nodata || editorial.ui.nodata));
    return;
  }

  const L = ed.labels;
  // Day 0 is 100% by definition; each curve point is the share still
  // waiting after that day's exits. step "end": flat until the next day
  // with an exit, then down.
  const points = [[0, 100], ...curve.map((p) => [p.day, p.pct_waiting])];
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, right: 24, top: 24, bottom: 48 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const i = params[0]?.dataIndex;
        if (i == null) return "";
        const p = i === 0 ? null : curve[i - 1];
        const day = i === 0 ? 0 : p.day;
        const pct = i === 0 ? 100 : p.pct_waiting;
        let html =
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(tpl(L.tipDay, { day: fmtInt(day) }))}</div>` +
          `<strong>${escapeHtml(tpl(L.tipWaiting, { pct: fmtPct(pct) }))}</strong>`;
        if (p) {
          html += "<br>" + escapeHtml(tpl(L.tipWatch, { n: fmtInt(p.at_risk), exits: fmtInt(p.exits) }));
        }
        return html;
      },
    },
    xAxis: valAxis({
      min: 0, max: s.horizon_days,
      name: "days", nameLocation: "middle", nameGap: 26,
      nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
      // the horizon is rarely a round number: its label would crowd the
      // last round tick, and the curve's end marks it anyway
      axisLabel: { ...valAxis().axisLabel, showMaxLabel: false },
      axisLine: { show: true, lineStyle: { color: C.rule } },
      splitLine: { show: false },
    }),
    yAxis: valAxis({
      min: 0, max: 100,
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series: [{
      name: L.waiting,
      type: "line",
      step: "end",
      data: points,
      color: C.accent,
      symbol: "none",
      lineStyle: { width: 2 },
      areaStyle: { color: C.accent, opacity: 0.07 },
    }],
  });
}
