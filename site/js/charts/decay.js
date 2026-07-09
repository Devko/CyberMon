// Chart 4 — NVD decay. Contract: site/data/nvd_decay.json
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, tooltipRows, fmtInt, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.decay;

  // The static note carries a {first_date} placeholder — fill it now that
  // the history rows are here (the record's actual start date).
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    noteEl.textContent = tpl(ed.note, {
      first_date: data.history[0]?.date ?? "today",
    });
  }

  // Two panels side by side: current statuses (bars) + backlog history (line).
  const wrap = el("div", "split");
  const left = el("div", "split-col split-col-narrow");
  const right = el("div", "split-col");
  left.append(el("div", "panel-subtitle", ed.barsTitle));
  right.append(el("div", "panel-subtitle", ed.lineTitle));
  const barsEl = el("div", "chart chart-half");
  const lineEl = el("div", "chart chart-half");
  left.append(barsEl);
  right.append(lineEl);
  wrap.append(left, right);
  slots.chart.classList.remove("chart");
  slots.chart.append(wrap);

  // ---- all CVEs by status ----------------------------------------------------
  // Log axis on purpose: Modified is two orders of magnitude bigger than the
  // live queue and a linear axis erases the queue bars entirely. Queue
  // statuses (the backlog definition) get the accent color.
  const QUEUE = new Set(["Received", "Awaiting Analysis", "Undergoing Analysis"]);
  const statuses = [...data.current.statuses]
    .filter((s) => s.n > 0) // log axis cannot place zero
    .sort((a, b) => a.n - b.n);
  const bars = mkChart(barsEl);
  bars.setOption({
    grid: { left: 8, right: 64, top: 10, bottom: 10, containLabel: true },
    tooltip: { ...baseTooltip, formatter: (p) => `${escapeHtml(p.name)}<br><strong>${fmtInt(p.value)}</strong> CVEs` },
    xAxis: { type: "log", show: false, min: 1 },
    yAxis: catAxis(statuses.map((s) => s.status), { axisLine: { show: false } }),
    series: [{
      type: "bar",
      data: statuses.map((s) => ({
        value: s.n,
        itemStyle: { color: QUEUE.has(s.status) ? C.accent : C.faint },
      })),
      barWidth: 14,
      label: { show: true, position: "right", color: C.muted, fontFamily: MONO, fontSize: 11, formatter: (p) => fmtInt(p.value) },
    }],
  });

  // ---- backlog history (CyberMon's own nightly record) ----------------------
  const hist = data.history;
  const line = mkChart(lineEl);
  line.setOption({
    grid: { ...baseGrid, left: 56, top: 16, bottom: 24 },
    tooltip: {
      ...baseTooltip, trigger: "axis",
      formatter: (params) => tooltipRows(params, fmtInt),
    },
    xAxis: catAxis(hist.map((d) => d.date), {
      boundaryGap: false,
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 10, formatter: (v) => v.slice(2) },
    }),
    yAxis: valAxis({
      min: (v) => Math.floor((v.min * 0.96) / 1000) * 1000,
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: (v) => `${v / 1000}k` },
    }),
    series: [
      {
        name: "Backlog total", type: "line",
        data: hist.map((d) => d.backlog_total),
        color: C.accent, symbol: "circle", symbolSize: 5,
        lineStyle: { width: 2 },
        areaStyle: { color: C.accent, opacity: 0.07 },
      },
      {
        name: "Awaiting analysis", type: "line",
        data: hist.map((d) => d.awaiting_analysis),
        // visible symbol so a young history (one snapshot = no line
        // segment yet) still renders a point instead of nothing
        color: C.muted, symbol: "circle", symbolSize: 4,
        lineStyle: { width: 1, type: [4, 4] },
      },
    ],
  });
}
