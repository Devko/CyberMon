// Chart 4 — NVD decay. Contract: site/data/nvd_decay.json
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, tooltipRows, fmtInt, MONO } from "../theme.js";
import { editorial } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.decay;

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

  // ---- current backlog by status --------------------------------------------
  const statuses = [...data.current.statuses].sort((a, b) => a.n - b.n);
  const bars = mkChart(barsEl);
  bars.setOption({
    grid: { left: 8, right: 56, top: 10, bottom: 10, containLabel: true },
    tooltip: { ...baseTooltip, formatter: (p) => `${p.name}<br><strong>${fmtInt(p.value)}</strong> CVEs` },
    xAxis: { type: "value", show: false },
    yAxis: catAxis(statuses.map((s) => s.status), { axisLine: { show: false } }),
    series: [{
      type: "bar",
      data: statuses.map((s) => s.n),
      barWidth: 14,
      itemStyle: { color: C.accent },
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
        color: C.muted, symbol: "none",
        lineStyle: { width: 1, type: [4, 4] },
      },
    ],
  });
}
