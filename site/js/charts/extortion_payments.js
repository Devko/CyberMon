// Extortion 2 — payment counts and median payment size per year. Contract:
// site/data/extortion_ledger.json (shared fetch, see extortion.js).
// Bars: distinct on-chain payments per year (left axis). Line: median
// payment USD (right axis, LOG scale — the median spans four orders of
// magnitude, from hundreds of dollars in the mass-campaign years to six
// figures). Years below min_n carry no median in the payload; the line
// simply skips them (absence is "not charted", never zero).
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, escapeHtml, MONO } from "../theme.js";
import { editorial } from "../editorial.js";
import { el } from "../dom.js";
import { fmtUSD, fmtUSDCompact } from "./extortion_fmt.js";

export function render(slots, data) {
  const ed = editorial.sections.payments;
  const rows = data.payments_by_year || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = rows.map((r) => (r.year === genYear ? `${r.year}*` : String(r.year)));

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 54, right: 62, top: 36 },
    legend: {
      ...baseLegend,
      data: [ed.legendPayments, ed.legendMedian],
    },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const p = params[0];
        const r = p && rows[p.dataIndex];
        if (!r) return "";
        // Sub-$100 medians keep their cents (2013's median is $0.03 —
        // rounding it to "$0" would chart a payment that wasn't there).
        const fmtMedian = (v) => (v < 100 ? `$${Number(v).toFixed(2)}` : fmtUSD(v));
        const median = "median_usd" in r
          ? `median payment <strong>${fmtMedian(r.median_usd)}</strong>`
          : `median not shown (fewer than ${fmtInt(data.min_n)} payments)`;
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(p.axisValueLabel ?? p.name))}</div>` +
          `<strong>${fmtInt(r.payments)}</strong> verified payments · ${fmtUSD(r.usd)} total<br>` +
          median
        );
      },
    },
    xAxis: catAxis(cats),
    yAxis: [
      valAxis({
        name: "payments",
        minInterval: 1, // counts — never fractional ticks
        nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
      }),
      valAxis({
        type: "log",
        name: "median USD (log)",
        nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
        position: "right",
        splitLine: { show: false },
        axisLabel: { ...valAxis().axisLabel, formatter: (v) => fmtUSDCompact(v) },
      }),
    ],
    series: [
      {
        name: ed.legendPayments, type: "bar", barWidth: "55%",
        data: rows.map((r) => r.payments),
        itemStyle: { color: C.ink, opacity: 0.55 },
      },
      {
        name: ed.legendMedian, type: "line", yAxisIndex: 1,
        // null = year below min_n (or a literal-zero median, which a log
        // axis cannot place): the line skips it rather than inventing 0.
        data: rows.map((r) => (r.median_usd > 0 ? r.median_usd : null)),
        color: C.accent,
        symbol: "circle", symbolSize: 5,
        lineStyle: { width: 2 }, z: 5,
      },
    ],
  });
}
