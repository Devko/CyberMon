// KEV 3 — remediation deadline span, median + IQR band per year.
// Contract: site/data/kev_latency.json (shared by all three KEV sections;
// kev.js fetches it once). Same band idiom as inflation.js / kev_latency.js.
// This cohort INCLUDES the 2021 launch batch on purpose: deadlines are set
// on the listing date, so they measure policy, not backlog age.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

const fmtDays = (v) => `${fmtInt(Math.round(v))}d`;

export function render(slots, data) {
  const ed = editorial.sections.remediation;
  const rows = data.remediation_span_by_year || [];
  if (!rows.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));

  // ---- caption: the latest complete year's median, and the partial
  // current year's when it has listings — from the data, never typed in.
  if (slots.caption) {
    const complete = rows.filter((r) => r.year < genYear);
    const latest = complete[complete.length - 1];
    const current = rows.find((r) => r.year === genYear);
    if (latest) {
      slots.caption.textContent = tpl(ed.caption, {
        latest_year: latest.year,
        latest_median: fmtInt(Math.round(latest.median_days)),
        current_clause: current
          ? tpl(ed.captionCurrentClause, {
              current_year: current.year,
              current_median: fmtDays(current.median_days),
            })
          : "",
      });
    }
  }
  const cats = rows.map((r) => (r.year === genYear ? `${r.year}*` : String(r.year)));

  const medianName = "Median deadline span";
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 24 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      formatter: (params) => {
        const p = params.find((x) => x.seriesName === medianName) ?? params[0];
        const r = p && rows[p.dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(p.axisValueLabel ?? p.name))}</div>` +
          `median <strong>${fmtDays(r.median_days)}</strong> · IQR ${fmtDays(r.p25_days)}–${fmtDays(r.p75_days)}<br>` +
          `${fmtInt(r.n)} entries listed`
        );
      },
    },
    xAxis: catAxis(cats, { boundaryGap: false }),
    yAxis: valAxis({
      name: "days",
      nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
    }),
    series: [
      // IQR band: a light fill with dashed p25 / p75 edges so the middle
      // half keeps a visible boundary on the dark ground (fill alone vanished).
      { // IQR base (p25): its line is the band's lower edge
        name: "_p25", type: "line", stack: "iqr",
        data: rows.map((r) => r.p25_days),
        lineStyle: { color: C.ink, width: 1, type: [3, 3], opacity: 0.55 },
        symbol: "none", silent: true, emphasis: { disabled: true },
      },
      { // IQR band = (p75 − p25) stacked on the base; its line is the p75 edge
        name: "_iqr", type: "line", stack: "iqr",
        data: rows.map((r) => +(r.p75_days - r.p25_days).toFixed(1)),
        lineStyle: { color: C.ink, width: 1, type: [3, 3], opacity: 0.55 },
        areaStyle: { color: C.ink, opacity: 0.12 },
        symbol: "none", silent: true, emphasis: { disabled: true },
      },
      {
        // neutral ink, not accent: a deadline policy is news, not alarm
        name: medianName, type: "line",
        data: rows.map((r) => r.median_days),
        color: C.ink, symbol: "circle", symbolSize: 5,
        lineStyle: { width: 2 }, z: 5,
      },
    ],
  });
}
