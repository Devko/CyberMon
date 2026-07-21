// Time to PoC 3 — PoC coverage by CVSS bucket, latest complete year.
// Contract: site/data/time_to_poc.json (shared; exploits.js fetches it
// once). Bars: the share of the window year's published records that any
// of the three trackers references, per severity bucket, with unscored
// records as a muted extra bar — they attract exploits too, and hiding
// them would flatter the scored corpus.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data) {
  const ed = editorial.sections.poc_coverage;
  const cov = data.coverage || {};

  // ---- window note (panel-note template) ------------------------------------
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    if (Number.isFinite(cov.window_year)) {
      noteEl.textContent = tpl(ed.note, { window_year: cov.window_year });
    } else {
      noteEl.remove();
    }
  }

  const rows = (cov.buckets || []).map((b) => ({ ...b, muted: false }));
  const un = cov.unscored;
  if (un && un.total > 0) {
    rows.push({ bucket: "unscored", ...un, muted: true });
  }
  if (!rows.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 24 },
    tooltip: {
      ...baseTooltip,
      formatter: (p) => {
        const r = rows[p.dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(String(p.name))}</div>` +
          `<strong>${fmtPct(r.pct)}</strong> have a public PoC or template<br>` +
          `${fmtInt(r.with_poc)} of ${fmtInt(r.total)} records published in ${cov.window_year}`
        );
      },
    },
    xAxis: catAxis(rows.map((r) => r.bucket)),
    yAxis: valAxis({
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series: [{
      type: "bar",
      barWidth: "55%",
      data: rows.map((r) => ({
        value: r.pct,
        itemStyle: r.muted
          ? { color: C.muted, opacity: 0.45 }
          : { color: C.accent, opacity: 0.85 },
      })),
      label: {
        show: true, position: "top",
        color: C.muted, fontFamily: MONO, fontSize: 11,
        formatter: (p) => fmtPct(p.value),
      },
    }],
  });
}
