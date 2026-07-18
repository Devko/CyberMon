// Hero — the Vulnrichment handoff curve. Contract: site/data/adp_coverage.json
// Monthly CISA-ADP enrichment volume, bucketed by the CISA-ADP container's
// OWN dateUpdated (never the CVE's publish date — CISA back-fills legacy
// records). Sweep months (a legacy-heavy bulk pass) are drawn in accent red.
// The optional NVD-backlog context comes from adp.js (best-effort read of
// nvd_decay.json) and is shown as prose, never charted as a fabricated line.
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, fmtPct,
  escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export function render(slots, data, ctx) {
  const ed = editorial.sections.adp_handoff;
  const h = data.headline;
  const months = data.months || [];

  // ---- headline stat: CISA-ADP's share of the published corpus ---------------
  const stat = el("div", "hero-stat");
  stat.append(el("div", "hero-stat-label", ed.statLabel));
  const row = el("div", "hero-stat-row");
  if (h && months.length && Number.isFinite(h.pct_cisa)) {
    row.append(
      el("span", "hero-num accent", fmtPct(h.pct_cisa)),
      el("span", "hero-when", tpl(ed.statNote, {
        cisa: fmtInt(h.total_cisa),
        total: fmtInt(h.total_published),
      }))
    );
  } else {
    row.append(el("span", "hero-when muted", ed.nodata));
  }
  stat.append(row);
  slots.stat.append(stat);

  // ---- chart -----------------------------------------------------------------
  if (!months.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }

  const cats = months.map((m) => m.month);
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: 24, bottom: 40 },
    tooltip: {
      ...baseTooltip,
      formatter: (p) => {
        const m = months[p.dataIndex];
        if (!m) return "";
        let html =
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(m.month)}</div>` +
          `<strong>${fmtInt(m.enriched)}</strong> records enriched<br>` +
          `<span style="color:${C.muted};">SSVC ${fmtInt(m.ssvc)} · ` +
          `CVSS ${fmtInt(m.cvss)} · CWE ${fmtInt(m.cwe)}</span>`;
        if (m.backfill) {
          html +=
            `<div style="margin-top:6px;padding-top:6px;border-top:1px dashed ${C.rule};` +
            `color:${C.accent};">${escapeHtml(ed.sweepTooltip)}</div>` +
            `<span style="color:${C.muted};">${fmtInt(m.legacy)} of ` +
            `${fmtInt(m.enriched)} on legacy CVEs</span>`;
        }
        return html;
      },
    },
    xAxis: catAxis(cats, {
      // interval:0 with a January-only formatter keeps a clean year axis over
      // a ~two-year monthly span without crowding.
      axisLabel: {
        ...{ color: C.muted, fontFamily: MONO, fontSize: 11 },
        interval: 0,
        formatter: (val, idx) => {
          const [year, mo] = String(val).split("-");
          return idx === 0 || mo === "01" ? year : "";
        },
      },
    }),
    yAxis: valAxis({
      minInterval: 1,
      axisLabel: {
        color: C.muted, fontFamily: MONO, fontSize: 11,
        formatter: (v) => (v >= 1000 ? `${v / 1000}k` : v),
      },
    }),
    series: [
      {
        name: "Enriched",
        type: "bar",
        barWidth: "70%",
        data: months.map((m) => ({
          value: m.enriched,
          // Sweep months read in accent; ordinary enrichment stays neutral.
          itemStyle: { color: m.backfill ? C.accent : C.versions.v4 },
        })),
      },
    ],
  });

  // ---- notes: sweep legend, then the best-effort NVD-backlog context --------
  if (h.backfill_month_count > 0) {
    slots.extra.append(el("p", "panel-note", ed.sweepNote));
  }
  const backlog = ctx?.nvdBacklog;
  if (Number.isFinite(backlog)) {
    slots.extra.append(
      el("p", "panel-note", tpl(ed.nvdContext, { backlog: fmtInt(backlog) }))
    );
  }
}
