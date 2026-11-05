// AI Product CVEs 1 (hero) — CVEs in the classifier's AI products per
// publication year, stacked by category, as counts or as a share of the
// year's published CVEs. Contract: site/data/ai_products.json (shared by all
// four sections; aisurface.js fetches it once). The site computes shares
// from the counts, so sub-1% shares keep their precision.
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid,
  fmtInt, fmtPct, escapeHtml, tooltipFootnote,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";
import { mkToggle } from "../ui.js";

// Newsprint-neutral, ordered dark to light from the bottom of the stack;
// the accent stays off (no category is the alarm).
const COLORS = {
  frameworks: C.sev.low,
  serving: C.sev.high,
  platforms: C.versions.v4,
  apps: C.versions.v3,
};

const shareOf = (n, d) => (d ? (n / d) * 100 : 0);

export function render(slots, data) {
  const ed = editorial.sections.aisurface_years;
  const L = ed.labels;
  const h = data.headline || {};
  const rows = data.years || [];
  const cats = data.categories || [];

  // ---- headline stat --------------------------------------------------------
  const stat = el("div", "hero-stat");
  stat.append(el("div", "hero-stat-label", ed.statLabel));
  const row = el("div", "hero-stat-row");
  if (rows.length && h.latest_year) {
    row.append(
      el("span", "hero-num accent", fmtInt(h.current_ai)),
      el("span", "hero-when", tpl(ed.statCurrent, {
        current_year: h.current_year, current_share: fmtPct(h.current_share_pct),
      })),
      el("span", "hero-vs", editorial.ui.vs),
      el("span", "hero-num", fmtInt(h.latest_ai)),
      el("span", "hero-when", tpl(ed.statLatest, {
        latest_year: h.latest_year, latest_share: fmtPct(h.latest_share_pct),
      }))
    );
  } else {
    row.append(el("span", "hero-when muted", ed.nodata));
  }
  stat.append(row);
  slots.stat.append(stat);

  if (!rows.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }

  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const xcats = rows.map((d) => (d.year === genYear ? `${d.year}*` : String(d.year)));

  const chart = mkChart(slots.chart);
  const draw = (asShare) => {
    chart.setOption(
      {
        grid: { ...baseGrid, left: 52, top: slots.chart.clientWidth < 600 ? 60 : 40 },
        legend: { ...baseLegend, itemHeight: 8, data: cats.map((c) => L.categories[c]) },
        tooltip: {
          ...baseTooltip,
          trigger: "axis",
          axisPointer: { type: "shadow" },
          formatter: (params) => {
            const r = rows[params[0]?.dataIndex];
            if (!r) return "";
            const head = `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(xcats[params[0].dataIndex])}</div>`;
            const body = [...cats].reverse().map((c) => {
              const p = params.find((q) => q.seriesName === L.categories[c]);
              return `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
                `<span>${p ? p.marker : ""} ${escapeHtml(L.categories[c])}</span>` +
                `<strong style="font-family:inherit">${fmtInt(r.by_category[c])}</strong></div>`;
            }).join("");
            return head + body + tooltipFootnote([
              tpl(L.tipTotal, {
                ai: fmtInt(r.ai), published: fmtInt(r.published),
                share: fmtPct(shareOf(r.ai, r.published)),
              }),
              tpl(L.tipNamed, { named: fmtPct(shareOf(r.named, r.published)) }),
              ...(r.top_product
                ? [tpl(L.tipTop, { label: r.top_product.label, n: fmtInt(r.top_product.n) })]
                : []),
            ]);
          },
        },
        xAxis: catAxis(xcats),
        yAxis: valAxis({
          min: 0,
          axisLabel: {
            color: C.muted, fontFamily: MONO, fontSize: 11,
            formatter: asShare ? (v) => `${v}%` : (v) => fmtInt(v),
          },
        }),
        series: cats.map((c) => ({
          name: L.categories[c],
          type: "bar",
          stack: "ai",
          barWidth: "62%",
          itemStyle: { color: COLORS[c], borderColor: C.panel, borderWidth: 1 },
          data: rows.map((r) => (asShare
            ? +shareOf(r.by_category[c], r.published).toFixed(3)
            : r.by_category[c])),
        })),
      },
      { replaceMerge: ["series", "yAxis"] }
    );
  };
  slots.controls.append(mkToggle([ed.toggleCount, ed.toggleShare], (i) => draw(i === 1)));
  draw(false);
}
