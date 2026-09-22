// Record Tags 1 (hero) — the three schema tags per publication year, as
// record counts or as a share of the year's published records. Contract:
// site/data/cve_tags.json (shared by all three tag sections; tags.js
// fetches it once). The site computes shares from the two counts, so tiny
// shares keep their precision.
import { C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, escapeHtml } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";
import { mkToggle } from "../ui.js";

// Accent reserved for the module's subject; disputed in ink so its flat line
// stays legible next to it; the hosted-service tag recedes.
const TAGS = [
  { key: "unsupported-when-assigned", color: C.accent, width: 2.5 },
  { key: "disputed", color: C.ink, width: 1.5 },
  { key: "exclusively-hosted-service", color: C.muted, width: 1.25, dash: [4, 3] },
];

// Shares here run well below 1%, so they print with two decimals.
const fmtShare = (v) => (Number.isFinite(v) ? `${v.toFixed(2)}%` : "—");

export function render(slots, data) {
  const ed = editorial.sections.tags_trend;
  const h = data.headline || {};
  const rows = data.years || [];

  // ---- headline stat --------------------------------------------------------
  const stat = el("div", "hero-stat");
  stat.append(el("div", "hero-stat-label", ed.statLabel));
  const row = el("div", "hero-stat-row");
  if (rows.length && h.unsupported_first_year) {
    row.append(
      el("span", "hero-num accent", fmtInt(h.unsupported_latest)),
      el("span", "hero-when", tpl(ed.statLatest, { latest_year: h.latest_year })),
      el("span", "hero-vs", "vs"),
      el("span", "hero-num", fmtInt(h.unsupported_first)),
      el("span", "hero-when", tpl(ed.statFirst, { first_year: h.unsupported_first_year })),
      el("span", "hero-when muted", "· " + tpl(ed.statCurrent, {
        current: fmtInt(h.unsupported_current), current_year: h.current_year,
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

  // ---- chart ----------------------------------------------------------------
  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = rows.map((d) => (d.year === genYear ? `${d.year}*` : String(d.year)));
  const shareOf = (r, key) => (r.published ? (r.counts[key] / r.published) * 100 : 0);

  const chart = mkChart(slots.chart);
  const draw = (asShare) => {
    chart.setOption(
      {
        // the three long tag names wrap to two legend rows on phones
        grid: { ...baseGrid, left: 50, top: slots.chart.clientWidth < 600 ? 72 : 48 },
        legend: { ...baseLegend, data: TAGS.map((t) => ed.tagLabels[t.key]) },
        tooltip: {
          ...baseTooltip,
          trigger: "axis",
          formatter: (params) => {
            const r = rows[params[0]?.dataIndex];
            if (!r) return "";
            const head = `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(cats[params[0].dataIndex])}</div>`;
            return head + TAGS.map((t) => {
              const p = params.find((q) => q.seriesName === ed.tagLabels[t.key]);
              const marker = p ? p.marker : "";
              return `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
                `<span>${marker} ${escapeHtml(ed.tagLabels[t.key])}</span>` +
                `<strong style="font-family:inherit">${fmtInt(r.counts[t.key])}</strong></div>` +
                `<div style="color:${C.muted};text-align:right;">${escapeHtml(tpl(ed.tooltipShare, {
                  pct: fmtShare(shareOf(r, t.key)), published: fmtInt(r.published),
                }))}</div>`;
            }).join("");
          },
        },
        xAxis: catAxis(cats, { boundaryGap: false }),
        yAxis: valAxis({
          min: 0,
          axisLabel: {
            color: C.muted, fontFamily: MONO, fontSize: 11,
            formatter: asShare ? (v) => `${v}%` : (v) => fmtInt(v),
          },
        }),
        series: TAGS.map((t) => ({
          name: ed.tagLabels[t.key],
          type: "line",
          data: rows.map((r) => (asShare ? +shareOf(r, t.key).toFixed(3) : r.counts[t.key])),
          color: t.color,
          symbol: "circle",
          symbolSize: 4,
          showSymbol: false,
          lineStyle: { width: t.width, ...(t.dash ? { type: t.dash } : {}) },
          z: t.key === "unsupported-when-assigned" ? 5 : 3,
        })),
      },
      { replaceMerge: ["series", "yAxis"] }
    );
  };
  slots.controls.append(mkToggle([ed.toggleCount, ed.toggleShare], (i) => draw(i === 1)));
  draw(false);

  // ---- context: CNA-private and ADP tags (listed, not charted) --------------
  const ctx = data.context || {};
  const list = (items) => (items || []).map((t) => `${t.tag} ${fmtInt(t.n)}`).join(" · ");
  if (ctx.private_tags?.length) {
    slots.extra.append(el("p", "panel-note", tpl(ed.contextNote, {
      private: fmtInt(ctx.private_tag_count),
      top: list(ctx.private_tags.slice(0, 3)),
      adp: ctx.adp_tags?.length ? list(ctx.adp_tags) : "none",
    })));
  }
}
