// oss_common.js — shared bits for the Open-Source Maintainers page (oss.html): registry
// display names, the fixed registry order, the 100%-stacked horizontal bar
// every section draws, and the template fill for captions / methodology the
// page script hands over. Contract: site/data/oss_maintainers.json.
import {
  C, MONO, mkChart, catAxis, valAxis, baseGrid, baseLegend, baseTooltip,
  escapeHtml, fmtPct,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export const regLabel = (id) => editorial.ossRegistries[id] ?? id;

// Fill a caption / methodology paragraph handed over by the page script
// (absent on carousel slides, which print neither).
export function fillRef(node, vars) {
  if (node) node.textContent = tpl(node.textContent, vars);
}

// The universe facts every methodology names.
export function universeVars(data) {
  const u = data.universe || {};
  const o = data.observed || {};
  return {
    edition: u.edition,
    rule_version: u.rule_version,
    selected_at: u.selected_at,
    per: u.per_ecosystem,
    floor: (u.download_floor ?? 0).toLocaleString("en-US"),
    refresh: o.refresh_days,
    max_age: o.max_age_days,
    sc_age: data.scorecard_dates?.max_age_days,
  };
}

// The page's empty-edition card: an honest "not yet", not an error.
export function noEdition(slots, text, refs) {
  for (const node of [refs?.caption, refs?.methodText]) {
    if (node) node.textContent = node.textContent.replace(/\{\w+\}/g, "—");
  }
  slots.chart.classList.remove("chart", "chart-tall");
  slots.chart.removeAttribute("role");
  slots.panel.querySelector(".panel-note")?.remove();
  slots.chart.append(el("div", "nodata-card", text));
}

// "Label: a · b · c" tally line under a chart.
export function tally(label, parts) {
  const wrap = el("div", "table-context");
  wrap.append(el("strong", null, `${label}: `));
  wrap.append(parts.join(" · "));
  return wrap;
}

const pct1 = (n, d) => (d ? Math.round((1000 * n) / d) / 10 : 0);

// Legend rows at this chart's width, and a chart height that fits them plus
// `plot` pixels of bars, so a phone's wrapped legend never sits on the bars.
// Item width: swatch + gap + the label in 11px mono (~6.7 px a character).
export function fitLegend(chartEl, names, plot) {
  const width = (chartEl.clientWidth || 800) - 24;
  let rows = 1;
  let line = 0;
  for (const name of names) {
    const w = 14 + 5 + name.length * 6.7 + 12;
    if (line > 0 && line + w > width) {
      rows += 1;
      line = w;
    } else {
      line += w;
    }
  }
  const top = 12 + rows * 20;
  // Carousel slides size their chart hosts themselves (carousel.js fit pass).
  if (!chartEl.closest(".slide")) chartEl.style.height = `${top + plot + 46}px`;
  return top;
}

// A segmented toggle that wraps onto more rows on a phone instead of
// running off the panel's left edge.
export function wrapToggle(toggle) {
  Object.assign(toggle.style, { flexWrap: "wrap", maxWidth: "100%" });
  for (const b of toggle.querySelectorAll("button")) b.style.whiteSpace = "nowrap";
  return toggle;
}

// One horizontal bar per registry (first registry on top), split into
// segments that each show a share of that registry's `total`. `segments`:
// [{key, name, color}], `count(eco, key)` returns the segment's count, and
// `tip(eco, seg, n, total, pct)` the tooltip text. Segment widths are
// shares, so registries of different sizes compare on one axis.
export function stackedShares(slots, ecos, { segments, count, total, tip, xAxis, labelKey }) {
  const rows = ecos.slice().reverse(); // ECharts draws the first category at the bottom
  const top = fitLegend(slots.chart, segments.map((sg) => sg.name), rows.length * 58);
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 84, right: 24, top, bottom: 40 },
    legend: {
      ...baseLegend,
      data: segments.map((s) => s.name),
      itemHeight: 8,
      type: "plain",
    },
    tooltip: {
      ...baseTooltip,
      trigger: "item",
      formatter: (p) => {
        const eco = rows[p.dataIndex];
        const seg = segments[p.seriesIndex];
        const n = count(eco, seg.key);
        const t = total(eco);
        return escapeHtml(tip(eco, seg, n, t, pct1(n, t)));
      },
    },
    xAxis: valAxis({
      min: 0,
      max: 100,
      name: xAxis,
      nameLocation: "middle",
      nameGap: 26,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: "{value}%" },
    }),
    yAxis: catAxis(rows.map((e) => regLabel(e.id)), {
      axisLabel: { ...catAxis([]).axisLabel, fontSize: 12 },
    }),
    series: segments.map((seg) => ({
      name: seg.name,
      type: "bar",
      stack: "share",
      barWidth: "58%",
      color: seg.color,
      itemStyle: { borderColor: C.panel, borderWidth: 1 },
      data: rows.map((e) => pct1(count(e, seg.key), total(e))),
      label: seg.key === labelKey ? {
        show: true,
        position: "inside",
        color: C.bg,
        fontFamily: MONO,
        fontSize: 11,
        fontWeight: 700,
        formatter: (p) => (p.value >= 9 ? fmtPct(p.value) : ""),
      } : { show: false },
    })),
  });
  return chart;
}
