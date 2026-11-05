// Support Windows 3 — the median support window per endoflife.date
// category (each product counted once), with how many tracked products have
// their newest line, or every line, out of support. Contract:
// site/data/support_windows.json (categories, catalog). Categories below the
// pipeline's product floor publish no median; they are named under the
// chart instead of being dropped.
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";
import { toYears, yearsLabel, medianTip, noData } from "./eol_shared.js";

export function render(slots, data) {
  const ed = editorial.sections.eol_categories;
  const L = ed.labels;
  const na = editorial.ui.na;
  const c = data.catalog || {};
  const cats = data.categories || [];
  const label = (id) => ed.categoryLabels[id] ?? id;

  // ---- headline stat ------------------------------------------------------------
  const stat = el("div", "hero-stat");
  const row = el("div", "hero-stat-row");
  row.append(
    el("span", "hero-num accent", fmtInt(c.newest_line_ended)),
    el("span", "hero-when", tpl(ed.statWhen, {
      products: fmtInt(c.products),
      no_supported: fmtInt(c.no_supported_line),
    }))
  );
  stat.append(el("div", "hero-stat-label", ed.statLabel), frag(row));
  slots.stat.append(stat);

  const charted = cats.filter((r) => Number.isFinite(r.median_days));
  const thin = cats.filter((r) => !Number.isFinite(r.median_days));
  if (!charted.length) {
    noData(slots, ed.nodata);
    return;
  }

  // Longest window on top: the contract sorts descending, a horizontal bar
  // axis draws bottom-up, so reverse.
  const shown = [...charted].reverse();
  const maxDays = Math.max(...charted.map((r) => r.median_days));
  const minDays = Math.min(...charted.map((r) => r.median_days));

  // Phones: long category names wrap to two lines instead of taking half
  // the width.
  const narrow = slots.chart.clientWidth < 600;
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 8, right: 72, top: 12, bottom: 30, containLabel: true },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params) => {
        const r = shown[params[0]?.dataIndex];
        if (!r) return "";
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(label(r.category))}</div>` +
          `<strong>${escapeHtml(medianTip(L, r.median_days, r.median_at_least, na))}</strong>` +
          `<div style="color:${C.muted};margin-top:4px;">` +
          `${escapeHtml(tpl(L.tipProducts, { products: fmtInt(r.products), lines: fmtInt(r.lines) }))}<br>` +
          `${escapeHtml(tpl(L.tipOpen, { n: fmtInt(r.open) }))}<br>` +
          `${escapeHtml(tpl(L.tipNewest, { n: fmtInt(r.newest_line_ended) }))}<br>` +
          `${escapeHtml(tpl(L.tipNone, { n: fmtInt(r.no_supported_line) }))}</div>`
        );
      },
    },
    // Each bar carries its value, so the value axis keeps only its name.
    xAxis: valAxis({
      min: 0,
      name: ed.xAxis,
      nameLocation: "middle",
      nameGap: 12,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
      axisLabel: { show: false },
    }),
    yAxis: catAxis(shown.map((r) => label(r.category)), {
      axisLabel: {
        color: C.muted, fontFamily: MONO, fontSize: 11,
        width: narrow ? 104 : 220, overflow: "break", lineHeight: 13,
      },
    }),
    series: [
      {
        type: "bar",
        barMaxWidth: 22,
        data: shown.map((r) => ({
          value: toYears(r.median_days),
          // The two categories the headline names read in accent and ink.
          itemStyle: {
            color: r.median_days === maxDays ? C.accent
              : r.median_days === minDays ? C.ink : C.versions.v2,
            borderRadius: [0, 2, 2, 0],
          },
        })),
        label: {
          show: true,
          position: "right",
          color: C.muted,
          fontFamily: MONO,
          fontSize: 11,
          formatter: (p) => yearsLabel(L, shown[p.dataIndex].median_days, null, na),
        },
      },
    ],
  });

  if (thin.length) {
    slots.extra.append(el("p", "panel-note", tpl(ed.notCharted, {
      min: fmtInt(data.min_category_products),
      list: thin.map((r) => tpl(ed.notChartedItem, {
        label: label(r.category), n: fmtInt(r.products),
      })).join(", "),
    })));
  }
}
