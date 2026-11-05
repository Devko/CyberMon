// KEV 5 — CVE age at listing (vintage). Contract: site/data/kev_latency.json
// (shared with the latency sections; kev.js fetches it once).
// Stacked bars per year of listing: the share of the year's additions whose
// CVE was more than a year old, split into the old-tail buckets, with the
// over-a-year total labelled on top. Below the chart, a table of the oldest
// CVEs added in the last 12 months (page only; carousel slides keep the chart).
import { C, mkChart, catAxis, valAxis, baseTooltip, baseGrid, baseLegend, fmtInt, fmtPct, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, withCveLinks } from "../dom.js";

// Contract order (kev_metrics.OLD_BUCKETS), bottom of the stack to top.
const ORDER = ["1-3y", "3-5y", "5-10y", "10y+"];
// One warm-neutral hue, darker to lighter as the CVE gets older, so the
// decade-old tail is the brightest segment on the dark panel. Validated as
// an ordinal ramp against the panel surface (dataviz validate_palette.js).
const RAMP = { "1-3y": "#5e5848", "3-5y": "#8a8471", "5-10y": "#b9b19a", "10y+": "#ece6d4" };

// Years of 365 days, the unit the bucket edges and the methodology use.
const fmtYears = (days) => (days / 365).toFixed(1);

export function render(slots, data) {
  const ed = editorial.sections.kev_vintage;
  const L = ed.labels;
  const rows = data.vintage_by_year || [];

  if (!rows.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", ed.nodata || editorial.ui.nodata));
  } else {
    drawBars(slots, data, rows, ed, L);
  }

  // The oldest-listings table is page-only, like the CVSS 4.0 adopters board.
  if (slots.panel.closest(".slide")) return;
  drawOldest(slots, data.oldest_recent, ed, L);
}

function drawBars(slots, data, rows, ed, L) {
  // The generation year plots but is partial — mark it (volume.js pattern).
  const genYear = Number(data.generated_at.slice(0, 4));
  const cats = rows.map((r) => (r.year === genYear ? `${r.year}*` : String(r.year)));
  const bucketOf = (r, key) => (r.buckets || []).find((b) => b.bucket === key) || { n: 0, pct: 0 };
  const names = ORDER.map((key) => L.buckets[key]);

  // The four legend entries wrap to two rows on a phone: leave room for
  // them above the top bar's label.
  const narrow = slots.chart.clientWidth > 0 && slots.chart.clientWidth < 520;
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 50, top: narrow ? 70 : 48 },
    // square swatches: the house 14×2 line swatch hides the darkest step
    legend: { ...baseLegend, itemWidth: 10, itemHeight: 10, data: names },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params) => {
        const i = params[0]?.dataIndex;
        const r = rows[i];
        if (!r) return "";
        // oldest first, matching the stack read top-down
        const lines = [...ORDER].reverse().map((key) => {
          const b = bucketOf(r, key);
          return escapeHtml(tpl(L.tipBucket, { label: L.buckets[key], pct: fmtPct(b.pct), n: fmtInt(b.n) }));
        });
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(cats[i])}</div>` +
          `<strong>${escapeHtml(tpl(L.tipTotal, { pct: fmtPct(r.pct_over_1y) }))}</strong><br>` +
          lines.join("<br>") + "<br>" +
          `<span style="color:${C.muted};">${escapeHtml(tpl(L.tipCount, { n: fmtInt(r.n) }))}</span>`
        );
      },
    },
    xAxis: catAxis(cats),
    yAxis: valAxis({
      min: 0,
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    series: ORDER.map((key, k) => ({
      name: L.buckets[key],
      type: "bar",
      stack: "age",
      barWidth: "55%",
      color: RAMP[key],
      // a hairline of panel between segments keeps neighbouring steps apart
      itemStyle: { borderColor: C.panel, borderWidth: 1 },
      data: rows.map((r) => bucketOf(r, key).pct),
      // the top segment carries the stack's total: the over-a-year share
      label: k === ORDER.length - 1 ? {
        show: true, position: "top",
        color: C.muted, fontFamily: MONO, fontSize: 11,
        formatter: (p) => fmtPct(rows[p.dataIndex]?.pct_over_1y),
      } : { show: false },
    })),
  });
}

function drawOldest(slots, recent, ed, L) {
  const shown = recent?.entries || [];
  if (!shown.length) return; // no listings in the window: nothing to name
  const box = el("div");
  box.style.marginTop = "16px"; // breathing room below the bars' axis
  box.append(el("div", "panel-subtitle", tpl(ed.oldestTitle, { shown: shown.length })));
  box.append(el("div", "table-context", tpl(ed.oldestContext, {
    n_over_10y: fmtInt(recent.n_over_10y),
    n_listed: fmtInt(recent.n_listed),
    since: recent.since,
    until: recent.until,
  })));

  const wrap = el("div", "table-wrap");
  const table = el("table", "cna-table");
  // Four short columns: no 640px floor, and no wrapping inside a CVE id or
  // a date; on the narrowest phones the wrap scrolls instead of the page.
  table.style.minWidth = "0";
  table.style.whiteSpace = "nowrap";
  if (slots.panel.clientWidth > 0 && slots.panel.clientWidth < 420) table.style.fontSize = "12px";
  const head = el("tr");
  // The listing date goes last: on the narrowest phones it is the column
  // that scrolls out of view, not the age.
  head.append(
    el("th", "", ed.colCve),
    el("th", "num", ed.colPublished),
    el("th", "num", ed.colAge),
    el("th", "num", ed.colAdded)
  );
  const thead = el("thead");
  thead.append(head);
  const tbody = el("tbody");
  for (const e of shown) {
    const tr = el("tr");
    const cve = el("td", "mono");
    cve.append(withCveLinks(String(e.cve_id ?? "")));
    tr.append(
      cve,
      el("td", "num", String(e.date_published ?? "").slice(0, 4)),
      el("td", "num", tpl(L.ageYears, { years: fmtYears(e.age_days) })),
      el("td", "num", String(e.date_added ?? ""))
    );
    tbody.append(tr);
  }
  table.append(thead, tbody);
  wrap.append(table);
  box.append(wrap);
  slots.extra.append(box);
}
