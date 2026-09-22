// Chart 10 — CVSS 4.0 adoption. Contract: site/data/cvss_v4.json
// Main chart: share of newly published records by the CVSS versions their
// CNA scored (monthly / yearly toggle, 100% stacked). Below it: the largest
// v4.0 adopters (table with bar-in-cell) and, on records scored in both,
// the v4.0 − v3.x difference histogram.
import { C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, tooltipRows, fmtInt, fmtPct, escapeHtml } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";
import { mkToggle } from "../ui.js";

// Stacking order bottom -> top; v4.0 (the subject) sits on the baseline so
// its growth reads directly: both v4.0 classes in reds (accent for "v4.0
// only"), v3.x-only newsprint-neutral, "neither" receding into the panel.
const CLASSES = [
  { key: "v4_only", color: C.accent },
  { key: "both", color: "#a0463d" },
  { key: "v3_only", color: C.sev.medium },
  { key: "neither", color: "#3b3c3e" },
];

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const monthLabel = (m) => `${MONTHS[Number(m.slice(5, 7)) - 1]} ${m.slice(0, 4)}`;
const fmtDelta = (v) => (v > 0 ? `+${v.toFixed(1)}` : v < 0 ? `−${Math.abs(v).toFixed(1)}` : "0.0");
const share = (n, d) => (d ? (n / d) * 100 : 0);

export function render(slots, data) {
  const ed = editorial.sections.cvss4;
  const genMonth = data.generated_at.slice(0, 7);
  const genYear = Number(data.generated_at.slice(0, 4));

  // Fill the panel note from the payload (ADP scores are not counted here).
  const cur = (data.years || []).find((r) => r.year === genYear);
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    if (cur) {
      noteEl.textContent = tpl(ed.note, {
        neither_adp: fmtInt(cur.neither_adp), neither: fmtInt(cur.neither),
        current_year: cur.year,
      });
    } else noteEl.remove();
  }

  if (!data.months?.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", ed.nodata));
    return;
  }

  // ---- main chart: coverage shares --------------------------------------------
  const views = {
    month: data.months.map((m) => ({ ...m, label: m.month === genMonth ? `${monthLabel(m.month)}*` : monthLabel(m.month) })),
    year: data.years.filter((y) => y.published).map((y) => ({ ...y, label: y.year === genYear ? `${y.year}*` : String(y.year) })),
  };
  const chart = mkChart(slots.chart);
  const draw = (rows) => {
    chart.setOption(
      {
        grid: { ...baseGrid, left: 48, top: 56 },
        legend: { ...baseLegend, data: CLASSES.map((c) => ed.classLabels[c.key]), icon: "rect", itemHeight: 8 },
        tooltip: {
          ...baseTooltip,
          trigger: "axis",
          order: "seriesDesc",
          formatter: (params) => {
            const row = rows[params[0]?.dataIndex];
            return tooltipRows(params, fmtPct) + (row
              ? `<div style="color:${C.muted};margin-top:4px;">${fmtInt(row.published)} published</div>`
              : "");
          },
        },
        xAxis: catAxis(rows.map((r) => r.label), { boundaryGap: rows.length < 8 }),
        yAxis: valAxis({ max: 100, axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: "{value}%" } }),
        series: CLASSES.map(({ key, color }) => ({
          name: ed.classLabels[key],
          type: rows.length < 8 ? "bar" : "line",
          stack: "cov",
          barMaxWidth: 64,
          areaStyle: { color, opacity: 0.9 },
          itemStyle: { color },
          lineStyle: { width: 0 },
          color,
          symbol: "none",
          emphasis: { focus: "series" },
          data: rows.map((r) => +share(r[key], r.published).toFixed(2)),
        })),
      },
      { replaceMerge: ["series", "xAxis"] }
    );
  };
  slots.controls.append(mkToggle([ed.toggleMonthly, ed.toggleYearly], (i) => draw(i ? views.year : views.month)));
  draw(views.month);

  // ---- adopters board, then the difference histogram -----------------------
  // A carousel slide (carousel.js) has room for the coverage chart only; the
  // board and the histogram stay on the site.
  if (slots.panel.closest(".slide")) return;
  const left = el("div");
  const right = el("div");
  slots.extra.append(left, right);

  const ad = data.adopters || {};
  const since = monthLabel(ad.window_from || data.since_month);
  left.append(el("div", "panel-subtitle", tpl(ed.adoptersTitle, { since })));
  const rows = ad.cnas || [];
  if (!rows.length) {
    left.append(el("div", "nodata-card", ed.nodata));
  } else {
    left.append(el("div", "table-context", tpl(ed.adoptersContext, {
      adopters: fmtInt(ad.adopter_count), shown: rows.length,
      min_v4: fmtInt(ad.min_v4), top_share: fmtPct(ad.top_share_pct),
    })));
    const wrap = el("div", "table-wrap");
    const table = el("table", "cna-table");
    const head = el("tr");
    // the share bar sits next to the name so it survives a phone-width scroll
    head.append(el("th", "", ed.colCna), el("th", "num", ed.colShare), el("th", "num", ed.colV4), el("th", "num", ed.colOnly));
    const thead = el("thead");
    thead.append(head);
    const tbody = el("tbody");
    for (const r of rows) {
      const tr = el("tr");
      const name = el("td", "cna-name");
      name.append(el("span", "cna-short", r.cna));
      const bar = el("td", "num");
      const cell = el("div", "cellbar");
      const fill = el("div", "cellbar-fill accent");
      fill.style.width = `${Math.max(0, Math.min(100, r.v4_share_pct)).toFixed(1)}%`;
      cell.append(fill, el("span", "cellbar-val", fmtPct(r.v4_share_pct)));
      bar.append(cell);
      tr.append(name, bar, el("td", "num", fmtInt(r.v4)), el("td", "num", fmtPct(r.v4_only_share_pct)));
      tbody.append(tr);
    }
    table.append(thead, tbody);
    wrap.append(table);
    left.append(wrap);
  }

  const cmp = data.compare || {};
  const cmpTitle = el("div", "panel-subtitle", ed.compareTitle);
  cmpTitle.style.marginTop = "20px"; // breathing room below the board
  right.append(cmpTitle);
  if (!cmp.n) {
    right.append(el("div", "nodata-card", ed.nodata));
    return;
  }
  right.append(el("div", "table-context", tpl(ed.compareStat, {
    n: fmtInt(cmp.n), same: fmtPct(cmp.same_band_pct), higher: fmtPct(cmp.v4_higher_pct),
    lower: fmtPct(cmp.v4_lower_pct), median: fmtDelta(cmp.median_delta),
  })));
  const histEl = el("div", "chart chart-half");
  right.append(histEl);
  const bins = cmp.bins || [];
  const binLabel = (b) => (b.lo <= -10 ? `≤${fmtDelta(b.hi)}` : b.hi >= 10 ? `≥${fmtDelta(b.lo)}` : fmtDelta(b.center));
  const binRange = (b) => (b.lo <= -10 ? `≤ ${fmtDelta(b.hi)}` : b.hi >= 10 ? `≥ ${fmtDelta(b.lo)}` : `${fmtDelta(b.lo)} to ${fmtDelta(b.hi)}`);
  const hist = mkChart(histEl);
  hist.setOption({
    grid: { ...baseGrid, left: 44, right: 10, top: 12, bottom: 44 },
    tooltip: {
      ...baseTooltip,
      trigger: "item",
      formatter: (p) => escapeHtml(tpl(ed.compareTooltip, { n: fmtInt(p.value), range: binRange(bins[p.dataIndex]) })),
    },
    xAxis: catAxis(bins.map(binLabel), {
      name: ed.compareAxis, nameLocation: "middle", nameGap: 28,
      nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
      axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 10, interval: 1 },
    }),
    yAxis: valAxis({ axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 10, formatter: (v) => (v >= 1000 ? `${v / 1000}k` : v) } }),
    series: [{
      type: "bar",
      barCategoryGap: "12%",
      data: bins.map((b) => ({
        value: b.n,
        // the zero bin (same score, ±0.2) in ink; moves either way neutral
        itemStyle: { color: b.center === 0 ? C.ink : C.faint },
      })),
    }],
  });
}
