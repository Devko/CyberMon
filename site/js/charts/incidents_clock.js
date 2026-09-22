// Incidents 1 (hero) — SEC Form 8-K cyber-incident filings per month or
// quarter, by filing date. Contract: site/data/sec_incidents.json (monthly /
// quarterly / totals / definitions; incidents.js fetches the file once for
// all three sections). Grouped bars: Item 1.05 originals (accent), Item 1.05
// amendments, Item 8.01 cyber filings; partial periods (the rule's first
// half-month, the current month/quarter) are drawn hollow. A status "empty"
// edition — before the first nightly EDGAR read — renders the nodata card.
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid,
  fmtInt, escapeHtml, tooltipRows, tooltipFootnote,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";
import { mkToggle } from "../ui.js";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const monthLabel = (m) => `${MONTHS[Number(m.slice(5, 7)) - 1]} ${m.slice(2, 4)}`;
const quarterLabel = (q) => `${q.slice(5)} ${q.slice(2, 4)}`;
const longDate = (iso) =>
  `${Number(iso.slice(8, 10))} ${MONTHS[Number(iso.slice(5, 7)) - 1]} ${iso.slice(0, 4)}`;

// The SEC staff statement steering not-yet-material incidents to Item 8.01
// (21 May 2024) — drawn as a reference line, not data.
const GUIDANCE = { month: "2024-05", quarter: "2024-Q2" };

// Fill the methodology's {q105}/... from the edition's own query definitions,
// so the page prints the measurement it actually ran.
export function fillMethodology(slots, data, ed) {
  const p = slots.panel.closest(".chart-section")?.querySelector(".method-body > p:first-child");
  const d = data.definitions;
  if (!p || !d) return;
  p.textContent = tpl(ed.methodology, {
    q105: d.item_105.q, forms105: d.item_105.forms, item105: d.item_105.item,
    q801: d.item_801.q, forms801: d.item_801.forms, item801: d.item_801.item,
  });
}

// Shared by the three sections: an edition that has not been fetched yet is
// a nodata card, never an error card and never a row of zeros.
export function showNoData(slots, text) {
  slots.panel.querySelector(".panel-note")?.remove();
  slots.chart.classList.remove("chart", "chart-tall");
  slots.chart.removeAttribute("aria-label");
  slots.chart.append(el("div", "nodata-card", text));
}

export function render(slots, data) {
  const ed = editorial.sections.incidents_clock;
  fillMethodology(slots, data, ed);
  if (data.status !== "ok") {
    showNoData(slots, ed.nodata);
    return;
  }
  const t = data.totals;

  // ---- headline stat: every figure filled from the edition --------------------
  const stat = el("div", "hero-stat");
  const row = el("div", "hero-stat-row");
  row.append(
    el("span", "hero-num accent", fmtInt(t.originals)),
    el("span", "hero-when", tpl(ed.statWhen, {
      companies: fmtInt(t.companies_105),
      start: longDate(data.window.start),
      amendments: fmtInt(t.amendments),
      voluntary: fmtInt(t.voluntary),
      latest: t.latest_105 ?? "—",
    }))
  );
  stat.append(el("div", "hero-stat-label", ed.statLabel), frag(row));
  slots.stat.append(stat);

  const chart = mkChart(slots.chart);
  const SERIES = [
    { key: "originals", name: ed.legendOriginals, color: C.accent },
    { key: "amendments", name: ed.legendAmendments, color: C.sev.high },
    { key: "voluntary", name: ed.legendVoluntary, color: C.versions.v3 },
  ];

  function draw(quarterly) {
    const rows = quarterly ? data.quarterly : data.monthly;
    const keyOf = (r) => (quarterly ? r.quarter : r.month);
    const labels = rows.map((r) => (quarterly ? quarterLabel(r.quarter) : monthLabel(r.month)));
    const guideIdx = rows.findIndex((r) => keyOf(r) === (quarterly ? GUIDANCE.quarter : GUIDANCE.month));
    // Phone widths wrap the three-entry legend onto three lines; give it
    // room so it never sits on the axis name or the guidance label.
    const narrow = slots.chart.clientWidth < 560;
    chart.setOption({
      grid: { ...baseGrid, left: 44, top: narrow ? 104 : 56, bottom: 40 },
      legend: { ...baseLegend, data: SERIES.map((s) => s.name), icon: "rect", itemHeight: 8 },
      tooltip: {
        ...baseTooltip,
        trigger: "axis",
        axisPointer: { type: "shadow" },
        formatter: (params) => {
          const r = rows[params[0]?.dataIndex];
          if (!r) return "";
          const head = `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(keyOf(r))}</div>`;
          const body = tooltipRows(params, fmtInt);
          return head + body + (r.partial ? tooltipFootnote([ed.partialTooltip]) : "");
        },
      },
      xAxis: catAxis(labels, {
        axisLabel: { ...catAxis([]).axisLabel, hideOverlap: true },
      }),
      yAxis: valAxis({
        name: ed.yAxis,
        minInterval: 1,
        nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
      }),
      series: SERIES.map((s, i) => ({
        name: s.name,
        type: "bar",
        barGap: "10%",
        barMaxWidth: quarterly ? 22 : 9,
        color: s.color,
        data: rows.map((r) => ({
          value: r[s.key],
          // Partial periods: outline only, so a short month never reads as
          // a quiet one.
          itemStyle: r.partial
            ? { color: "transparent", borderColor: s.color, borderWidth: 1, borderType: "dashed" }
            : { color: s.color },
        })),
        markLine: i === 0 && guideIdx >= 0 ? {
          silent: true,
          symbol: "none",
          lineStyle: { color: C.faint, type: "dashed", width: 1 },
          label: {
            formatter: ed.guidanceMark, color: C.muted, fontFamily: MONO, fontSize: 10,
            position: "end",
          },
          data: [{ xAxis: guideIdx }],
        } : undefined,
      })),
    }, { replaceMerge: ["series", "xAxis"] });
  }

  slots.controls.append(mkToggle([ed.toggleMonthly, ed.toggleQuarterly], (idx) => draw(idx === 1)));
  draw(false);
}
