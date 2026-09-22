// Changelog 3 — how late the ransomware flag lands. Contract:
// site/data/kev_changelog.json → flag_lag (additive since 2026-09-22;
// changelog.js fetches the file once). Two views behind one toggle: the
// distribution of days from dateAdded to the observed Unknown->Known flip
// (stacked by granularity — capture-dated lags are loose upper bounds,
// nightly ones are good to the day), and the median with its IQR per
// listing year. Step-month flips are excluded by the pipeline.
import { C, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, fmtInt, escapeHtml } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, clear } from "../dom.js";
import { mkToggle } from "../ui.js";

export function render(slots, data) {
  const ed = editorial.sections.flaglag;
  const lag = data.flag_lag;

  // Editions before 2026-09-22 carry no flag_lag block.
  if (!lag) {
    slots.panel.querySelector(".panel-note")?.remove();
    slots.chart.classList.remove("chart");
    slots.chart.removeAttribute("aria-label");
    slots.chart.append(el("div", "nodata-card", ed.noBlock));
    return;
  }

  const overall = lag.overall || {};
  const n = (lag.n_capture ?? 0) + (lag.n_daily ?? 0);
  // Whole days on the page (the file keeps one decimal).
  const days = (v) => fmtInt(v === null || v === undefined ? v : Math.round(v));
  const vars = {
    n: fmtInt(n), median: days(overall.median_days), p25: days(overall.p25_days),
    p75: days(overall.p75_days), n_capture: fmtInt(lag.n_capture),
    n_daily: fmtInt(lag.n_daily), step_month: lag.step_month,
    step_flips: fmtInt(lag.excluded_step), went_back: fmtInt(lag.went_back),
  };

  // ---- stat -----------------------------------------------------------------
  const stat = el("div", "hero-stat");
  const row = el("div", "hero-stat-row");
  const hasMedian = overall.median_days !== null && overall.median_days !== undefined;
  row.append(
    el("span", "hero-num accent", hasMedian ? tpl(ed.statBig, vars) : "—"),
    el("span", "hero-when", hasMedian ? tpl(ed.statLead, vars) : ed.statLeadThin)
  );
  stat.append(row);
  const notes = [tpl(ed.statNote, vars)];
  if (lag.step_month) notes.push(tpl(ed.statNoteStep, vars));
  notes.push(tpl(lag.went_back ? ed.wentBack : ed.wentBackNone, vars));
  stat.append(el("div", "hero-stat-label", notes.join(" · ")));
  slots.stat.append(stat);

  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) noteEl.textContent = tpl(ed.note, vars);

  if (!n) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  const DAILY = C.versions.v3;
  const CAPTURE = C.sev.medium;
  let chart = null;

  const drawBuckets = () => {
    const rows = lag.buckets || [];
    chart.setOption({
      grid: { ...baseGrid, left: 44, right: 18, top: 40, bottom: 36 },
      legend: { ...baseLegend, data: [ed.legendDaily, ed.legendCapture] },
      tooltip: {
        ...baseTooltip,
        trigger: "axis",
        axisPointer: { type: "shadow" },
        formatter: (ps) => {
          const r = rows[ps[0]?.dataIndex];
          if (!r) return "";
          return (
            `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(ed.bucketLabels[r.label] ?? r.label)}</div>` +
            `${escapeHtml(ed.legendDaily)} <strong>${fmtInt(r.daily)}</strong><br>` +
            `${escapeHtml(ed.legendCapture)} <strong>${fmtInt(r.capture)}</strong>`
          );
        },
      },
      xAxis: catAxis(rows.map((r) => ed.bucketLabels[r.label] ?? r.label), {
        name: ed.axisDays, nameLocation: "middle", nameGap: 24,
        nameTextStyle: { color: C.faint, fontSize: 10 },
        axisLabel: { color: C.muted, fontSize: 10, interval: 0, hideOverlap: false },
      }),
      yAxis: valAxis({ minInterval: 1 }),
      series: [
        { name: ed.legendDaily, type: "bar", stack: "lag", data: rows.map((r) => r.daily),
          itemStyle: { color: DAILY }, barMaxWidth: 48 },
        { name: ed.legendCapture, type: "bar", stack: "lag", data: rows.map((r) => r.capture),
          itemStyle: { color: CAPTURE }, barMaxWidth: 48 },
      ],
    }, true);
  };

  const drawYears = () => {
    const rows = lag.by_year || [];
    const has = (r) => r.median_days !== null && r.median_days !== undefined;
    chart.setOption({
      grid: { ...baseGrid, left: 48, right: 18, top: 40, bottom: 48 },
      legend: { ...baseLegend, data: [ed.legendIqr, ed.legendMedian] },
      tooltip: {
        ...baseTooltip,
        trigger: "axis",
        axisPointer: { type: "shadow" },
        formatter: (ps) => {
          const r = rows[ps[0]?.dataIndex];
          if (!r) return "";
          const head = `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(tpl(ed.yearTip, { year: r.year, n: fmtInt(r.n) }))}</div>`;
          if (!has(r)) return head + escapeHtml(ed.yearThin);
          return (
            head +
            `${escapeHtml(ed.legendMedian)} <strong>${days(r.median_days)} d</strong><br>` +
            `${escapeHtml(ed.legendIqr)} <strong>${days(r.p25_days)}–${days(r.p75_days)} d</strong>`
          );
        },
      },
      xAxis: catAxis(rows.map((r) => `${r.year}\n(${r.n})`), {
        name: ed.axisYear, nameLocation: "middle", nameGap: 34,
        nameTextStyle: { color: C.faint, fontSize: 10 },
        axisLabel: { color: C.muted, fontSize: 10, interval: 0 },
      }),
      yAxis: valAxis({ name: ed.axisDaysShort, nameTextStyle: { color: C.faint, fontSize: 10 } }),
      series: [
        // Floating IQR bar: an invisible base to p25, then the p25..p75 span.
        { name: "_base", type: "bar", stack: "iqr", silent: true,
          data: rows.map((r) => (has(r) ? r.p25_days : null)),
          itemStyle: { color: "transparent" }, barMaxWidth: 40 },
        { name: ed.legendIqr, type: "bar", stack: "iqr",
          data: rows.map((r) => (has(r) ? r.p75_days - r.p25_days : null)),
          itemStyle: { color: C.sev.medium, opacity: 0.75 }, barMaxWidth: 40 },
        { name: ed.legendMedian, type: "scatter", symbol: "rect", symbolSize: [30, 3],
          data: rows.map((r) => (has(r) ? r.median_days : null)),
          itemStyle: { color: C.accent } },
      ],
    }, true);
  };

  const VIEWS = [drawBuckets, drawYears];
  const draw = (i) => {
    if (!chart) chart = mkChart(slots.chart);
    VIEWS[i]();
  };
  clear(slots.controls).append(mkToggle(ed.toggleLabels, draw, 0));
  draw(0);
}
