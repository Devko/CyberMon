// Detection Rules 3 — how long techniques new to ATT&CK waited for a first
// Sigma rule. Contract: site/data/sigma_coverage.json (cohorts, lag,
// attack). One stacked bar per year of ATT&CK entry: a rule older than the
// technique, a first rule within a year, a first rule later, no rule yet.
// A year whose techniques have had less than a year of follow-up carries an
// asterisk (the caption says so). The stat is the median wait over the
// two-year-follow-up cohort the pipeline computes, exact or a lower bound.
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid,
  fmtInt, escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";
import { fillRef, noEdition } from "./sigma_shared.js";

const BUCKETS = ["before_debut", "within_year", "later", "none"];
const COLORS = {
  before_debut: C.versions.v2,
  within_year: C.versions.v3,
  later: C.sev.high,
  none: C.accent,
};

export function render(slots, data, refs) {
  const ed = editorial.sections.sigma_lag;
  const L = ed.labels;
  const cohorts = data.cohorts || [];
  const lag = data.lag || {};
  const attack = data.attack || {};
  if (!cohorts.length) {
    noEdition(slots, ed.nodata, refs);
    return;
  }

  const young = cohorts.filter((c) => !c.full_year);
  const lastYear = young.length ? young[young.length - 1].year : null;
  if (refs?.caption) {
    fillRef(refs.caption, { last_year: lastYear ?? "" }, tpl);
    // Every cohort has a full year of follow-up: drop the asterisk sentence.
    if (lastYear === null) {
      refs.caption.textContent = refs.caption.textContent.replace(/\s*\*[^.]*\.$/, "");
    }
  }
  fillRef(refs?.methodText, {
    first_version: attack.first_version,
    first_released: attack.first_released,
    n: fmtInt(lag.n),
    follow_years: Math.round((lag.follow_up_days ?? 730) / 365),
  }, tpl);

  // ---- note: within-a-year share, 2018–2022 entrants vs later full years -----
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    const full = cohorts.filter((c) => c.full_year);
    const early = full.filter((c) => c.year >= 2018 && c.year <= 2022);
    const recent = full.filter((c) => c.year >= 2023);
    const sum = (rows, f) => rows.reduce((s, c) => s + f(c), 0);
    const within = (c) => c.before_debut + c.within_year;
    if (early.length && recent.length) {
      noteEl.textContent = tpl(ed.note, {
        early_n: fmtInt(sum(early, (c) => c.techniques)),
        early_within: fmtInt(sum(early, within)),
        recent_n: fmtInt(sum(recent, (c) => c.techniques)),
        recent_within: fmtInt(sum(recent, within)),
        recent_to: recent[recent.length - 1].year,
      });
    } else {
      noteEl.remove();
    }
  }

  // ---- headline stat: the median wait ----------------------------------------------
  const median = lag.median_exact ? lag.median_days : lag.median_at_least_days;
  if (lag.n && median !== null && median !== undefined) {
    const stat = el("div", "hero-stat");
    const row = el("div", "hero-stat-row");
    row.append(
      el("span", "hero-num accent",
        tpl(lag.median_exact ? ed.statValue : ed.statValueAtLeast, { n: fmtInt(median) })),
      el("span", "hero-when", tpl(ed.statWhen, {
        n: fmtInt(lag.n),
        first_version: attack.first_version,
        through: lag.debut_through,
      }))
    );
    stat.append(el("div", "hero-stat-label", ed.statLabel), frag(row));
    slots.stat.append(stat);
  }

  const labels = cohorts.map((c) => (c.full_year ? String(c.year) : `${c.year}*`));
  // Phones: the four legend entries wrap to four rows; give them room
  // (a carousel slide, ~500px wide, wraps to two and keeps the default).
  const narrow = slots.chart.clientWidth < 420;
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 44, top: narrow ? 120 : 62, bottom: 30 },
    legend: {
      ...baseLegend,
      data: BUCKETS.map((b) => L[b]),
      icon: "rect",
      itemHeight: 8,
    },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params) => {
        const i = params.length ? params[0].dataIndex : -1;
        const c = cohorts[i];
        if (!c) return "";
        const line = (b) =>
          `<div style="display:flex;gap:10px;justify-content:space-between;">` +
          `<span><span style="display:inline-block;width:8px;height:8px;background:${COLORS[b]};margin-right:6px;"></span>` +
          `${escapeHtml(L[b])}</span><strong style="font-family:inherit">${fmtInt(c[b])}</strong></div>`;
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(labels[i])} · ` +
          `${escapeHtml(tpl(L.tipTotal, { n: fmtInt(c.techniques) }))}</div>` +
          BUCKETS.map(line).join("")
        );
      },
    },
    xAxis: catAxis(labels),
    yAxis: valAxis({
      minInterval: 1,
      name: L.yAxis,
      nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
    }),
    series: BUCKETS.map((b) => ({
      name: L[b],
      type: "bar",
      stack: "lag",
      barMaxWidth: 42,
      color: COLORS[b],
      itemStyle: { borderColor: C.panel, borderWidth: 1 },
      emphasis: { focus: "series" },
      data: cohorts.map((c) => c[b]),
    })),
  });
}
