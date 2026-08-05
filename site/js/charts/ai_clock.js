// The AI Alibi 1 (hero) — CyberMon's exploitation clock across the whole
// record, with the AI era shaded and the AI timeline marked. Contract:
// site/data/ai_alibi.json (shared by all three sections; ai.js fetches it
// once and hands every renderer the same era store).
//
// Two deliberate departures from the site's usual year charts:
//
// 1. The x-axis is a VALUE axis of years, not the usual category axis.
//    Milestones need sub-year positions (a November release must not land
//    on the January gridline), and only a value axis can carry a
//    fractional year. Ticks are forced to whole years so it still reads
//    as a year axis.
// 2. Milestones ride a second, hidden 0-1 y-axis pinned to the top of the
//    plot rather than being drawn as vertical markLines. Ten labelled
//    verticals inside four years at the right edge is an unreadable
//    thicket; the dots stay legible and the full dated, sourced,
//    categorised list renders as a rail below the chart — which is also
//    what makes each claim auditable, since every row carries its link.
import { C, mkChart, valAxis, baseTooltip, baseGrid, fmtInt, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, link } from "../dom.js";
import { makeEraStore } from "./ai_era.js";

const fmtDays = (v) => `${fmtInt(Math.round(v))}d`;

// Timeline categories -> the accent they carry. Only the two that bear on
// the argument get colour: a capability arriving, and a threat-intel shop
// reporting it found no offensive uplift. Everything else stays newsprint.
const KIND_COLOR = {
  capability: C.accent,
  no_uplift: "#ded7c2",
  offensive: "#c08a45",
  defensive: "#77715f",
  research: "#4b473d",
};

// Fractional year position for a YYYY-MM-DD plot date: 2022-11-30 -> 2022.91.
// Day-of-month is deliberately ignored — at a 28-year span it is under a
// pixel, and pretending otherwise would imply precision the month-precision
// rows don't have.
function yearPos(plotDate) {
  const year = Number(plotDate.slice(0, 4));
  const month = Number(plotDate.slice(5, 7));
  return year + (month - 0.5) / 12;
}

// ---- symmetric log scale ----------------------------------------------------
// The gap series spans -800 days (1999) to single digits (every year since
// ~2005). On a linear axis the 1999 outlier sets the scale and the entire
// period this module is ABOUT — 2004 onward, including the AI era — renders
// inside ~3% of the axis height, as a flat line nobody can read. The caption
// promises "a line that does nothing in particular once it enters"; a reader
// has to be able to SEE it doing nothing.
//
// A sign-preserving log keeps every year on one chart and makes both halves
// legible: the collapse on the left, the flat stretch on the right.
//
// It needs a LINEAR REGION around zero, or it trades one distortion for
// another. A pure log magnifies small values — the modern series sits at
// +1, +4, +2, -12 days, and log-scaling that turns a few days of noise into
// a cliff inside the AI band, which is exactly the misreading this chart
// exists to prevent. Below the threshold the scale is linear, above it
// logarithmic (the matplotlib symlog construction).
//
// The threshold is a month: a clock that moved inside 30 days did not move
// in any sense a defender schedules around, so a month of drift should look
// like drift, not like an event. Ticks are pinned to round day values so
// the axis still reads in days — the transform is a rendering device, never
// a change to the numbers, and the tooltip always quotes the real value.
const SYM_LINEAR_DAYS = 30;
const toSym = (v) => {
  const a = Math.abs(v);
  return Math.sign(v) * (a <= SYM_LINEAR_DAYS
    ? a / SYM_LINEAR_DAYS
    : 1 + Math.log10(a / SYM_LINEAR_DAYS));
};
const fromSym = (t) => {
  const a = Math.abs(t);
  return Math.sign(t) * (a <= 1
    ? a * SYM_LINEAR_DAYS
    : SYM_LINEAR_DAYS * Math.pow(10, a - 1));
};
const SYM_TICK_DAYS = [-3000, -300, -30, 0, 30, 300];

// `eraStore` is optional: ai.js passes a live one, the carousel generator
// passes nothing and gets an inert store pinned to the default era.
export function render(slots, data, eraStore = makeEraStore(data)) {
  const ed = editorial.sections.ai_clock;
  const head = data.headline || {};
  const clock = data.clock || {};
  const gap = (clock.metrics || []).find((m) => m.id === "poc_gap");
  const rows = gap ? gap.years : [];

  // ---- headline stat --------------------------------------------------------
  const stat = el("div", "hero-stat");
  stat.append(el("div", "hero-stat-label", ed.statLabel));
  const row = el("div", "hero-stat-row");
  if (head.judged > 0) {
    row.append(
      el("span", "hero-num accent", String(head.accelerated)),
      el("span", "hero-when", tpl(ed.statOf, { judged: head.judged })),
      el("span", "hero-vs", "·"),
      el("span", "hero-num", String(head.no_uplift_reports)),
      el("span", "hero-when", ed.statUplift)
    );
  } else {
    row.append(el("span", "hero-when muted", "Not enough data yet."));
  }
  stat.append(row);
  slots.stat.append(stat);

  if (!rows.length) {
    slots.chart.classList.remove("chart", "chart-tall");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  // ---- era selector (this page's shared control) ----------------------------
  // Only where it can actually drive something: a printed slide has no
  // interaction, and a dead dropdown on it would promise one.
  if (eraStore.live) {
    const label = el("label", "term-select-label", ed.selectLabel);
    const select = el("select", "term-select");
    for (const e of eraStore.eras) {
      const opt = el("option", null, `${e.label} · ${e.date}`);
      opt.value = e.id;
      if (e.id === eraStore.id) opt.selected = true;
      select.append(opt);
    }
    label.append(select);
    slots.controls.append(label);
    select.addEventListener("change", () => eraStore.set(select.value));
  }

  // ---- chart ----------------------------------------------------------------
  const milestones = data.milestones || [];
  const firstYear = rows[0].year;
  const lastYear = rows[rows.length - 1].year;
  const byYear = new Map(rows.map((r) => [r.year, r]));

  // The axis spans the union of the clock and the timeline, not just the
  // clock. The two legitimately end at different times — the clock stops
  // at the last COMPLETE year while milestones keep landing — and binding
  // the axis to the clock alone silently clipped anything newer off the
  // chart. The resulting gap is not a blemish to hide: it is the honest
  // statement that the newest events are real and this page cannot judge
  // them yet, which is why the boundary below is drawn and labelled.
  const lastMilestoneYear = milestones.length
    ? Math.floor(yearPos(milestones[milestones.length - 1].plot_date))
    : lastYear;
  const axisMax = Math.max(lastYear, lastMilestoneYear) + 0.5;

  // Axis bounds in transformed space, padded so the extremes aren't drawn
  // on the frame; ticks are the round day values that fall inside them.
  const symValues = rows.map((r) => toSym(r.value));
  const symMin = Math.min(...symValues, 0) - 0.25;
  const symMax = Math.max(...symValues, 0) + 0.25;
  const symTicks = SYM_TICK_DAYS.map(toSym)
    .filter((t) => t >= symMin && t <= symMax);

  const chart = mkChart(slots.chart);

  const build = (eraId) => {
    const era = eraStore.eras.find((e) => e.id === eraId) || eraStore.eras[0];
    // The band opens at the cutoff's own date, not its cut_year: the
    // shading marks when the era began, while the pre/post arithmetic
    // uses whole years. Showing the real date keeps the two honest.
    const bandStart = yearPos(era.date.length === 10 ? era.date : `${era.date}-15`);

    chart.setOption({
      grid: { ...baseGrid, left: 56, top: 30, right: 24 },
      tooltip: {
        ...baseTooltip,
        trigger: "item",
        formatter: (p) => {
          if (p.seriesName === "_milestones") {
            const m = p.data.milestone;
            const when = m.precision === "month"
              ? tpl(ed.tipMonth, { date: m.date })
              : m.date;
            return (
              `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(when)}</div>` +
              `<strong>${escapeHtml(m.label)}</strong><br>` +
              `<span style="color:${C.muted};">${escapeHtml(m.note)}</span>`
            );
          }
          const r = byYear.get(Math.round(p.value[0]));
          if (!r) return "";
          return (
            `<div style="color:${C.muted};margin-bottom:4px;">${r.year}</div>` +
            `median <strong>${fmtDays(r.value)}</strong> · ${fmtInt(r.n)} matched CVEs`
          );
        },
      },
      xAxis: {
        type: "value",
        min: firstYear - 0.5,
        max: axisMax,
        minInterval: 1,
        axisLabel: { ...{ color: C.muted, fontFamily: MONO, fontSize: 11 }, formatter: (v) => String(Math.round(v)) },
        axisLine: { lineStyle: { color: C.rule } },
        axisTick: { show: false },
        splitLine: { show: false },
      },
      yAxis: [
        valAxis({
          name: "days (log)",
          nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
          min: symMin,
          max: symMax,
          // Ticks at round DAY values, placed at their transformed
          // positions — the axis reads in days even though it is spaced
          // logarithmically. customValues needs ECharts >= 5.5 (the site
          // pins 5.5.1); without it the axis degrades to default ticks,
          // which the formatter still labels correctly.
          interval: 1,
          axisLabel: {
            color: C.muted, fontFamily: MONO, fontSize: 11,
            customValues: symTicks,
            formatter: (t) => fmtDays(fromSym(t)),
          },
          axisTick: { customValues: symTicks },
          splitLine: { customValues: symTicks, lineStyle: { color: C.rule, type: [2, 4] } },
        }),
        // Hidden rail for the milestone dots: 0-1, drawn near the top.
        { type: "value", min: 0, max: 1, show: false },
      ],
      series: [
        {
          name: "Median gap",
          type: "line",
          // Plotted transformed, reported raw — the tooltip below reads
          // `byYear`, never the plotted y.
          data: rows.map((r) => [r.year, toSym(r.value)]),
          color: C.accent,
          symbol: "circle",
          symbolSize: 4,
          lineStyle: { width: 2 },
          z: 5,
          markLine: {
            silent: true,
            symbol: "none",
            lineStyle: { color: C.faint, type: "dashed", width: 1 },
            label: { show: false },
            data: [
              { yAxis: 0 },
              // Where testable evidence stops. Everything to the right is
              // timeline only — the clock has no complete year there yet,
              // and no verdict on this page rests on it.
              {
                xAxis: lastYear + 0.5,
                lineStyle: { color: C.muted, type: "solid", width: 1, opacity: 0.5 },
                label: {
                  show: true, position: "insideEndTop", color: C.muted,
                  fontFamily: MONO, fontSize: 9,
                  formatter: tpl(ed.evidenceEdge, { year: lastYear }),
                },
              },
            ],
          },
          markArea: {
            silent: true,
            itemStyle: { color: C.accentSoft },
            label: {
              show: true,
              // Bottom, not top: the milestone dots ride the top of the
              // plot and the two collide there.
              position: "insideBottom",
              color: C.muted,
              fontFamily: MONO,
              fontSize: 10,
              formatter: tpl(ed.bandLabel, { label: era.label }),
            },
            data: [[{ xAxis: bandStart }, { xAxis: axisMax }]],
          },
        },
        {
          name: "_milestones",
          type: "scatter",
          yAxisIndex: 1,
          symbolSize: 9,
          z: 10,
          data: milestones.map((m) => ({
            value: [yearPos(m.plot_date), 0.94],
            milestone: m,
            itemStyle: { color: KIND_COLOR[m.kind] || C.faint },
          })),
        },
      ],
    });
  };

  build(eraStore.id);
  eraStore.subscribe(build);

  // ---- timeline rail (the auditable half of the overlay) --------------------
  // Every marker on the chart appears here dated, categorised and linked.
  // A dot a reader can't trace back to a primary source is decoration;
  // this rail is what makes it evidence. Skipped on printed slides: ten
  // sourced rows overflow a slide, and a link is useless on paper — the
  // deck's closing card already points back to the live page.
  if (eraStore.live) {
    const rail = el("div", "timeline-rail");
    rail.append(el("p", "timeline-rail-title", ed.railTitle));
    const list = el("ol", "timeline-list");
    for (const m of milestones) {
      const item = el("li", "timeline-item");
      const dot = el("span", "timeline-dot");
      dot.style.background = KIND_COLOR[m.kind] || C.faint;
      const when = el("span", "timeline-date mono", m.date);
      const body = el("span", "timeline-body");
      body.append(el("span", "timeline-label", m.label));
      body.append(link(m.source, ed.railSourceLabel, "timeline-src mono"));
      body.append(el("span", "timeline-note", m.note));
      item.append(dot, when, body);
      list.append(item);
    }
    rail.append(list);
    slots.extra.append(rail);
  }

  // ---- panel note -----------------------------------------------------------
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    if (rows.length) {
      noteEl.textContent = tpl(ed.note, {
        first_year: firstYear,
        last_year: lastYear,
        n: fmtInt(rows.reduce((sum, r) => sum + r.n, 0)),
        milestones: milestones.length,
      });
    } else {
      noteEl.remove(); // never show a template with holes in it
    }
  }
}
