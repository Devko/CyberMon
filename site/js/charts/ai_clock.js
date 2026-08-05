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
        max: lastYear + 0.5,
        minInterval: 1,
        axisLabel: { ...{ color: C.muted, fontFamily: MONO, fontSize: 11 }, formatter: (v) => String(Math.round(v)) },
        axisLine: { lineStyle: { color: C.rule } },
        axisTick: { show: false },
        splitLine: { show: false },
      },
      yAxis: [
        valAxis({
          name: "days",
          nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
        }),
        // Hidden rail for the milestone dots: 0-1, drawn near the top.
        { type: "value", min: 0, max: 1, show: false },
      ],
      series: [
        {
          name: "Median gap",
          type: "line",
          data: rows.map((r) => [r.year, r.value]),
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
            data: [{ yAxis: 0 }],
          },
          markArea: {
            silent: true,
            itemStyle: { color: C.accentSoft },
            label: {
              show: true,
              position: "insideTop",
              color: C.muted,
              fontFamily: MONO,
              fontSize: 10,
              formatter: tpl(ed.bandLabel, { label: era.label }),
            },
            data: [[{ xAxis: bandStart }, { xAxis: lastYear + 0.5 }]],
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
