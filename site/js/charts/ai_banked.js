// The AI Alibi 2 — the inflection test. One diverging bar per speed
// metric: how much of that metric's total travelled distance the selected
// AI era accounts for, and in which direction. Contract:
// site/data/ai_alibi.json (`banked`), re-rendered when the hero's era
// selector changes.
//
// The bar is `shift_share_pct`, which the PIPELINE signs — positive means
// the era moved the metric toward FASTER exploitation, negative toward
// slower. That sign convention lives in ai_metrics._verdict precisely so
// this file never has to know that a falling gap and a rising
// within-a-week share both mean "faster"; three metrics with two
// different polarities is exactly where a chart file starts lying.
//
// Bars right of zero are the only ones that support the AI-made-attackers
// -fast story, so they are the only ones that carry the accent.
import { C, mkChart, valAxis, baseTooltip, baseGrid, escapeHtml, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";
import { makeEraStore } from "./ai_era.js";

const VERDICT_COLOR = {
  accelerated: C.accent,
  decelerated: "#77715f",
  no_inflection: "#4b473d",
  insufficient: C.rule,
};

const fmtSigned = (v) => `${v > 0 ? "+" : ""}${v.toFixed(1)}%`;
const fmtLevel = (v, unit) =>
  v === null || v === undefined ? "—" : unit === "days" ? `${Math.round(v)}d` : `${v.toFixed(1)}%`;

// `eraStore` is optional — see ai_era.js. Without one this renders the
// default cutoff and never re-renders, which is exactly a printed slide.
export function render(slots, data, eraStore = makeEraStore(data)) {
  const ed = editorial.sections.ai_banked;
  const banked = data.banked || {};
  const metrics = banked.metrics || [];

  if (!metrics.length) {
    slots.chart.classList.remove("chart");
    slots.chart.append(el("div", "nodata-card", "Not enough data yet."));
    return;
  }

  const chart = mkChart(slots.chart);
  const table = el("div", "verdict-table");
  slots.extra.append(table);

  const build = (eraId) => {
    const era = eraStore.eras.find((e) => e.id === eraId) || eraStore.eras[0];
    // Rows bottom-up: ECharts' category axis draws index 0 at the bottom,
    // and the headline metric should sit at the top of the board.
    const cells = metrics
      .map((m) => ({
        metric: m,
        block: (m.eras || []).find((b) => b.era === era.id),
      }))
      .filter((r) => r.block)
      .reverse();

    const judged = cells.filter((r) => r.block.verdict !== "insufficient");

    chart.setOption(
      {
        grid: { ...baseGrid, left: 8, right: 28, top: 20, bottom: 34, containLabel: true },
        // An era too young to judge draws three zero-length bars, which
        // reads as a broken chart rather than a withheld verdict. Say so
        // on the plot itself — the empty state is a finding here ("one
        // year is not an era"), not an absence.
        graphic: judged.length ? [] : [{
          type: "text", left: "center", top: "middle", silent: true,
          style: {
            text: tpl(ed.allWithheld, {
              cut_year: era.cut_year,
              years: cells.length ? cells[0].block.post.years : 0,
            }),
            fill: C.muted, fontFamily: MONO, fontSize: 12,
          },
        }],
        tooltip: {
          ...baseTooltip,
          trigger: "item",
          formatter: (p) => {
            const { metric, block } = cells[p.dataIndex];
            const u = metric.unit;
            const head = `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(metric.label)}</div>`;
            if (block.verdict === "insufficient") {
              return head + escapeHtml(tpl(ed.tipInsufficient, { years: block.post.years }));
            }
            return (
              head +
              `${escapeHtml(ed.tipEarly)} <strong>${fmtLevel(block.early.value, u)}</strong><br>` +
              `${escapeHtml(tpl(ed.tipPre, { cut_year: block.cut_year }))} <strong>${fmtLevel(block.pre.value, u)}</strong><br>` +
              `${escapeHtml(ed.tipPost)} <strong>${fmtLevel(block.post.value, u)}</strong> ` +
              `<span style="color:${C.muted};">(${block.post.years}y)</span><br>` +
              `<span style="color:${C.muted};">${escapeHtml(tpl(ed.tipBanked, { pct: block.pct_banked === null ? "—" : block.pct_banked.toFixed(1) }))}</span>`
            );
          },
        },
        xAxis: valAxis({
          name: ed.axisLabel,
          nameLocation: "middle",
          nameGap: 24,
          nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
          axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: (v) => `${v}%` },
        }),
        yAxis: {
          type: "category",
          data: cells.map((r) => r.metric.label),
          axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, width: 210, overflow: "break" },
          axisLine: { lineStyle: { color: C.rule } },
          axisTick: { show: false },
        },
        series: [
          {
            type: "bar",
            barMaxWidth: 22,
            data: cells.map((r) => ({
              // An unjudged era has no share to draw — a zero-length bar
              // beside a "withheld" label, never a bar implying zero movement.
              value: r.block.shift_share_pct ?? 0,
              itemStyle: { color: VERDICT_COLOR[r.block.verdict] || C.faint },
            })),
            markLine: {
              silent: true,
              symbol: "none",
              lineStyle: { color: C.faint, width: 1 },
              label: { show: false },
              data: [{ xAxis: 0 }],
            },
          },
        ],
      },
      { replaceMerge: ["series", "yAxis", "graphic"] }
    );

    // ---- verdict table (the numbers behind every bar) -----------------------
    table.replaceChildren();
    table.append(el("p", "verdict-caption", tpl(ed.tableCaption, { era: era.label, date: era.date })));
    for (const { metric, block } of [...cells].reverse()) {
      const rowEl = el("div", "verdict-row" + (metric.primary ? " is-primary" : ""));
      const badge = el("span", `verdict-badge verdict-${block.verdict}`, ed.verdicts[block.verdict]);
      const name = el("span", "verdict-metric", metric.label);
      // The strongest evidence is named as such, not just placed first —
      // row order is invisible to a screen reader and to anyone who
      // quotes a single line out of the table.
      if (metric.primary) name.append(el("span", "verdict-primary-tag", ed.primaryTag));
      rowEl.append(badge, name);
      const levels = block.verdict === "insufficient"
        ? tpl(ed.rowInsufficient, { years: block.post.years })
        : tpl(ed.rowLevels, {
            early: fmtLevel(block.early.value, metric.unit),
            pre: fmtLevel(block.pre.value, metric.unit),
            post: fmtLevel(block.post.value, metric.unit),
            share: fmtSigned(block.shift_share_pct ?? 0),
          });
      rowEl.append(el("span", "verdict-levels mono", levels));
      table.append(rowEl);
    }

    // ---- panel note ---------------------------------------------------------
    const noteEl = slots.panel.querySelector(".panel-note");
    if (noteEl) {
      // "0 of 0 judged metrics accelerated" is technically true and reads
      // as a glitch; an era with nothing to judge gets its own sentence.
      noteEl.textContent = judged.length
        ? tpl(ed.note, {
            judged: judged.length,
            total: cells.length,
            accelerated: judged.filter((r) => r.block.verdict === "accelerated").length,
            window: banked.window_years,
            threshold: banked.inflection_threshold_pct,
          })
        : tpl(ed.noteWithheld, { total: cells.length, cut_year: era.cut_year });
    }
  };

  build(eraStore.id);
  eraStore.subscribe(build);
}
