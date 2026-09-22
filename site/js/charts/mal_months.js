// Registry Malware 1 (hero) — OpenSSF malicious-packages reports per month
// of feed publication, by registry. Contract: site/data/registry_malware.json
// (months, catalog, bursts). Default view stacks the registries on a linear
// axis (the bursts are the story); the log view draws each registry as its
// own line — never stacked, a stack on a log axis misreads — so the small
// registries stay legible beside npm.
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid,
  fmtInt, fmtPct, escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";
import { mkToggle } from "../ui.js";
import {
  FOLDED, REGISTRY_COLORS, ecoLabel, fillRef, fold, monthLabel, noEdition,
} from "./osv_shared.js";

const KEYS = [...FOLDED, "other"];
const kfmt = (v) => (v >= 1e6 ? `${v / 1e6}M` : v >= 1000 ? `${v / 1000}k` : v);

export function render(slots, data, refs) {
  const ed = editorial.sections.mal_months;
  const cat = data.catalog || {};
  const months = data.months || [];
  if (!cat.reports || !months.length) {
    noEdition(slots, ed.nodata, refs);
    return;
  }
  const top = (data.bursts || [])[0];
  const year = Number((data.as_of || data.generated_at).slice(0, 4));
  fillRef(refs?.caption, {
    peak_month: monthLabel(cat.peak_month),
    peak_reports: fmtInt(cat.peak_reports),
    peak_share: fmtPct(cat.peak_share_pct),
    peak_top_n: fmtInt(top?.top_source_reports),
    peak_top_source: top?.top_source ?? "—",
    median: fmtInt(cat.median_month),
  });
  const partial = months.find((m) => m.partial);
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    const text = tpl(ed.note, { month: partial ? monthLabel(partial.month) : "" });
    noteEl.textContent = partial ? text : text.replace(/^\*[^.]*\.\s*/, "");
  }

  // ---- headline stat ----------------------------------------------------------
  const stat = el("div", "hero-stat");
  const row = el("div", "hero-stat-row");
  row.append(
    el("span", "hero-num accent", fmtInt(cat.reports)),
    el("span", "hero-when", tpl(ed.statWhen, {
      first_month: monthLabel(cat.first_month),
      this_year: fmtInt(cat.this_year),
      year,
    }))
  );
  stat.append(el("div", "hero-stat-label", ed.statLabel), frag(row));
  slots.stat.append(stat);

  const labels = months.map((m) => (m.partial ? `${m.month}*` : m.month));
  const folded = months.map((m) => fold(m.by_ecosystem));
  const present = KEYS.filter((k) => folded.some((f) => f[k] > 0));

  const chart = mkChart(slots.chart);
  let log = false;
  const draw = () => {
    const series = present.map((k) => ({
      name: ecoLabel(k),
      color: REGISTRY_COLORS[k],
      emphasis: { focus: "series" },
      ...(log
        ? {
            type: "line",
            // small dots: a registry with one report between empty months
            // is a lone point, which a bare line would not draw
            symbol: "circle",
            symbolSize: 3,
            connectNulls: false,
            lineStyle: { width: 2, color: REGISTRY_COLORS[k] },
            // a log axis has no zero: an empty month is a gap in the line
            data: folded.map((f) => (f[k] > 0 ? f[k] : null)),
          }
        : {
            type: "bar",
            stack: "mal",
            barCategoryGap: "12%",
            data: folded.map((f) => f[k]),
          }),
    }));
    chart.setOption({
      grid: { ...baseGrid, left: 56, top: slots.chart.clientWidth < 600 ? 66 : 44, bottom: 30 },
      legend: { ...baseLegend, data: present.map(ecoLabel), icon: "rect", itemHeight: 8 },
      tooltip: {
        ...baseTooltip,
        trigger: "axis",
        axisPointer: { type: log ? "line" : "shadow" },
        formatter: (params) => {
          const i = params.length ? params[0].dataIndex : -1;
          const m = months[i];
          if (!m) return "";
          const rows = present
            .filter((k) => folded[i][k] > 0)
            .map((k) =>
              `<div style="display:flex;gap:10px;justify-content:space-between;">` +
              `<span><span style="display:inline-block;width:8px;height:8px;background:${REGISTRY_COLORS[k]};margin-right:6px;"></span>` +
              `${escapeHtml(ecoLabel(k))}</span><strong style="font-family:inherit">${fmtInt(folded[i][k])}</strong></div>`)
            .join("");
          return (
            `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(monthLabel(m.month))}${m.partial ? " *" : ""}</div>` +
            rows +
            `<div style="color:${C.muted};margin-top:4px;">${fmtInt(m.total)} reports` +
            (m.withdrawn ? ` · ${fmtInt(m.withdrawn)} withdrawn` : "") + `</div>`
          );
        },
      },
      xAxis: catAxis(labels, {
        axisLabel: {
          ...catAxis([]).axisLabel,
          // one label per January
          interval: (i) => labels[i].slice(5, 7) === "01",
          formatter: (v) => v.slice(0, 4),
        },
      }),
      yAxis: valAxis(log
        ? { type: "log", logBase: 10, min: 1, name: ed.yAxisLog,
            nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11, align: "left" },
            axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11,
                         formatter: kfmt } }
        : { type: "value", min: 0, name: ed.yAxis,
            nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11, align: "left" },
            axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11,
                         formatter: kfmt } }),
      series,
    }, { replaceMerge: ["series", "yAxis"] });
  };
  slots.controls.append(mkToggle([ed.toggleStacked, ed.toggleLog], (idx) => {
    log = idx === 1;
    draw();
  }));
  draw();

  // ---- the largest months, named ------------------------------------------------
  const bursts = data.bursts || [];
  if (bursts.length) {
    const line = el("div", "table-context");
    line.append(el("strong", null, `${ed.burstsLabel}: `));
    line.append(bursts.map((b) => tpl(
      b.top_source === "unattributed" ? ed.burstTemplateNone : ed.burstTemplate, {
      month: monthLabel(b.month),
      n: fmtInt(b.reports),
      share: fmtPct(b.share_pct),
      src_n: fmtInt(b.top_source_reports),
      src: b.top_source,
    })).join(" · "));
    slots.extra.append(line);
  }
}
