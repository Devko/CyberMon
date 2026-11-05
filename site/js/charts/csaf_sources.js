// Machine-Readable Advisories 1 (hero) — each listed provider's CSAF
// documents split by type (VEX / security advisory / other). Contract:
// site/data/csaf_adoption.json (sources, totals). One 100%-stacked bar per
// measured provider plus an "all documents" bar on top; the provider's
// document count sits on a right-hand label axis (counts span five orders of
// magnitude, so a share axis keeps every provider readable). Providers the
// lister names but the pipeline could not count are listed under the chart
// with the reason.
import {
  C, MONO, mkChart, catAxis, valAxis, baseGrid, baseLegend, baseTooltip,
  fmtInt, fmtPct, escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";

export const GROUPS = ["vex", "advisory", "other", "unsampled"];
const COLORS = {
  vex: C.accent,
  advisory: C.versions.v3,
  other: C.versions.v2,
  unsampled: C.sev.unscored,
};

// Display name: the editorial short form when there is one.
export function shortName(name) {
  return editorial.sections.csaf_sources.shortNames[name] ?? name;
}

export function isMeasured(row) {
  return row.status === "measured" || row.status === "carried";
}

export function fillRef(node, vars) {
  if (node) node.textContent = tpl(node.textContent, vars);
}

export function noEdition(slots, text, refs) {
  slots.chart.classList.remove("chart", "chart-tall");
  slots.chart.append(el("div", "nodata-card", text));
  for (const node of [refs?.caption, refs?.methodText]) {
    if (node) node.textContent = node.textContent.replace(/\{\w+\}/g, editorial.ui.na);
  }
}

export function render(slots, data, refs) {
  const ed = editorial.sections.csaf_sources;
  const L = ed.labels;
  const rows = (data.sources || []).filter(isMeasured);
  const t = data.totals || {};
  if (!rows.length || !t.documents) {
    noEdition(slots, ed.nodata, refs);
    return;
  }

  fillRef(refs?.caption, {
    listed: fmtInt(t.listed),
    top_name: shortName(t.top_name),
    top_share: fmtPct(t.top_share_pct),
    documents: fmtInt(t.documents),
  });
  fillRef(refs?.methodText, { k: fmtInt(data.sampling?.k) });

  // ---- headline stat ---------------------------------------------------------
  const stat = el("div", "hero-stat");
  const row = el("div", "hero-stat-row");
  row.append(
    el("span", "hero-num accent", fmtPct(t.vex_pct)),
    el("span", "hero-when", tpl(ed.statWhen, {
      vex: fmtInt(t.mix?.vex),
      documents: fmtInt(t.documents),
      vex_top_share: fmtPct(t.vex_top_share_pct),
      vex_top_name: shortName(t.vex_top_name),
    }))
  );
  stat.append(el("div", "hero-stat-label", ed.statLabel), frag(row));
  slots.stat.append(stat);

  // ---- chart -----------------------------------------------------------------
  // ECharts draws the first category at the bottom: reverse so the "all
  // documents" bar and the largest provider sit on top.
  const bars = [{ name: ed.allRow, documents: t.documents, mix: t.mix, sample_n: t.sample_n }]
    .concat(rows.map((r) => ({ name: shortName(r.name), documents: r.documents, mix: r.mix,
                                sample_n: r.sample_n })))
    .reverse();
  const groups = GROUPS.filter((g) => bars.some((b) => (b.mix?.[g] ?? 0) > 0));
  const share = (b, g) => (b.documents ? (100 * (b.mix?.[g] ?? 0)) / b.documents : 0);

  slots.chart.style.height = `${Math.max(320, bars.length * 30 + 90)}px`;
  const chart = mkChart(slots.chart);
  const narrow = slots.chart.clientWidth < 520;
  chart.setOption({
    grid: { ...baseGrid, left: narrow ? 106 : 140, right: narrow ? 64 : 80, top: 34, bottom: 40 },
    legend: { ...baseLegend, data: groups.map((g) => ed.legend[g]), icon: "rect", itemHeight: 8 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params) => {
        const b = params.length && bars[params[0].dataIndex];
        if (!b) return "";
        const lines = groups
          .filter((g) => (b.mix?.[g] ?? 0) > 0)
          .map((g) => `<div>${escapeHtml(tpl(L.tipShare, {
            label: ed.legend[g],
            n: fmtInt(b.mix[g]),
            pct: fmtPct(share(b, g)),
          }))}</div>`)
          .join("");
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(b.name)} · ` +
          `${escapeHtml(tpl(L.tipDocs, { n: fmtInt(b.documents) }))}</div>` + lines +
          `<div style="color:${C.muted};margin-top:4px;">` +
          `${escapeHtml(tpl(L.tipSample, { n: fmtInt(b.sample_n) }))}</div>`
        );
      },
    },
    xAxis: valAxis({
      max: 100,
      name: ed.xAxis,
      nameLocation: "middle",
      nameGap: 24,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
      axisLabel: { ...valAxis().axisLabel, formatter: "{value}%" },
    }),
    yAxis: [
      catAxis(bars.map((b) => b.name), {
        axisLabel: { ...catAxis([]).axisLabel, fontSize: 11, width: narrow ? 98 : 132,
                     overflow: "truncate", interval: 0 },
      }),
      catAxis(bars.map((b) => fmtInt(b.documents)), {
        position: "right",
        axisLine: { show: false },
        axisLabel: { ...catAxis([]).axisLabel, fontSize: 11, color: C.muted, interval: 0 },
      }),
    ],
    series: groups.map((g) => ({
      name: ed.legend[g],
      type: "bar",
      stack: "mix",
      barWidth: "62%",
      color: COLORS[g],
      itemStyle: { borderColor: C.panel, borderWidth: 1 },
      data: bars.map((b) => Number(share(b, g).toFixed(2))),
    })),
  });

  // ---- sources the lister names but nobody could count -------------------------
  const missing = (data.sources || []).filter((r) => !isMeasured(r));
  if (missing.length) {
    const list = missing.map((r) => `${shortName(r.name)} (${tpl(
      ed.statusLabels[r.status] ?? r.status, { detail: r.detail })})`).join("; ");
    slots.extra.append(el("p", "table-context", tpl(ed.notCounted, { list })));
  }
  const carried = rows.filter((r) => r.status === "carried");
  if (carried.length) {
    const list = carried.map((r) => `${shortName(r.name)} (${r.measured_on})`).join("; ");
    slots.extra.append(el("p", "table-context", tpl(ed.carried, { list })));
  }
}
