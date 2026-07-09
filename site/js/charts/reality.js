// Chart 3 — score vs. reality. Contract: site/data/score_vs_reality.json
import { C, mkChart, catAxis, baseTooltip, baseGrid, fmtInt, fmtPct, MONO } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

function statCard(bigText, leadText, noteText, accent) {
  const card = el("div", "stat-card");
  card.append(
    el("div", "stat-big" + (accent ? " accent" : ""), bigText),
    el("div", "stat-lead", leadText),
    el("div", "stat-note", noteText)
  );
  return card;
}

export function render(slots, data) {
  const ed = editorial.sections.reality;

  // ---- headline stats -------------------------------------------------------
  const hs = data.headline;
  const kev = data.kev;
  const stats = el("div", "stat-grid");
  stats.append(
    statCard(
      fmtPct(hs.pct_critical_epss_below_1pct),
      ed.statCriticalTemplate.replace("{pct} ", ""), // big number carries the {pct}
      tpl(ed.statCriticalNote, { n: fmtInt(hs.n_critical_with_epss) }),
      true
    ),
    statCard(
      fmtPct(kev.pct_below_high),
      ed.statKevTemplate.replace("{pct} ", ""),
      tpl(ed.statKevNote, { below_high: fmtInt(kev.below_high), total: fmtInt(kev.total) }),
      true
    )
  );
  slots.stat.append(stats);

  // ---- heatmap: CVSS × EPSS -------------------------------------------------
  const xCats = data.epss_buckets; // probability of exploitation
  const yCats = data.cvss_buckets; // severity, low -> high (bottom -> top)
  const cell = new Map(data.grid.map((g) => [`${g.cvss_bucket}|${g.epss_bucket}`, g.n]));
  const points = [];
  let maxLog = 0;
  let minLog = Infinity;
  yCats.forEach((cv, yi) => {
    xCats.forEach((ep, xi) => {
      const n = cell.get(`${cv}|${ep}`) ?? 0;
      const lg = Math.log10(n + 1); // log-ish scale so sparse cells stay visible
      maxLog = Math.max(maxLog, lg);
      minLog = Math.min(minLog, lg);
      points.push({ value: [xi, yi, +lg.toFixed(4)], raw: n });
    });
  });
  if (!Number.isFinite(minLog)) minLog = 0;

  const heat = mkChart(slots.chart);
  heat.setOption({
    grid: { ...baseGrid, left: 74, right: 14, top: 14, bottom: 54 },
    tooltip: {
      ...baseTooltip,
      formatter: (p) =>
        `<div style="color:${C.muted};margin-bottom:4px;">CVSS ${yCats[p.value[1]]} × EPSS ${xCats[p.value[0]]}</div>` +
        `<strong>${fmtInt(p.data.raw)}</strong> CVEs`,
    },
    xAxis: catAxis(xCats, {
      position: "bottom",
      name: "EPSS: probability of exploitation →",
      nameLocation: "middle", nameGap: 32,
      nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10 },
      splitArea: { show: false },
    }),
    yAxis: catAxis(yCats, {
      name: "CVSS →", nameLocation: "end",
      nameTextStyle: { color: C.faint, fontFamily: MONO, fontSize: 10, align: "right" },
    }),
    visualMap: {
      // anchor at the observed minimum so cells actually differentiate
      show: false, min: minLog, max: maxLog, dimension: 2,
      inRange: { color: ["#1d1e21", "#463030", "#7e352e", "#b53a30", C.accent] },
    },
    series: [{
      type: "heatmap",
      data: points,
      label: {
        show: true, color: C.ink, fontFamily: MONO, fontSize: 11,
        formatter: (p) => (p.data.raw >= 1000 ? `${(p.data.raw / 1000).toFixed(p.data.raw >= 10000 ? 0 : 1)}k` : String(p.data.raw)),
      },
      itemStyle: { borderColor: C.bg, borderWidth: 2 },
      emphasis: { itemStyle: { borderColor: C.ink, borderWidth: 1 } },
    }],
  });

  // ---- KEV distribution small bar ------------------------------------------
  const kevTitle = el("div", "panel-subtitle", ed.kevBarTitle);
  const kevEl = el("div", "chart chart-kev");
  slots.extra.append(kevTitle, kevEl);

  const kevCats = kev.cvss_distribution.map((d) => d.bucket);
  const kevChart = mkChart(kevEl);
  kevChart.setOption({
    grid: { left: 74, right: 40, top: 8, bottom: 8 },
    tooltip: { ...baseTooltip, formatter: (p) => `CVSS ${p.name}<br><strong>${fmtInt(p.value)}</strong> KEV entries` },
    xAxis: { type: "value", show: false },
    yAxis: catAxis(kevCats, { axisLine: { show: false } }),
    series: [{
      type: "bar",
      data: kev.cvss_distribution.map((d, i) => ({
        value: d.n,
        // accent = the inversion: exploited-in-the-wild yet rated below High
        itemStyle: { color: i < 2 ? C.accent : C.faint },
      })),
      barWidth: 12,
      label: { show: true, position: "right", color: C.muted, fontFamily: MONO, fontSize: 11, formatter: (p) => fmtInt(p.value) },
    }],
  });
}
