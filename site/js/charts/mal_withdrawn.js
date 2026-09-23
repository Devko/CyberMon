// Malicious Packages 3 — withdrawn reports, by the year the report was
// published. Contract: site/data/registry_malware.json (years[].withdrawn,
// ecosystems[].withdrawn). Bars per year; the per-registry split is a text
// tally below (most registries have none).
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseGrid, fmtInt, fmtPct,
  escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";
import { ecoLabel, fillRef, noEdition } from "./osv_shared.js";

export function render(slots, data, refs) {
  const ed = editorial.sections.mal_withdrawn;
  const cat = data.catalog || {};
  const years = (data.years || []).filter((y) => y.total > 0);
  if (!cat.reports || !years.length) {
    noEdition(slots, ed.nodata, refs);
    return;
  }
  fillRef(refs?.caption, {
    withdrawn: fmtInt(cat.withdrawn),
    reports: fmtInt(cat.reports),
    pct: fmtPct((100 * cat.withdrawn) / cat.reports).replace(/^0\.0%$/, "<0.1%"),
  });
  const labels = years.map((y) => (y.partial ? `${y.year}*` : String(y.year)));

  slots.chart.style.height = "260px";
  const chart = mkChart(slots.chart);
  chart.setOption({
    grid: { ...baseGrid, left: 48, top: 30, bottom: 30 },
    tooltip: {
      ...baseTooltip,
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params) => {
        const y = years[params.length ? params[0].dataIndex : -1];
        return y ? escapeHtml(tpl(ed.tooltip, {
          year: y.year, n: fmtInt(y.withdrawn), total: fmtInt(y.total),
        })) : "";
      },
    },
    xAxis: catAxis(labels),
    yAxis: valAxis({
      name: ed.yAxis,
      minInterval: 1,
      nameTextStyle: { color: C.muted, fontFamily: MONO, fontSize: 11, align: "left" },
    }),
    series: [{
      type: "bar",
      barMaxWidth: 48,
      color: C.versions.v3,
      data: years.map((y) => y.withdrawn),
      label: {
        show: true, position: "top", color: C.muted, fontFamily: MONO, fontSize: 11,
        formatter: (p) => (p.value ? fmtInt(p.value) : ""),
      },
    }],
  });

  const line = el("div", "table-context");
  line.append(el("strong", null, `${ed.byEcosystem}: `));
  line.append((data.ecosystems || []).map((e) => tpl(ed.ecoTemplate, {
    name: ecoLabel(e.ecosystem), n: fmtInt(e.withdrawn), reports: fmtInt(e.reports),
  })).join(" · "));
  slots.extra.append(line);
}
