// Advisory Gap 1 (hero) — reviewed GHSA advisories per GitHub publication
// year, split by whether they carry a CVE alias. Contract:
// site/data/advisory_gap.json (years + ecosystems[].years). An ecosystem
// picker swaps the series; a toggle swaps counts for the no-CVE share. The
// young no-CVE cohort (published inside the young window) is its own pale
// segment — provisional, because a CVE can still be added.
import {
  C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid,
  fmtInt, fmtPct, escapeHtml,
} from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el, frag } from "../dom.js";
import { mkToggle } from "../ui.js";
import { ecoLabel, fillRef, noEdition } from "./osv_shared.js";

const YOUNG = "rgba(255, 74, 63, 0.38)";

export function render(slots, data, refs) {
  const ed = editorial.sections.gap_years;
  const cat = data.catalog || {};
  const years = data.years || [];
  if (!cat.advisories || !years.length) {
    noEdition(slots, ed.nodata, refs);
    return;
  }

  const lag = data.cve_lag || {};
  const partial = years.find((y) => y.partial);
  fillRef(refs?.caption, {
    without_pct: fmtPct(cat.without_cve_pct),
    advisories: fmtInt(cat.advisories),
    without: fmtInt(cat.without_cve),
  });
  fillRef(refs?.methodText, {
    not_reviewed: fmtInt(cat.not_reviewed),
    withdrawn: fmtInt(cat.withdrawn_excluded),
    multi: fmtInt(cat.multi_ecosystem),
    days: data.young_days,
  });
  const noteEl = slots.panel.querySelector(".panel-note");
  if (noteEl) {
    const text = tpl(ed.note, {
      year: partial ? partial.year : "",
      lag_n: fmtInt(lag.n),
      later_90: fmtInt(lag.later_90d),
      later_365: fmtInt(lag.later_365d),
    });
    // No partial year on file (a January edition before the first
    // advisory): drop the asterisk sentence, keep the rest.
    noteEl.textContent = partial ? text : text.replace(/^\*[^.]*\.\s*/, "");
  }

  // ---- headline stat ----------------------------------------------------------
  const stat = el("div", "hero-stat");
  const row = el("div", "hero-stat-row");
  row.append(
    el("span", "hero-num accent", fmtPct(cat.without_cve_pct)),
    el("span", "hero-when", tpl(ed.statWhen, {
      without: fmtInt(cat.without_cve),
      advisories: fmtInt(cat.advisories),
    }))
  );
  stat.append(el("div", "hero-stat-label", ed.statLabel), frag(row));
  slots.stat.append(stat);

  // ---- series sources: all ecosystems, or one --------------------------------
  const ecos = data.ecosystems || [];
  const labels = years.map((y) => (y.partial ? `${y.year}*` : String(y.year)));
  let rows = years;
  let share = false;
  const youngName = tpl(ed.legendYoung, { days: data.young_days });

  const chart = mkChart(slots.chart);
  const draw = () => {
    const tooltip = {
      ...baseTooltip,
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params) => {
        const i = params.length ? params[0].dataIndex : -1;
        const r = rows[i];
        if (!r) return "";
        const line = (color, name, v) =>
          `<div style="display:flex;gap:10px;justify-content:space-between;">` +
          `<span><span style="display:inline-block;width:8px;height:8px;background:${color};margin-right:6px;"></span>` +
          `${escapeHtml(name)}</span><strong style="font-family:inherit">${fmtInt(v)}</strong></div>`;
        return (
          `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(labels[i])}</div>` +
          line(C.versions.v2, ed.legendWith, r.with_cve) +
          line(C.accent, ed.legendWithout, r.without_cve - r.without_cve_young) +
          (r.without_cve_young ? line(YOUNG, youngName, r.without_cve_young) : "") +
          `<div style="color:${C.muted};margin-top:4px;">` +
          `${escapeHtml(tpl(ed.tooltipShare, { pct: r.total ? fmtPct((100 * r.without_cve) / r.total) : "—" }))}` +
          ` · ${fmtInt(r.total)} total</div>`
        );
      },
    };
    const series = share
      ? [{
          name: ed.legendShare,
          type: "line",
          symbol: "circle",
          symbolSize: 8,
          lineStyle: { color: C.accent, width: 2 },
          itemStyle: { color: C.accent },
          data: rows.map((r) => (r.total ? Math.round((1000 * r.without_cve) / r.total) / 10 : null)),
        }]
      : [
          { name: ed.legendWith, color: C.versions.v2, data: rows.map((r) => r.with_cve) },
          { name: ed.legendWithout, color: C.accent,
            data: rows.map((r) => r.without_cve - r.without_cve_young) },
          { name: youngName, color: YOUNG, data: rows.map((r) => r.without_cve_young) },
        ].map((s) => ({
          ...s, type: "bar", stack: "gap", barMaxWidth: 42,
          itemStyle: { borderColor: C.panel, borderWidth: 1 },
          emphasis: { focus: "series" },
        }));
    chart.setOption({
      grid: { ...baseGrid, left: 52, top: 58, bottom: 30 },
      legend: {
        ...baseLegend,
        data: share ? [ed.legendShare] : [ed.legendWith, ed.legendWithout, youngName],
        icon: "rect",
        itemHeight: 8,
      },
      tooltip,
      xAxis: catAxis(labels),
      yAxis: valAxis(share
        ? { max: 100, name: null, axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11, formatter: "{value}%" } }
        : { max: null, minInterval: 1,
            axisLabel: { color: C.muted, fontFamily: MONO, fontSize: 11,
                         formatter: (v) => (v >= 1000 ? `${v / 1000}k` : v) } }),
      series,
    }, { replaceMerge: ["series", "yAxis", "legend"] });
  };

  // ---- controls ------------------------------------------------------------------
  const label = el("label", "term-select-label", ed.selectLabel);
  const select = el("select", "term-select");
  const all = el("option", null, ed.allLabel);
  all.value = "";
  select.append(all);
  for (const e of ecos) {
    const opt = el("option", null, `${ecoLabel(e.ecosystem)} · ${fmtInt(e.total)}`);
    opt.value = e.ecosystem;
    select.append(opt);
  }
  label.append(select);
  select.addEventListener("change", () => {
    const hit = ecos.find((e) => e.ecosystem === select.value);
    rows = hit ? hit.years : years;
    draw();
  });
  // Two controls: let them wrap onto two rows at phone width.
  slots.controls.style.flexWrap = "wrap";
  slots.controls.style.gap = "0 14px";
  slots.controls.append(
    mkToggle([ed.toggleCount, ed.toggleShare], (idx) => { share = idx === 1; draw(); }),
    label
  );
  draw();
}
