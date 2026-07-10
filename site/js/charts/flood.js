// Chart 2 — the 9.8 flood. Contract: site/data/nine_eight_flood.json
import { C, MONO, mkChart, catAxis, valAxis, baseTooltip, baseLegend, baseGrid, tooltipRows, tooltipFootnote, fmtInt, fmtPct } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";
import { mkToggle } from "../ui.js";

const BUCKETS = [
  // stacking order: bottom -> top; Critical crowns the stack in accent red.
  // "No score in record", not "Unscored": pre-2018 CVEs were mostly scored
  // by NVD in its own database, which this chart deliberately doesn't read.
  { key: "unscored", label: "No score in record" },
  { key: "low", label: "Low" },
  { key: "medium", label: "Medium" },
  { key: "high", label: "High" },
  { key: "critical", label: "Critical (≥9.0)" },
];

export function render(slots, data) {
  const ed = editorial.sections.flood;
  const edp = editorial.projection;
  // The generation year is still filling in — label it so its shorter bar
  // reads as "partial", not "decline".
  const genYear = Number(data.generated_at.slice(0, 4));
  const years = data.years.map((d) =>
    d.year === genYear ? `${d.year}*` : String(d.year));

  // Optional full-year pace projection of the current-year total (absolute
  // view only — shares are already normalized, so they never project).
  const proj = data.projection;
  const projIdx = proj ? data.years.findIndex((d) => d.year === proj.year) : -1;
  const hasProj = projIdx > 0;

  // Era marker: everything left of this line was scored (if at all) in
  // NVD's database, not in the CVE record — the near-empty severity bands
  // there are a fact about the record format, not about the vulnerabilities.
  const eraMarkLine = data.record_era
    ? {
        silent: true, symbol: "none",
        lineStyle: { color: C.faint, type: [3, 4], width: 1 },
        label: {
          color: C.muted, fontFamily: MONO, fontSize: 10,
          formatter: () => ed.eraMarker,
          position: "insideEndTop", distance: 6,
        },
        data: [{ xAxis: String(data.record_era.year) }],
      }
    : undefined;

  const mkSeries = (normalized) =>
    BUCKETS.map(({ key, label }, i) => ({
      name: label,
      type: "line",
      stack: "sev",
      areaStyle: { color: C.sev[key], opacity: key === "critical" ? 0.9 : 0.75 },
      lineStyle: { width: 0 },
      color: C.sev[key],
      symbol: "none",
      emphasis: { focus: "series" },
      ...(i === 0 && eraMarkLine ? { markLine: eraMarkLine } : {}),
      data: data.years.map((row) => {
        if (!normalized) return row[key];
        const total = BUCKETS.reduce((s, b) => s + row[b.key], 0);
        return total ? +((row[key] / total) * 100).toFixed(2) : 0;
      }),
    }));

  // Short dashed horizontal marker at the projected total height, spanning
  // the last year interval, with a small mono label anchored to its right
  // end (endLabel renders without symbols; per-point labels don't). Hidden
  // from the axis tooltip via the "_" prefix; the formatter appends its
  // own rows.
  const projMarker = () => ({
    name: "_projected total",
    type: "line",
    data: data.years.map((d, i) =>
      i === projIdx - 1 || i === projIdx ? proj.total : null),
    color: C.ink,
    symbol: "none",
    lineStyle: { width: 1.5, type: [3, 3], opacity: 0.9 },
    endLabel: {
      show: true,
      formatter: tpl(edp.floodLabel, { n: fmtInt(proj.total) }),
      color: C.muted,
      fontFamily: MONO,
      fontSize: 10,
      align: "right",
      verticalAlign: "bottom",
      offset: [0, -6],
    },
    z: 6,
    silent: true,
  });

  const chart = mkChart(slots.chart);

  const setMode = (normalized) => {
    chart.setOption(
      {
        grid: { ...baseGrid, left: 54, top: 44 },
        legend: { ...baseLegend, data: BUCKETS.map((b) => b.label).reverse(), icon: "rect", itemHeight: 8 },
        tooltip: {
          ...baseTooltip,
          trigger: "axis",
          order: "seriesDesc",
          formatter: (params) => {
            let html = tooltipRows(params, (v) => (normalized ? fmtPct(v) : fmtInt(v)));
            if (!normalized && hasProj && params.some((p) => p.dataIndex === projIdx)) {
              html += tooltipFootnote([
                tpl(edp.tooltipProjected, { name: edp.floodTooltipName, n: fmtInt(proj.total) }),
                tpl(edp.tooltipElapsed, { pct: fmtPct(proj.elapsed * 100) }),
              ]);
            }
            return html;
          },
        },
        xAxis: catAxis(years, { boundaryGap: false }),
        yAxis: valAxis(
          normalized
            ? { max: 100, axisLabel: { color: C.muted, fontFamily: baseLegend.textStyle.fontFamily, fontSize: 11, formatter: "{value}%" } }
            : { max: null, axisLabel: { color: C.muted, fontFamily: baseLegend.textStyle.fontFamily, fontSize: 11, formatter: (v) => (v >= 1000 ? `${v / 1000}k` : v) } }
        ),
        series: [
          ...mkSeries(normalized),
          ...(!normalized && hasProj ? [projMarker()] : []),
        ],
      },
      { replaceMerge: ["series", "yAxis"] }
    );
  };

  slots.controls.append(
    mkToggle([ed.toggleAbsolute, ed.toggleShare], (idx) => setMode(idx === 1))
  );
  setMode(false);
  if (hasProj) slots.extra.append(el("p", "panel-note", edp.note));
}
