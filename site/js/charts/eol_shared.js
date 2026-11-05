// Support Windows — helpers shared by the three eol_* renderers and the page
// script (eol.js). Contract: site/data/support_windows.json. Windows arrive
// as whole days; the page shows years with one decimal.
import { fmtInt } from "../theme.js";
import { tpl } from "../editorial.js";
import { el } from "../dom.js";

const DAYS_PER_YEAR = 365.25;

export const toYears = (days) =>
  Number.isFinite(days) ? Math.round((days / DAYS_PER_YEAR) * 10) / 10 : null;

// "2.3 years", or "at least 4.1 years" for a median that was not reached,
// or the n/a word when neither is known.
export function yearsLabel(labels, days, atLeast, na) {
  if (Number.isFinite(days)) return tpl(labels.years, { n: toYears(days).toFixed(1) });
  if (Number.isFinite(atLeast) && labels.atLeast) {
    return tpl(labels.atLeast, { n: toYears(atLeast).toFixed(1) });
  }
  return na;
}

// Tooltip line "2.3 years (853 days)".
export function medianTip(labels, days, atLeast, na) {
  if (!Number.isFinite(days)) return yearsLabel(labels, days, atLeast, na);
  return tpl(labels.tipMedian, {
    years: yearsLabel(labels, days, null, na),
    days: fmtInt(days),
  });
}

// An empty edition: an honest empty card in place of the chart.
export function noData(slots, text) {
  slots.chart.classList.remove("chart", "chart-tall");
  slots.chart.append(el("div", "nodata-card", text));
}

// One point of a by-year line: hollow when the year is provisional.
export function yearPoint(value, provisional, color) {
  if (!Number.isFinite(value)) return null; // a gap, never a joined line
  return {
    value,
    symbol: provisional ? "emptyCircle" : "circle",
    symbolSize: provisional ? 7 : 5,
    itemStyle: { color, borderColor: color, borderWidth: provisional ? 1.5 : 0 },
  };
}
