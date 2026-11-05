// Shared bits for the Detection Rules page (sigma.html): the template fill
// for captions / methodology the page script hands over, and the honest
// empty-edition card.
import { el } from "../dom.js";

// Fill a caption / methodology paragraph handed over by the page script
// (absent on carousel slides, which print neither).
export function fillRef(node, vars, tpl) {
  if (node) node.textContent = tpl(node.textContent, vars);
}

// The page's empty-edition card: an honest "not yet", not an error.
export function noEdition(slots, text, refs) {
  for (const node of [refs?.caption, refs?.methodText]) {
    if (node) node.textContent = node.textContent.replace(/\{\w+\}/g, "—");
  }
  slots.chart.classList.remove("chart", "chart-tall");
  slots.chart.removeAttribute("role");
  slots.panel.querySelector(".panel-note")?.remove();
  slots.chart.append(el("div", "nodata-card", text));
}

// "2023Q1" -> "Q1 2023" for tooltips and stat lines.
export const quarterName = (q) => (q ? `${q.slice(4)} ${q.slice(0, 4)}` : "—");

// Quarter-axis label: the year under each Q1 slot ("2017Q1" -> "2017"),
// every other year only when the chart is narrow.
export function yearLabel(quarter, narrow) {
  if (!quarter.startsWith(`${quarter.slice(0, 4)}Q1`)) return "";
  const year = Number(quarter.slice(0, 4));
  return narrow && year % 2 ? "" : String(year);
}
