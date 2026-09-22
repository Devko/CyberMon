// Shared bits for the two OSV-fed pages (advisories.html, malware.html):
// ecosystem display names, the registry palette, month labels and the
// template fill for captions / methodology the page scripts hand over.
import { C } from "../theme.js";
import { editorial, tpl } from "../editorial.js";
import { el } from "../dom.js";

export const ecoLabel = (id) => editorial.osvEcosystems[id] ?? id;

// Registry palette: colour follows the registry, never its rank. Checked
// with the dataviz validator against the dark panel (CVD and normal-vision
// separation pass for adjacent pairs; the low chroma is the house
// newsprint look). Registries past the fourth fold into Other.
export const REGISTRY_COLORS = {
  npm: C.accent,
  PyPI: C.versions.v3,
  RubyGems: C.sev.high,
  NuGet: "#6f93b8",
  other: "#6a665b",
};
export const FOLDED = ["npm", "PyPI", "RubyGems", "NuGet"];

// Fold a {registry: n} map into the fixed series FOLDED + "other".
export function fold(byEco) {
  const out = { other: 0 };
  for (const k of FOLDED) out[k] = 0;
  for (const [k, n] of Object.entries(byEco || {})) {
    if (FOLDED.includes(k)) out[k] += n;
    else out.other += n;
  }
  return out;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
export const monthLabel = (ym) => `${MONTHS[Number(ym.slice(5, 7)) - 1]} ${ym.slice(0, 4)}`;

// Fill a caption / methodology paragraph handed over by the page script
// (absent on carousel slides, which print neither).
export function fillRef(node, vars) {
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
