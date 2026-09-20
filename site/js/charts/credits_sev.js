// Shared by the AI Credits funnel and board: the severity strip (one flex
// segment per bucket, widths = share of the row's counted CVEs) and its
// legend. Fills come from the theme.js severity ramp — accent is Critical.
import { C, fmtInt } from "../theme.js";
import { el } from "../dom.js";

export const SEVERITIES = ["critical", "high", "medium", "low", "unscored"];

export function sevStrip(severity, labels) {
  const total = SEVERITIES.reduce((n, s) => n + (severity[s] || 0), 0);
  const strip = el("div", "sev-strip");
  strip.setAttribute("role", "img");
  strip.setAttribute("aria-label", SEVERITIES
    .filter((s) => severity[s])
    .map((s) => `${labels[s]} ${severity[s]}`).join(", "));
  for (const s of SEVERITIES) {
    if (!severity[s]) continue;
    const seg = el("span");
    seg.style.flex = `${severity[s]} 0 0`;
    seg.style.background = C.sev[s];
    seg.title = `${labels[s]} ${fmtInt(severity[s])} of ${fmtInt(total)}`;
    strip.append(seg);
  }
  return strip;
}

export function sevLegend(severity, labels) {
  const legend = el("div", "sev-legend");
  for (const s of SEVERITIES) {
    if (!severity[s]) continue;
    const item = el("span");
    const swatch = el("i");
    swatch.style.background = C.sev[s];
    item.append(swatch, `${labels[s]} ${fmtInt(severity[s])}`);
    legend.append(item);
  }
  return legend;
}
