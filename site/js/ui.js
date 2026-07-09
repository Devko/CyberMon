// =============================================================================
// ui.js — small interactive widgets (no editorial strings here).
// =============================================================================
import { el } from "./dom.js";

// Segmented toggle. labels: string[]; onChange(index) fires on switch.
export function mkToggle(labels, onChange, activeIndex = 0) {
  const wrap = el("div", "toggle");
  wrap.setAttribute("role", "group");
  const buttons = labels.map((label, i) => {
    const b = el("button", "toggle-btn" + (i === activeIndex ? " is-active" : ""), label);
    b.type = "button";
    b.setAttribute("aria-pressed", String(i === activeIndex));
    b.addEventListener("click", () => {
      if (b.classList.contains("is-active")) return;
      buttons.forEach((x, j) => {
        x.classList.toggle("is-active", j === i);
        x.setAttribute("aria-pressed", String(j === i));
      });
      onChange(i);
    });
    wrap.append(b);
    return b;
  });
  return wrap;
}
