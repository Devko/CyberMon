// =============================================================================
// theme.js — shared palette, ECharts base styling, formatting helpers.
// Colors mirror the CSS custom properties in css/style.css.
// =============================================================================

export const C = {
  bg: "#0e0f11",
  panel: "#15171a",
  panelUp: "#1b1d21",
  ink: "#e9e4d8",
  muted: "#96907f",
  faint: "#5d594e",
  rule: "#2a2c2e",
  accent: "#ff4a3f",
  accentSoft: "rgba(255, 74, 63, 0.14)",

  // Severity ramp: accent reserved for Critical; the rest stay newsprint-neutral.
  sev: {
    critical: "#ff4a3f",
    high: "#c08a45",
    medium: "#77715f",
    low: "#4b473d",
    unscored: "#312f2a",
  },

  versions: { v2: "#847e6d", v3: "#ded7c2", v4: "#a89f8a" },
};

export const MONO =
  'ui-monospace, "Cascadia Mono", "SF Mono", Menlo, Consolas, "Liberation Mono", monospace';

export const fmtInt = (n) => Number(n).toLocaleString("en-US");
export const fmtPct = (v) => `${Number(v).toFixed(1)}%`;

// ECharts tooltips render via innerHTML — every data-derived string
// interpolated into a tooltip formatter must pass through this first.
export const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// --- ECharts shared option fragments ----------------------------------------

export const baseText = { color: C.muted, fontFamily: MONO, fontSize: 11 };

export function catAxis(data, extra = {}) {
  return {
    type: "category",
    data,
    axisLine: { lineStyle: { color: C.rule } },
    axisTick: { show: false },
    axisLabel: { ...baseText },
    ...extra,
  };
}

export function valAxis(extra = {}) {
  return {
    type: "value",
    axisLine: { show: false },
    axisLabel: { ...baseText },
    splitLine: { lineStyle: { color: C.rule, type: [2, 4] } },
    ...extra,
  };
}

export const baseTooltip = {
  backgroundColor: "#1b1d21",
  borderColor: C.rule,
  borderWidth: 1,
  padding: [8, 12],
  textStyle: { color: C.ink, fontFamily: MONO, fontSize: 12 },
  extraCssText: "box-shadow: 0 8px 24px rgba(0,0,0,.5); border-radius: 2px;",
};

export const baseLegend = {
  textStyle: { color: C.muted, fontFamily: MONO, fontSize: 11 },
  inactiveColor: C.faint,
  itemWidth: 14,
  itemHeight: 2,
  icon: "rect",
  top: 0,
};

export const baseGrid = { left: 44, right: 18, top: 36, bottom: 28 };

// --- Chart registry (for window-resize handling) ----------------------------

const instances = [];

export function mkChart(el) {
  const chart = window.echarts.init(el, null, { renderer: "canvas" });
  instances.push(chart);
  return chart;
}

let hooked = false;
export function hookResize() {
  if (hooked) return;
  hooked = true;
  let t = null;
  window.addEventListener("resize", () => {
    clearTimeout(t);
    t = setTimeout(() => instances.forEach((c) => c.resize()), 120);
  });
}

// Axis-tooltip formatter that hides helper series (names starting with "_").
export function tooltipRows(params, valueFmt = (v) => v) {
  const rows = params
    .filter((p) => p.seriesName && !p.seriesName.startsWith("_"))
    .filter((p) => p.value !== null && p.value !== undefined && !Number.isNaN(p.value))
    .map(
      (p) =>
        `<div style="display:flex;gap:10px;justify-content:space-between;align-items:baseline;">` +
        `<span>${p.marker} ${p.seriesName}</span>` +
        `<strong style="font-family:inherit">${valueFmt(p.value)}</strong></div>`
    )
    .join("");
  const head = params.length ? `<div style="color:${C.muted};margin-bottom:4px;">${escapeHtml(params[0].axisValueLabel ?? params[0].name)}</div>` : "";
  return head + rows;
}
