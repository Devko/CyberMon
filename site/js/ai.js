// =============================================================================
// ai.js — The AI Alibi tab (ai.html). Builds the three sections from
// editorial.js. Like exploits.js, all sections share ONE contract file
// (data/ai_alibi.json), fetched once and passed to each renderer.
//
// One thing this page does that the others don't: the era cutoff is a
// SHARED control. The hero owns the selector, and the inflection board
// re-renders when it changes — so a reader who suspects the default date
// was chosen to flatter the thesis can move it and watch the answer.
// The store lives in charts/ai_era.js because the carousel generator
// calls the same renderers without one; here it is created `live`.
//
// Each renderer runs inside its own try/catch so one bad chart yields one
// inline error card, not a dead page. Shared chrome comes from common.js.
// =============================================================================
import { editorial } from "./editorial.js";
import { el, link, clear } from "./dom.js";
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, errorCard } from "./common.js";
import { makeEraStore } from "./charts/ai_era.js";
import { render as renderClock } from "./charts/ai_clock.js";
import { render as renderBanked } from "./charts/ai_banked.js";
import { render as renderAttention } from "./charts/ai_attention.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/ai_alibi.json";

const SECTIONS = [
  { id: "ai_clock", render: renderClock, hero: true },
  { id: "ai_banked", render: renderBanked },
  { id: "ai_attention", render: renderAttention },
];

// ---- section skeleton (mirrors exploits.js) ---------------------------------

function buildSection(cfg) {
  const ed = editorial.sections[cfg.id];
  if (!ed) throw new Error(`no editorial.sections entry for section "${cfg.id}"`);
  const section = el("section", "chart-section" + (cfg.hero ? " hero" : ""));
  section.id = `s-${cfg.id}`;

  const head = el("header", "section-head");
  head.append(
    el("p", "section-kicker", `${ed.num} — ${ed.kicker}`),
    el("h2", "section-headline", ed.headline),
    el("p", "section-caption", ed.caption)
  );

  const stat = el("div", "section-stat");
  const panel = el("div", "panel");
  const controls = el("div", "panel-controls");
  const chart = el("div", "chart" + (cfg.hero ? " chart-tall" : ""));
  const extra = el("div", "panel-extra");
  panel.append(controls, chart, extra);

  // Panel-note template, filled by the renderer once the payload is here
  // (exploits.js backfillNote pattern).
  if (ed.note) panel.append(el("p", "panel-note", ed.note));

  if (ed.source) {
    const src = el("p", "chart-source");
    src.append(editorial.chartSourcePrefix + ed.source + " · ");
    src.append(link("#footer", editorial.chartSourceLinkText, "mono"));
    panel.append(src);
  }

  const details = el("details", "method");
  const summary = el("summary", null, editorial.methodologyLabel);
  const methodBody = el("div", "method-body");
  const methodText = el("p", null, ed.methodology);
  const methodSrc = el("p", "method-src", editorial.methodologySourcePrefix);
  methodSrc.append(link(editorial.metricsUrl, editorial.methodologySourceLinkText, "mono"));
  methodBody.append(methodText, methodSrc);
  details.append(summary, methodBody);

  section.append(head, stat, panel, details);

  return { section, slots: { stat, panel, controls, chart, extra } };
}

function showError(slots) {
  clear(slots.stat);
  clear(slots.controls);
  clear(slots.extra);
  // Never leave an unfilled {placeholder} note next to an error card.
  slots.panel.querySelector(".panel-note")?.remove();
  clear(slots.chart).classList.remove("chart", "chart-tall");
  slots.chart.append(errorCard(DATA_FILE));
}

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("ai")];

  const built = [];
  for (const cfg of SECTIONS) {
    const { section, slots } = buildSection(cfg);
    main.append(section);
    built.push({ cfg, slots });
  }

  jobs.push(
    fetchJSON(DATA_FILE)
      .then((data) => {
        const eraStore = makeEraStore(data, { live: true });
        for (const { cfg, slots } of built) {
          // Per-section isolation: the payload is shared, the failures aren't.
          try {
            cfg.render(slots, data, eraStore);
          } catch (err) {
            console.warn(`[CyberMon] section "${cfg.id}" failed:`, err);
            showError(slots);
          }
        }
      })
      .catch((err) => {
        console.warn(`[CyberMon] ${DATA_FILE} failed:`, err);
        for (const { slots } of built) showError(slots);
      })
  );

  await Promise.allSettled(jobs);
}

if (!window.echarts) {
  // ECharts CDN failed: chart sections degrade to error cards, the prose survives.
  console.warn("[CyberMon] ECharts failed to load from CDN.");
}
boot().catch((err) => console.error("[CyberMon] page boot failed:", err));
