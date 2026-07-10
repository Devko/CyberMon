// =============================================================================
// breaches.js — Breach Ledger tab (breaches.html). Builds the three breach
// sections from editorial.js. All three sections share ONE contract file
// (data/breach_ledger.json), fetched once and passed to each renderer
// (kev.js pattern). Each renderer runs inside its own try/catch so one bad
// chart yields one inline error card, not a dead page. Shared chrome
// (masthead/nav/banner/footer) comes from common.js.
// =============================================================================
import { editorial } from "./editorial.js";
import { el, link, clear } from "./dom.js";
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, errorCard } from "./common.js";
import { render as renderLag } from "./charts/breach_lag.js";
import { render as renderVolume } from "./charts/breach_volume.js";
import { render as renderClasses } from "./charts/breach_classes.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/breach_ledger.json";

const SECTIONS = [
  { id: "disclosure", render: renderLag, hero: true },
  { id: "exposure", render: renderVolume },
  { id: "leaks", render: renderClasses },
];

// ---- section skeleton (mirrors kev.js) --------------------------------------

function buildSection(cfg) {
  const ed = editorial.sections[cfg.id];
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

  // Panel-note template (import-era callout / cohort audit trail): rendered
  // now, filled by the renderer once the payload is here (kev.js pattern).
  const noteTpl = ed.importNote ?? ed.catalogNote;
  if (noteTpl) panel.append(el("p", "panel-note", noteTpl));

  if (ed.source) {
    const src = el("p", "chart-source");
    src.append(editorial.chartSourcePrefix + ed.source + " \u00b7 ");
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

function showError(slots, file) {
  clear(slots.stat);
  clear(slots.controls);
  clear(slots.extra);
  // Never leave an unfilled {placeholder} note next to an error card.
  slots.panel.querySelector(".panel-note")?.remove();
  clear(slots.chart).classList.remove("chart", "chart-tall");
  slots.chart.append(errorCard(file));
}

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("breaches")];

  const built = [];
  for (const cfg of SECTIONS) {
    const { section, slots } = buildSection(cfg);
    main.append(section);
    built.push({ cfg, slots });
  }

  jobs.push(
    fetchJSON(DATA_FILE)
      .then((data) => {
        for (const { cfg, slots } of built) {
          // Per-section isolation: the payload is shared, the failures aren't.
          try {
            cfg.render(slots, data);
          } catch (err) {
            console.warn(`[CyberMon] section "${cfg.id}" failed:`, err);
            showError(slots, DATA_FILE);
          }
        }
      })
      .catch((err) => {
        console.warn(`[CyberMon] ${DATA_FILE} failed:`, err);
        for (const { slots } of built) showError(slots, DATA_FILE);
      })
  );

  await Promise.allSettled(jobs);
}

if (!window.echarts) {
  // ECharts CDN failed: chart sections degrade to error cards, the prose survives.
  console.warn("[CyberMon] ECharts failed to load from CDN.");
}
boot();
