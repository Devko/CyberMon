// =============================================================================
// changelog.js — KEV Changelog tab (changelog.html). Builds the three
// changelog sections from editorial.js. Like epss.js, all sections share
// ONE contract file (data/kev_changelog.json), fetched once and passed to
// each renderer. Each renderer runs inside its own try/catch so one bad
// chart yields one inline error card, not a dead page. Shared chrome
// (masthead/nav/banner/footer) comes from common.js.
// =============================================================================
import { editorial } from "./editorial.js";
import { el, link, clear } from "./dom.js";
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, errorCard } from "./common.js";
import { render as renderEdits } from "./charts/changelog_edits.js";
import { render as renderFlips } from "./charts/changelog_flips.js";
import { render as renderReceipts } from "./charts/changelog_receipts.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/kev_changelog.json";

const SECTIONS = [
  { id: "edits", render: renderEdits, hero: true },
  { id: "flagflip", render: renderFlips },
  { id: "receipts", render: renderReceipts },
];

// ---- section skeleton (mirrors epss.js) --------------------------------------

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

  // Record-start callout (edits section): rendered as a template now,
  // filled by the renderer once the payload is here (kev.js pattern).
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
  const jobs = [initChrome("changelog")];

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
