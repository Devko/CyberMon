// =============================================================================
// kev.js — KEV Latency tab (kev.html). Builds the four KEV sections from
// editorial.js. Like market.js, the three latency sections share ONE
// contract file (data/kev_latency.json), fetched once and passed to each
// renderer; the ransomware section reads its own file (no CVE join, own
// contract). Each renderer runs inside its own try/catch so one bad chart
// yields one inline error card, not a dead page. Shared chrome
// (masthead/nav/banner/footer) comes from common.js.
// =============================================================================
import { editorial } from "./editorial.js";
import { el, link, clear } from "./dom.js";
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, errorCard } from "./common.js";
import { render as renderLatency } from "./charts/kev_latency.js";
import { render as renderBuckets } from "./charts/kev_buckets.js";
import { render as renderRemediation } from "./charts/kev_remediation.js";
import { render as renderRansomware } from "./charts/kev_ransomware.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/kev_latency.json";

// Sections without an explicit file share DATA_FILE (and its single fetch).
const SECTIONS = [
  { id: "latency", render: renderLatency, hero: true },
  { id: "buckets", render: renderBuckets },
  { id: "remediation", render: renderRemediation },
  { id: "ransomware", render: renderRansomware, file: "data/kev_ransomware.json" },
];

// ---- section skeleton (mirrors market.js) -----------------------------------

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

  // Launch-batch callout (latency section): rendered as a template now, filled
  // by the renderer once the payload is here (decay.js panel-note pattern).
  if (ed.backfillNote) panel.append(el("p", "panel-note", ed.backfillNote));

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
  const jobs = [initChrome("kev")];

  // file -> the sections rendered from that file (one fetch per file).
  const byFile = new Map();
  for (const cfg of SECTIONS) {
    const { section, slots } = buildSection(cfg);
    main.append(section);
    const file = cfg.file ?? DATA_FILE;
    if (!byFile.has(file)) byFile.set(file, []);
    byFile.get(file).push({ cfg, slots });
  }

  for (const [file, built] of byFile) {
    jobs.push(
      fetchJSON(file)
        .then((data) => {
          for (const { cfg, slots } of built) {
            // Per-section isolation: the payload is shared, the failures aren't.
            try {
              cfg.render(slots, data);
            } catch (err) {
              console.warn(`[CyberMon] section "${cfg.id}" failed:`, err);
              showError(slots, file);
            }
          }
        })
        .catch((err) => {
          console.warn(`[CyberMon] ${file} failed:`, err);
          for (const { slots } of built) showError(slots, file);
        })
    );
  }

  await Promise.allSettled(jobs);
}

if (!window.echarts) {
  // ECharts CDN failed: chart sections degrade to error cards, the prose survives.
  console.warn("[CyberMon] ECharts failed to load from CDN.");
}
boot();
