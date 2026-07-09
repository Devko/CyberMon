// =============================================================================
// main.js — CVE Ecosystem tab (index.html). Builds the six chart sections from
// editorial.js, fetches each contract file independently, renders charts.
// A failed fetch only takes down its own section (inline error card).
// Shared chrome (masthead/nav/banner/footer) comes from common.js.
// =============================================================================
import { editorial, tpl } from "./editorial.js";
import { el, link, clear } from "./dom.js";
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, errorCard } from "./common.js";
import { render as renderInflation } from "./charts/inflation.js";
import { render as renderFlood } from "./charts/flood.js";
import { render as renderReality } from "./charts/reality.js";
import { render as renderDecay } from "./charts/decay.js";
import { render as renderCna } from "./charts/cna.js";
import { render as renderVolume } from "./charts/volume.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const SECTIONS = [
  { id: "inflation", file: "data/severity_inflation.json", render: renderInflation, hero: true },
  { id: "flood", file: "data/nine_eight_flood.json", render: renderFlood },
  { id: "reality", file: "data/score_vs_reality.json", render: renderReality },
  { id: "decay", file: "data/nvd_decay.json", render: renderDecay },
  { id: "cna", file: "data/cna_leaderboard.json", render: renderCna },
  { id: "volume", file: "data/volume_curve.json", render: renderVolume },
];

// ---- section skeleton -------------------------------------------------------

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

  if (ed.note) panel.append(el("p", "panel-note", ed.note));

  const details = el("details", "method");
  const summary = el("summary", null, editorial.methodologyLabel);
  const methodBody = el("div", "method-body");
  const methodText = el("p", null, ed.methodology);
  const methodSrc = el("p", "method-src", editorial.methodologySourcePrefix);
  methodSrc.append(link(editorial.metricsUrl, editorial.methodologySourceLinkText, "mono"));
  methodBody.append(methodText, methodSrc);
  details.append(summary, methodBody);

  section.append(head, stat, panel, details);

  return { section, slots: { stat, panel, controls, chart, extra }, methodText };
}

function showError(slots, file) {
  clear(slots.controls);
  clear(slots.extra);
  clear(slots.chart).classList.remove("chart", "chart-tall");
  slots.chart.append(errorCard(file));
}

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("cve")];

  for (const cfg of SECTIONS) {
    const { section, slots, methodText } = buildSection(cfg);
    main.append(section);
    jobs.push(
      fetchJSON(cfg.file)
        .then((data) => {
          if (cfg.id === "cna") {
            // fill methodology placeholders from the contract itself
            methodText.textContent = tpl(editorial.sections.cna.methodology, {
              window_years: data.window_years,
              min_cves: data.min_cves,
            });
          }
          cfg.render(slots, data);
        })
        .catch((err) => {
          console.warn(`[CyberMon] section "${cfg.id}" failed:`, err);
          showError(slots, cfg.file);
        })
    );
  }

  await Promise.allSettled(jobs);
}

if (!window.echarts) {
  // ECharts CDN failed: sections degrade to error cards, the prose survives.
  console.warn("[CyberMon] ECharts failed to load from CDN.");
}
boot();
