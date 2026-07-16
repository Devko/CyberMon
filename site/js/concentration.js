// =============================================================================
// concentration.js — CNA Concentration tab (concentration.html). Builds the
// three concentration sections from editorial.js. Like market.js, ALL
// sections share ONE contract file (data/cna_concentration.json): it is
// fetched once and the parsed payload is passed to every section renderer.
// Each renderer runs inside its own try/catch so one bad chart yields one
// inline error card, not a dead page. Two sections carry editorial
// {placeholders} that are filled from the payload before rendering (the
// cve.js cna-methodology pattern). Shared chrome comes from common.js.
// =============================================================================
import { editorial, tpl } from "./editorial.js";
import { el, link, clear } from "./dom.js";
import { hookResize, fmtInt } from "./theme.js";
import { initChrome, fetchJSON, errorCard } from "./common.js";
import { render as renderConcentration } from "./charts/concentration_trend.js";
import { render as renderEntrants } from "./charts/concentration_entrants.js";
import { render as renderRejection } from "./charts/concentration_rejection.js";

// RELATIVE path only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/cna_concentration.json";

const SECTIONS = [
  { id: "concentration", render: renderConcentration, hero: true },
  { id: "entrants", render: renderEntrants },
  { id: "rejection", render: renderRejection },
];

// ---- section skeleton (mirrors market.js) -----------------------------------

function buildSection(cfg) {
  const ed = editorial.sections[cfg.id];
  if (!ed) throw new Error(`no editorial.sections entry for section "${cfg.id}"`);
  const section = el("section", "chart-section" + (cfg.hero ? " hero" : ""));
  section.id = `s-${cfg.id}`;

  const head = el("header", "section-head");
  const caption = el("p", "section-caption", ed.caption);
  head.append(
    el("p", "section-kicker", `${ed.num} — ${ed.kicker}`),
    el("h2", "section-headline", ed.headline),
    caption
  );

  const stat = el("div", "section-stat");
  const panel = el("div", "panel");
  const controls = el("div", "panel-controls");
  const chart = el("div", "chart" + (cfg.hero ? " chart-tall" : ""));
  const extra = el("div", "panel-extra");
  panel.append(controls, chart, extra);

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

  return { section, slots: { stat, panel, controls, chart, extra }, caption, methodText };
}

// Fill editorial {placeholders} from the contract itself (cve.js pattern).
function fillTemplates(cfg, refs, data) {
  if (cfg.id === "concentration") {
    const hhi = data.headline?.hhi_latest;
    refs.methodText.textContent = tpl(editorial.sections.concentration.methodology, {
      hhi_latest: Number.isFinite(hhi) ? fmtInt(Math.round(hhi)) : "n/a",
    });
  } else if (cfg.id === "rejection") {
    const rl = data.rejection_leaderboard || {};
    const vars = {
      window_years: rl.window_years ?? "?",
      min_total: Number.isFinite(rl.min_total) ? fmtInt(rl.min_total) : "?",
    };
    refs.caption.textContent = tpl(editorial.sections.rejection.caption, vars);
    refs.methodText.textContent = tpl(editorial.sections.rejection.methodology, vars);
  }
}

function showError(slots, file) {
  clear(slots.stat);
  clear(slots.controls);
  clear(slots.extra);
  clear(slots.chart).classList.remove("chart", "chart-tall");
  slots.chart.append(errorCard(file));
}

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("concentration")];

  const built = [];
  for (const cfg of SECTIONS) {
    const { section, slots, caption, methodText } = buildSection(cfg);
    main.append(section);
    built.push({ cfg, slots, refs: { caption, methodText } });
  }

  jobs.push(
    fetchJSON(DATA_FILE)
      .then((data) => {
        for (const { cfg, slots, refs } of built) {
          // Per-section isolation: the payload is shared, the failures aren't.
          try {
            fillTemplates(cfg, refs, data);
            cfg.render(slots, data);
          } catch (err) {
            console.warn(`[CyberMon] section "${cfg.id}" failed:`, err);
            showError(slots, DATA_FILE);
          }
        }
      })
      .catch((err) => {
        console.warn(`[CyberMon] ${DATA_FILE} failed:`, err);
        for (const { cfg, slots, refs } of built) {
          // No payload: resolve editorial {placeholders} to honest fallbacks
          // so raw template braces never reach the reader.
          fillTemplates(cfg, refs, {});
          showError(slots, DATA_FILE);
        }
      })
  );

  await Promise.allSettled(jobs);
}

if (!window.echarts) {
  // ECharts CDN failed: chart sections degrade to error cards, the prose survives.
  console.warn("[CyberMon] ECharts failed to load from CDN.");
}
boot().catch((err) => console.error("[CyberMon] page boot failed:", err));
