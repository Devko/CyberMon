// =============================================================================
// adp.js — Vulnrichment / ADP handoff tab (adp.html). Builds the three
// sections from editorial.js. Like naming.js, every section shares ONE
// contract file (data/adp_coverage.json), fetched once and passed to each
// renderer. Each renderer runs inside its own try/catch so one bad chart
// yields one inline error card, not a dead page. Shared chrome comes from
// common.js.
//
// The hero also wants the CURRENT NVD backlog as "the gap CISA fills"
// context. That is a BEST-EFFORT secondary read of data/nvd_decay.json: its
// failure must never card the page — the handoff stands on its own — so it
// resolves to a number or null and is passed alongside the ADP data.
// =============================================================================
import { editorial } from "./editorial.js";
import { el, link, clear } from "./dom.js";
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, errorCard } from "./common.js";
import { render as renderHandoff } from "./charts/adp_handoff.js";
import { render as renderAdds } from "./charts/adp_adds.js";
import { render as renderProviders } from "./charts/adp_providers.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/adp_coverage.json";
const NVD_FILE = "data/nvd_decay.json"; // best-effort context, never required

const SECTIONS = [
  { id: "adp_handoff", render: renderHandoff, hero: true },
  { id: "adp_adds", render: renderAdds },
  { id: "adp_providers", render: renderProviders },
];

// ---- section skeleton (mirrors naming.js) -----------------------------------

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
  slots.panel.querySelector(".panel-note")?.remove();
  clear(slots.chart).classList.remove("chart", "chart-tall");
  slots.chart.append(errorCard(file));
}

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("adp")];

  const built = [];
  for (const cfg of SECTIONS) {
    const { section, slots } = buildSection(cfg);
    main.append(section);
    built.push({ cfg, slots });
  }

  // Best-effort NVD context: resolve to { nvdBacklog } — a number or null —
  // and NEVER reject, so a missing/failed nvd_decay.json can't card the page.
  const nvdCtx = fetchJSON(NVD_FILE)
    .then((d) => ({ nvdBacklog: d?.current?.backlog_total ?? null }))
    .catch(() => ({ nvdBacklog: null }));

  jobs.push(
    Promise.all([fetchJSON(DATA_FILE), nvdCtx])
      .then(([data, ctx]) => {
        for (const { cfg, slots } of built) {
          // Per-section isolation: the payload is shared, the failures aren't.
          try {
            cfg.render(slots, data, ctx);
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
boot().catch((err) => console.error("[CyberMon] page boot failed:", err));
