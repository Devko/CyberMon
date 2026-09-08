// =============================================================================
// epss.js — EPSS Report Card tab (epss.html). Builds the three report-card
// sections from editorial.js. Like kev.js, all sections share ONE contract
// file (data/epss_report.json), fetched once and passed to each renderer.
// Each renderer runs inside its own try/catch so one bad chart yields one
// inline error card, not a dead page. Shared chrome (masthead/nav/banner/
// footer) comes from common.js.
// =============================================================================
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderGrade } from "./charts/epss_grade.js";
import { render as renderDistribution } from "./charts/epss_distribution.js";
import { render as renderPercentile } from "./charts/epss_percentile.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/epss_report.json";

const SECTIONS = [
  { id: "grade", render: renderGrade, hero: true },
  { id: "distribution", render: renderDistribution },
  { id: "percentile", render: renderPercentile },
];

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("epss")];

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
            showError(slots, DATA_FILE, err);
          }
        }
      })
      .catch((err) => {
        console.warn(`[CyberMon] ${DATA_FILE} failed:`, err);
        for (const { slots } of built) showError(slots, DATA_FILE, err);
      })
  );

  await Promise.allSettled(jobs);
}

if (!window.echarts) {
  // ECharts CDN failed: chart sections degrade to error cards, the prose survives.
  console.warn("[CyberMon] ECharts failed to load from CDN.");
}
boot().catch((err) => console.error("[CyberMon] page boot failed:", err));
