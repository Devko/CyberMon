// =============================================================================
// credits.js — AI Credits tab (credits.html). Builds the four sections from
// editorial.js. All four share ONE contract file (data/ai_credits.json),
// fetched once and passed to each renderer. Each renderer runs inside its own
// try/catch so one bad chart yields one inline error card, not a dead page.
// Shared chrome comes from common.js.
// =============================================================================
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderFunnel } from "./charts/credits_funnel.js";
import { render as renderLanes } from "./charts/credits_lanes.js";
import { render as renderBoard } from "./charts/credits_board.js";
import { render as renderCoverage } from "./charts/credits_coverage.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/ai_credits.json";

const SECTIONS = [
  { id: "credits_funnel", render: renderFunnel, hero: true },
  { id: "credits_lanes", render: renderLanes },
  { id: "credits_board", render: renderBoard },
  { id: "credits_coverage", render: renderCoverage },
];

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("credits")];

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
