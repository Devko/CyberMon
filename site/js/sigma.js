// =============================================================================
// sigma.js — Detection Rules tab (sigma.html). Builds the four sections from
// editorial.js. All sections share ONE contract file (data/sigma_coverage.json),
// fetched once and passed to each renderer with the section's caption and
// methodology nodes, whose {placeholders} the renderers fill from the payload
// (the advisories.js pattern). Each renderer runs inside its own try/catch so
// one bad chart yields one inline error card, not a dead page.
// =============================================================================
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderChurn } from "./charts/sigma_churn.js";
import { render as renderCoverage } from "./charts/sigma_coverage.js";
import { render as renderLag } from "./charts/sigma_lag.js";
import { render as renderTactics } from "./charts/sigma_tactics.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/sigma_coverage.json";

const SECTIONS = [
  { id: "sigma_churn", render: renderChurn, hero: true },
  { id: "sigma_coverage", render: renderCoverage },
  { id: "sigma_lag", render: renderLag },
  { id: "sigma_tactics", render: renderTactics },
];

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("sigma")];

  const built = [];
  for (const cfg of SECTIONS) {
    const { section, slots, caption, methodText } = buildSection(cfg, null, { dataFiles: [DATA_FILE] });
    main.append(section);
    built.push({ cfg, slots, refs: { caption, methodText } });
  }

  jobs.push(
    fetchJSON(DATA_FILE)
      .then((data) => {
        for (const { cfg, slots, refs } of built) {
          // Per-section isolation: the payload is shared, the failures aren't.
          try {
            cfg.render(slots, data, refs);
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
