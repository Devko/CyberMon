// =============================================================================
// roster.js — CNA Roster History tab (roster.html). Builds the three roster
// sections from editorial.js. Like rescores.js, all sections share ONE
// contract file (data/cna_roster.json), fetched once and passed to each
// renderer; each renderer runs inside its own try/catch so one bad chart
// yields one inline error card, not a dead page. Shared chrome: common.js.
// =============================================================================
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderSize } from "./charts/roster_size.js";
import { render as renderFlux } from "./charts/roster_flux.js";
import { render as renderMix } from "./charts/roster_mix.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/cna_roster.json";

const SECTIONS = [
  { id: "roster_size", render: renderSize, hero: true },
  { id: "roster_flux", render: renderFlux },
  { id: "roster_mix", render: renderMix },
];

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("roster")];

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
