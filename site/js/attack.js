// =============================================================================
// attack.js — ATT&CK Churn tab (attack.html). Builds the three ATT&CK
// sections from editorial.js. Like kev.js, all sections share ONE contract
// file (data/attack_churn.json), fetched once and passed to each renderer.
// Each renderer runs inside its own try/catch so one bad chart yields one
// inline error card, not a dead page. Shared chrome (masthead/nav/banner/
// footer) comes from common.js.
// =============================================================================
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderMap } from "./charts/attack_map.js";
import { render as renderChurn } from "./charts/attack_churn.js";
import { render as renderCatalog } from "./charts/attack_catalog.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/attack_churn.json";

const SECTIONS = [
  { id: "map", render: renderMap, hero: true },
  { id: "churn", render: renderChurn },
  { id: "catalog", render: renderCatalog },
];

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("attack")];

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
