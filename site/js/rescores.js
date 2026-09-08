// =============================================================================
// rescores.js — Silent Rescores tab (rescores.html). Builds the three rescore
// sections from editorial.js. Like calendar.js, all sections share ONE
// contract file (data/rescore_log.json), fetched once and passed to each
// renderer; each renderer runs inside its own try/catch so one bad chart
// yields one inline error card, not a dead page. Shared chrome: common.js.
// =============================================================================
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderWeek } from "./charts/rescore_week.js";
import { render as renderMagnitude } from "./charts/rescore_magnitude.js";
import { render as renderEditors } from "./charts/rescore_editors.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/rescore_log.json";

const SECTIONS = [
  { id: "week", render: renderWeek, hero: true },
  { id: "magnitude", render: renderMagnitude },
  { id: "editors", render: renderEditors },
];

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("rescores")];

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
