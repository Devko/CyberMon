// =============================================================================
// breaches.js — Breach Ledger tab (breaches.html). Builds the three breach
// sections from editorial.js. All three sections share ONE contract file
// (data/breach_ledger.json), fetched once and passed to each renderer
// (kev.js pattern). Each renderer runs inside its own try/catch so one bad
// chart yields one inline error card, not a dead page. Shared chrome
// (masthead/nav/banner/footer) comes from common.js.
// =============================================================================
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderLag } from "./charts/breach_lag.js";
import { render as renderVolume } from "./charts/breach_volume.js";
import { render as renderClasses } from "./charts/breach_classes.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/breach_ledger.json";

const SECTIONS = [
  { id: "disclosure", render: renderLag, hero: true },
  { id: "exposure", render: renderVolume },
  { id: "leaks", render: renderClasses },
];

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("breaches")];

  const built = [];
  for (const cfg of SECTIONS) {
    const { section, slots } = buildSection(cfg, null, { noteKeys: ["importNote", "catalogNote"] });
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
