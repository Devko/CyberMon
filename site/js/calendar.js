// =============================================================================
// calendar.js — CVE Calendar tab (calendar.html). Builds the three calendar
// sections from editorial.js. Like kev.js, all sections share ONE contract
// file (data/cve_calendar.json), fetched once and passed to each renderer;
// each renderer runs inside its own try/catch so one bad chart yields one
// inline error card, not a dead page. Shared chrome comes from common.js.
// =============================================================================
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderIdAge } from "./charts/calendar_idage.js";
import { render as renderWeekday } from "./charts/calendar_weekday.js";
import { render as renderPatch } from "./charts/calendar_patch.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/cve_calendar.json";

const SECTIONS = [
  { id: "reservation", render: renderIdAge, hero: true },
  { id: "weekbeat", render: renderWeekday },
  { id: "patchtuesday", render: renderPatch },
];

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("calendar")];

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
