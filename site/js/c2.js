// =============================================================================
// c2.js — Botnet Weather tab (c2.html). Builds the three C2 sections from
// editorial.js. Like roster.js, all sections share ONE contract file
// (data/botnet_weather.json), fetched once and passed to each renderer; each
// renderer runs inside its own try/catch so one bad chart yields one inline
// error card, not a dead page. Shared chrome: common.js.
// =============================================================================
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderWeather } from "./charts/c2_weather.js";
import { render as renderToday } from "./charts/c2_today.js";
import { render as renderAge } from "./charts/c2_age.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/botnet_weather.json";

const SECTIONS = [
  { id: "c2_weather", render: renderWeather, hero: true },
  { id: "c2_today", render: renderToday },
  { id: "c2_age", render: renderAge },
];

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("c2")];

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
