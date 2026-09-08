// =============================================================================
// market.js — Security Market tab (market.html). Builds the three market
// sections from editorial.js. Unlike cve.js, ALL sections share ONE contract
// file (data/market_hype.json): it is fetched once and the parsed payload is
// passed to every section renderer. Each renderer runs inside its own
// try/catch so one bad chart yields one inline error card, not a dead page.
// Shared chrome (masthead/nav/banner/footer) comes from common.js.
// =============================================================================
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderHype } from "./charts/market_hype.js";
import { render as renderRisers } from "./charts/market_risers.js";
import { render as renderDivergence } from "./charts/market_divergence.js";

// RELATIVE path only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/market_hype.json";

const SECTIONS = [
  { id: "hype", render: renderHype, hero: true },
  { id: "risers", render: renderRisers },
  { id: "divergence", render: renderDivergence },
];

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("market")];

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
