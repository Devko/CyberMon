// =============================================================================
// incidents.js — Incident Clock tab (incidents.html). Builds the three SEC
// cyber-incident filing sections from editorial.js. Like c2.js, all sections
// share ONE contract file (data/sec_incidents.json), fetched once and passed
// to each renderer; each renderer runs inside its own try/catch so one bad
// chart yields one inline error card, not a dead page. An edition with
// status "empty" (before the first nightly EDGAR read) is not an error: each
// renderer shows its nodata card. Shared chrome: common.js.
// =============================================================================
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderClock } from "./charts/incidents_clock.js";
import { render as renderAmend } from "./charts/incidents_amend.js";
import { render as renderReceipts } from "./charts/incidents_receipts.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/sec_incidents.json";

const SECTIONS = [
  { id: "incidents_clock", render: renderClock, hero: true },
  { id: "incidents_amend", render: renderAmend },
  { id: "incidents_receipts", render: renderReceipts },
];

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("incidents")];

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
