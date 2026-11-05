// =============================================================================
// oss.js — Open-Source Maintainers tab (oss.html). Builds the three sections
// from editorial.js. All sections share ONE contract file
// (data/oss_maintainers.json), fetched once and passed to each renderer; each
// renderer runs inside its own try/catch so one bad chart yields one inline
// error card, not a dead page. Methodology paragraphs carry {placeholders}
// the renderers fill from the payload (refs, the malware.js pattern).
// Shared chrome: common.js.
// =============================================================================
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderAccounts } from "./charts/oss_accounts.js";
import { render as renderShared } from "./charts/oss_shared.js";
import { render as renderScorecard } from "./charts/oss_scorecard.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/oss_maintainers.json";

const SECTIONS = [
  { id: "oss_accounts", render: renderAccounts, hero: true },
  { id: "oss_shared", render: renderShared },
  { id: "oss_scorecard", render: renderScorecard },
];

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("oss")];

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
