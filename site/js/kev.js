// =============================================================================
// kev.js — KEV Latency tab (kev.html). Builds the four KEV sections from
// editorial.js. Like market.js, the three latency sections share ONE
// contract file (data/kev_latency.json), fetched once and passed to each
// renderer; the ransomware section reads its own file (no CVE join, own
// contract). Each renderer runs inside its own try/catch so one bad chart
// yields one inline error card, not a dead page. Shared chrome
// (masthead/nav/banner/footer) comes from common.js.
// =============================================================================
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderLatency } from "./charts/kev_latency.js";
import { render as renderBuckets } from "./charts/kev_buckets.js";
import { render as renderRemediation } from "./charts/kev_remediation.js";
import { render as renderRansomware } from "./charts/kev_ransomware.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/kev_latency.json";

// Sections without an explicit file share DATA_FILE (and its single fetch).
const SECTIONS = [
  { id: "latency", render: renderLatency, hero: true },
  { id: "buckets", render: renderBuckets },
  { id: "remediation", render: renderRemediation },
  { id: "ransomware", render: renderRansomware, file: "data/kev_ransomware.json" },
];

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("kev")];

  // file -> the sections rendered from that file (one fetch per file).
  const byFile = new Map();
  for (const cfg of SECTIONS) {
    const { section, slots } = buildSection(cfg, null, { noteKeys: ["backfillNote"] });
    main.append(section);
    const file = cfg.file ?? DATA_FILE;
    if (!byFile.has(file)) byFile.set(file, []);
    byFile.get(file).push({ cfg, slots });
  }

  for (const [file, built] of byFile) {
    jobs.push(
      fetchJSON(file)
        .then((data) => {
          for (const { cfg, slots } of built) {
            // Per-section isolation: the payload is shared, the failures aren't.
            try {
              cfg.render(slots, data);
            } catch (err) {
              console.warn(`[CyberMon] section "${cfg.id}" failed:`, err);
              showError(slots, file, err);
            }
          }
        })
        .catch((err) => {
          console.warn(`[CyberMon] ${file} failed:`, err);
          for (const { slots } of built) showError(slots, file, err);
        })
    );
  }

  await Promise.allSettled(jobs);
}

if (!window.echarts) {
  // ECharts CDN failed: chart sections degrade to error cards, the prose survives.
  console.warn("[CyberMon] ECharts failed to load from CDN.");
}
boot().catch((err) => console.error("[CyberMon] page boot failed:", err));
