// =============================================================================
// adp.js — Vulnrichment / ADP handoff tab (adp.html). Builds the three
// sections from editorial.js. Like naming.js, every section shares ONE
// contract file (data/adp_coverage.json), fetched once and passed to each
// renderer. Each renderer runs inside its own try/catch so one bad chart
// yields one inline error card, not a dead page. Shared chrome comes from
// common.js.
//
// The hero also wants the CURRENT NVD backlog as "the gap CISA fills"
// context. That is a BEST-EFFORT secondary read of data/nvd_decay.json: its
// failure must never card the page — the handoff stands on its own — so it
// resolves to a number or null and is passed alongside the ADP data.
// =============================================================================
import { hookResize } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderHandoff } from "./charts/adp_handoff.js";
import { render as renderAdds } from "./charts/adp_adds.js";
import { render as renderProviders } from "./charts/adp_providers.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/adp_coverage.json";
const NVD_FILE = "data/nvd_decay.json"; // best-effort context, never required

const SECTIONS = [
  { id: "adp_handoff", render: renderHandoff, hero: true },
  { id: "adp_adds", render: renderAdds },
  { id: "adp_providers", render: renderProviders },
];

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("adp")];

  const built = [];
  for (const cfg of SECTIONS) {
    const { section, slots } = buildSection(cfg);
    main.append(section);
    built.push({ cfg, slots });
  }

  // Best-effort NVD context: resolve to { nvdBacklog } — a number or null —
  // and NEVER reject, so a missing/failed nvd_decay.json can't card the page.
  const nvdCtx = fetchJSON(NVD_FILE)
    .then((d) => ({ nvdBacklog: d?.current?.backlog_total ?? null }))
    .catch(() => ({ nvdBacklog: null }));

  jobs.push(
    Promise.all([fetchJSON(DATA_FILE), nvdCtx])
      .then(([data, ctx]) => {
        for (const { cfg, slots } of built) {
          // Per-section isolation: the payload is shared, the failures aren't.
          try {
            cfg.render(slots, data, ctx);
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
