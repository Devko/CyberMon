// =============================================================================
// concentration.js — CNA Concentration tab (concentration.html). Builds the
// four concentration sections from editorial.js. Like market.js, the first
// three share ONE contract file (data/cna_concentration.json): it is
// fetched once and the parsed payload is passed to each of their
// renderers. The CNA profile (section 04) names its own file
// (data/cna_profiles.json) and is fetched separately.
// Each renderer runs inside its own try/catch so one bad chart yields one
// inline error card, not a dead page. Three sections carry editorial
// {placeholders} that are filled from the payload before rendering (the
// cve.js cna-methodology pattern). Shared chrome comes from common.js.
// =============================================================================
import { editorial, tpl } from "./editorial.js";
import { hookResize, fmtInt } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderConcentration } from "./charts/concentration_trend.js";
import { render as renderEntrants } from "./charts/concentration_entrants.js";
import { render as renderRejection } from "./charts/concentration_rejection.js";
import { render as renderCnaProfile } from "./charts/cna_profile.js";

// RELATIVE path only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/cna_concentration.json";

const SECTIONS = [
  { id: "concentration", render: renderConcentration, hero: true },
  { id: "entrants", render: renderEntrants },
  { id: "rejection", render: renderRejection },
  { id: "cna_profile", render: renderCnaProfile, file: "data/cna_profiles.json" },
];

// Fill editorial {placeholders} from the contract itself (cve.js pattern).
function fillTemplates(cfg, refs, data) {
  if (cfg.id === "concentration") {
    const hhi = data.headline?.hhi_latest;
    refs.methodText.textContent = tpl(editorial.sections.concentration.methodology, {
      hhi_latest: Number.isFinite(hhi) ? fmtInt(Math.round(hhi)) : editorial.ui.na,
    });
  } else if (cfg.id === "rejection") {
    const rl = data.rejection_leaderboard || {};
    const vars = {
      window_years: rl.window_years ?? "?",
      min_total: Number.isFinite(rl.min_total) ? fmtInt(rl.min_total) : "?",
    };
    refs.caption.textContent = tpl(editorial.sections.rejection.caption, vars);
    refs.methodText.textContent = tpl(editorial.sections.rejection.methodology, vars);
  } else if (cfg.id === "cna_profile") {
    const ed = editorial.sections.cna_profile;
    const w = data.window || {};
    const log = data.rescore_log || {};
    const vars = {
      from: w.from ?? editorial.ui.na,
      to: w.to ?? editorial.ui.na,
      years: w.years ?? editorial.ui.na,
      min_published: Number.isFinite(data.min_published) ? fmtInt(data.min_published) : editorial.ui.na,
      min_scored: Number.isFinite(data.min_scored) ? fmtInt(data.min_scored) : editorial.ui.na,
      log_from: log.first_observed ?? editorial.ui.na,
    };
    refs.caption.textContent = tpl(ed.caption, vars);
    refs.methodText.textContent = tpl(ed.methodology, vars);
  }
}

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("concentration")];

  const built = [];
  for (const cfg of SECTIONS) {
    const { section, slots, caption, methodText } = buildSection(cfg, null, { dataFiles: [DATA_FILE] });
    main.append(section);
    built.push({ cfg, slots, refs: { caption, methodText } });
  }

  // One fetch per data file; sections naming no file share DATA_FILE.
  const byFile = new Map();
  for (const b of built) {
    const file = b.cfg.file ?? DATA_FILE;
    if (!byFile.has(file)) byFile.set(file, []);
    byFile.get(file).push(b);
  }

  for (const [file, group] of byFile) jobs.push(
    fetchJSON(file)
      .then((data) => {
        for (const { cfg, slots, refs } of group) {
          // Per-section isolation: the payload is shared, the failures aren't.
          try {
            fillTemplates(cfg, refs, data);
            cfg.render(slots, data);
          } catch (err) {
            console.warn(`[CyberMon] section "${cfg.id}" failed:`, err);
            showError(slots, file, err);
          }
        }
      })
      .catch((err) => {
        console.warn(`[CyberMon] ${file} failed:`, err);
        for (const { cfg, slots, refs } of group) {
          // No payload: resolve editorial {placeholders} to honest fallbacks
          // so raw template braces never reach the reader.
          fillTemplates(cfg, refs, {});
          showError(slots, file, err);
        }
      })
  );

  await Promise.allSettled(jobs);
}

if (!window.echarts) {
  // ECharts CDN failed: chart sections degrade to error cards, the prose survives.
  console.warn("[CyberMon] ECharts failed to load from CDN.");
}
boot().catch((err) => console.error("[CyberMon] page boot failed:", err));
