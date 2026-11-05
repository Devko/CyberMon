// =============================================================================
// eol.js — Support Windows tab (eol.html). Builds the three sections from
// editorial.js. Like tags.js, all sections share ONE contract file
// (data/support_windows.json), fetched once and passed to each renderer; each
// renderer runs inside its own try/catch so one bad chart yields one inline
// error card, not a dead page. Captions and methodology carry editorial
// {placeholders} filled from the payload. Shared chrome: common.js.
// =============================================================================
import { editorial, tpl } from "./editorial.js";
import { hookResize, fmtInt } from "./theme.js";
import { initChrome, fetchJSON, buildSection, showError } from "./common.js";
import { render as renderYears } from "./charts/eol_years.js";
import { render as renderPhases } from "./charts/eol_phases.js";
import { render as renderCategories } from "./charts/eol_categories.js";
import { yearsLabel } from "./charts/eol_shared.js";

// RELATIVE paths only — must work under python -m http.server AND under a
// GitHub Pages project subpath (/CyberMon/).
const DATA_FILE = "data/support_windows.json";

const SECTIONS = [
  { id: "eol_years", render: renderYears, hero: true },
  { id: "eol_phases", render: renderPhases },
  { id: "eol_categories", render: renderCategories },
];

// Fill editorial {placeholders} from the contract itself.
export function fillTemplates(id, refs, data) {
  const ed = editorial.sections[id];
  const na = editorial.ui.na;
  const c = data.catalog || {};
  const yrs = (days, atLeast) => yearsLabel(ed.labels, days, atLeast, na);
  let vars = {};
  if (id === "eol_years") {
    const all = data.periods?.all || {};
    const pan = data.periods?.panel || {};
    vars = {
      panel: fmtInt(data.panel?.products),
      panel_early: yrs(pan.early?.median_days, pan.early?.median_at_least),
      panel_late: yrs(pan.late?.median_days, pan.late?.median_at_least),
      all_early: yrs(all.early?.median_days, all.early?.median_at_least),
      all_late: yrs(all.late?.median_days, all.late?.median_at_least),
      all_early_products: fmtInt(all.early?.products),
      all_late_products: fmtInt(all.late?.products),
      panel_early_lines: fmtInt(pan.early?.lines),
      panel_late_lines: fmtInt(pan.late?.lines),
      products: fmtInt(c.products),
      lines: fmtInt(c.lines),
      open: fmtInt(c.open),
      undated: fmtInt(c.ended_undated),
      as_of: data.as_of ?? na,
      min_products: fmtInt(data.min_products),
    };
  } else if (id === "eol_phases") {
    const ph = data.phases || {};
    vars = {
      products: fmtInt(ph.products),
      active: yrs(ph.active_median_days, ph.active_median_at_least),
      security: yrs(ph.security_median_days, ph.security_median_at_least),
      gap_lines: fmtInt(ph.gap_lines),
      gap: fmtInt(ph.gap_median_days),
      zero_gap: fmtInt(ph.zero_gap_lines),
      gap_unknown: fmtInt(ph.gap_unknown_lines),
    };
  } else if (id === "eol_categories") {
    vars = {
      products: fmtInt(c.products),
      newest_ended: fmtInt(c.newest_line_ended),
      no_supported: fmtInt(c.no_supported_line),
      min_cat: fmtInt(data.min_category_products),
    };
  }
  refs.caption.textContent = tpl(ed.caption, vars);
  refs.methodText.textContent = tpl(ed.methodology, vars);
}

// ---- boot ---------------------------------------------------------------------

async function boot() {
  hookResize();

  const main = document.getElementById("sections");
  const jobs = [initChrome("eol")];

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
            fillTemplates(cfg.id, refs, data);
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
